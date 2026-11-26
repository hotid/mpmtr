// Package core is the single measurement core of mpmtr. It owns all flow,
// probe, route and statistics state and is driven from exactly one goroutine
// (no internal locking). It performs no I/O by itself: probes leave through a
// Transport, packets and capture watermarks come in through methods, and
// time is passed in explicitly — which makes every scenario reproducible in
// tests with a simulated network and a virtual clock.
package core

import (
	"time"
)

// Mono is monotonic time in nanoseconds since the core was created. All
// intervals, deadlines, scheduling and state-machine timing use Mono.
type Mono int64

// Wall is the time of day in nanoseconds since the Unix epoch, as the
// kernel stamps packets. It places packets and capture drops in time
// against each other; intervals and deadlines of the core itself use Mono.
// The two are never mixed: one is a clock that can jump, the other is not.
type Wall int64

// Add is the time d later.
func (w Wall) Add(d time.Duration) Wall { return w + Wall(d) }

// Sub is the time from o to w.
func (w Wall) Sub(o Wall) time.Duration { return time.Duration(w - o) }

// Time is w as a time.Time.
func (w Wall) Time() time.Time { return time.Unix(0, int64(w)) }

// TTL is a place on a path, counted in hops from the source: the TTL a
// probe is sent with, the hop that answers it, the distance of the
// destination. 0 is "not known". It is its own type so that a hop number is
// not mixed up with a count, an index or an identifier; where it becomes a
// byte of a packet or an index into the hops of a route, that is said
// (Byte, the hop and hopIf of a route).
type TTL int

// Byte is t as the TTL field of a packet.
func (t TTL) Byte() uint8 { return uint8(t) }

// FlowID identifies a flow among all flows of the run; EndpointID an
// endpoint, by its place in the order the targets were given. They are
// types of their own so that one is not passed for the other, or for a
// flow's number within its endpoint (F1, F2, ...), a count or a hop.
type FlowID int

// EndpointID identifies an endpoint (see FlowID).
type EndpointID int

// AllEndpoints is "every endpoint" where one may be chosen.
const AllEndpoints EndpointID = -1

// Class is the scheduler class of a probe.
type Class uint8

const (
	ClassE2E Class = iota
	ClassIncident
	ClassRefresh // continuous hop measurements / topology refresh
	ClassDiscovery
	ClassCensus // anycast: one SYN per port to learn which server answers it
	ClassApp    // application check by a plugin over a real TCP connection
	numClasses
)

func (c Class) String() string {
	return [...]string{"e2e", "incident", "refresh", "discovery", "census", "app"}[c]
}

// Outcome of a probe.
type Outcome uint8

const (
	OutNone Outcome = iota
	// E2E
	OutSynAck
	OutRst
	OutICMPUnreach // network failure reported by ICMP (incl. time exceeded on an E2E probe)
	OutTimeout
	OutWeak
	OutUnexpected
	OutLocalError
	OutCaptureImpaired
	OutInvalid
	OutSkipped
	OutCancelled
	// Hop
	OutTimeExceeded
	OutDestReached
	// No reply while the remote still held TCP state for an earlier probe of
	// this 4-tuple (evidence: challenge ACK or SYN/ACK retransmission after
	// our RST). A TCP-state artifact of 4-tuple reuse, not network loss.
	OutRemoteState
	// Application check (plugin) over a real connection from the flow's
	// port: the server answered its protocol / did not. A failed check is
	// a failure of that server like a lost probe.
	OutAppOK
	OutAppFail
)

var outcomeNames = [...]string{"none", "syn_ack", "rst", "icmp_unreachable", "timeout", "weak_reply",
	"unexpected_reply", "local_error", "capture_impaired", "measurement_invalid", "skipped", "cancelled",
	"icmp_time_exceeded", "destination_reached", "remote_state_conflict", "app_ok", "app_failed"}

func (o Outcome) String() string { return outcomeNames[o] }

// Valid reports whether the outcome counts in strict E2E statistics.
func (o Outcome) Valid() bool {
	return o == OutSynAck || o == OutRst || o == OutICMPUnreach || o == OutTimeout || o == OutAppOK || o == OutAppFail
}

// Positive reports a strict positive TCP reply.
func (o Outcome) Positive() bool { return o == OutSynAck || o == OutRst || o == OutAppOK }

// Failure reports a valid network failure.
func (o Outcome) Failure() bool { return o == OutTimeout || o == OutICMPUnreach }

// Answered: TCP answered. A failed application check is one too: the
// connection was taken (or refused) and only the protocol failed, which is
// counted apart from TCP (see appUpdate).
func (o Outcome) Answered() bool { return o.Positive() || o == OutAppFail }

// SkipReason explains a skipped E2E slot. Never a network loss.
type SkipReason uint8

const (
	SkipNone SkipReason = iota
	SkipPPS
	SkipEndpointPPS
	SkipInflight
	SkipBusy
	SkipLag
	SkipIncident
	SkipInvalid
	SkipApp
	SkipTrace
	numSkip
)

var skipNames = [...]string{"", "global_pps", "endpoint_pps", "max_inflight", "flow_busy", "scheduler_lag", "yield_incident", "flow_invalid", "app_check", "yield_trace"}

func (s SkipReason) String() string { return skipNames[s] }

// Config of the measurement core. All values are validated by the CLI.
type Config struct {
	Interval   time.Duration // E2E interval per flow
	Timeout    time.Duration // E2E reply deadline
	HopTimeout time.Duration // hop probe deadline (<= Timeout)
	Flows      int           // active flows per endpoint
	MaxFlows   int           // discovery limit per endpoint
	MaxTTL     TTL
	// Application checks: DOWN after this many failed checks in a row,
	// back after this many passed ones (3 and 2).
	AppDownAfter, AppUpAfter int
	E2ETTL                   uint8

	PPS          float64 // global probes per second
	EndpointPPS  float64 // per endpoint
	MaxInflight  int
	ResponderPPS float64

	Discovery      bool // discovery sweeps + continuous hop measurements
	TraceOnFailure bool // incident traces
	QuoteFallback  bool // allow ICMP quote seq-mismatch fallback
	DiscoverOnly   bool // --discover: no E2E monitoring, discovery to stop condition
	ReportCount    int  // report mode: E2E probes to execute per flow (0 = live)

	// SharedHops: a hop seen by several measured flows at the same TTL with
	// the same responder is refreshed by one of them (the lowest-numbered);
	// its replies count for all of them in the route tree.
	SharedHops bool

	// Anycast: tell the servers behind the destination address apart by
	// their TCP timestamp clocks, find the ports that reach each of them,
	// and measure every server.
	Anycast bool

	// App: an application check plugin runs every AppInterval on each
	// measured port, over a real TCP connection from that port (Transport
	// must implement AppChecker).
	App         bool
	AppInterval time.Duration
	AppTimeout  time.Duration

	// TOS (IPv4 TOS / IPv6 traffic class) and the IPv6 flow label of every
	// probe: part of a flow's identity, the same for all flows.
	TOS       uint8
	FlowLabel uint32

	DiscInitial int // 32

	Seed uint64

	// Derived/tunable thresholds (defaults set by Defaults()).
	DownAfter        int     // consecutive failures for DOWN (5)
	UpAfter          int     // consecutive positives to leave DOWN (5)
	LossMinValid     int     // 30
	LossWilsonLow    float64 // 0.02
	LossTicks        int     // 3
	LossClearRate    float64 // 0.005
	LossClearConsec  int     // 30
	OKCoverage       float64 // 0.75
	RTTFactor        float64 // 1.5
	RTTAbsMin        time.Duration
	RTTMinSamples    int // 20
	RTTPeriods       int // 3
	RTTClearFactor   float64
	RTTClearAbs      time.Duration
	BaselineSamples  int // 60
	IncidentRounds   int
	IncidentControls int
}

// Defaults fills unset thresholds with the documented defaults.
func (c *Config) Defaults() {
	set := func(p *int, v int) {
		if *p == 0 {
			*p = v
		}
	}
	setf := func(p *float64, v float64) {
		if *p == 0 {
			*p = v
		}
	}
	setd := func(p *time.Duration, v time.Duration) {
		if *p == 0 {
			*p = v
		}
	}
	setd(&c.Interval, time.Second)
	setd(&c.AppInterval, 10*time.Second)
	setd(&c.AppTimeout, 5*time.Second)
	setd(&c.Timeout, time.Second)
	if c.HopTimeout == 0 {
		c.HopTimeout = c.Timeout
		if c.HopTimeout > c.Interval/2 {
			c.HopTimeout = c.Interval / 2
		}
	}
	set(&c.Flows, 1)
	set(&c.MaxFlows, 256)
	if c.MaxTTL <= 0 {
		c.MaxTTL = 30
	}
	set(&c.AppDownAfter, 3)
	set(&c.AppUpAfter, 2)
	if c.E2ETTL == 0 {
		c.E2ETTL = 64
	}
	setf(&c.PPS, 1000)
	setf(&c.EndpointPPS, 500)
	set(&c.MaxInflight, int(c.PPS*c.Timeout.Seconds()*1.5)+16)
	setf(&c.ResponderPPS, 100)
	set(&c.DiscInitial, 32)
	set(&c.DownAfter, 5)
	set(&c.UpAfter, 5)
	set(&c.LossMinValid, 30)
	setf(&c.LossWilsonLow, 0.02)
	set(&c.LossTicks, 3)
	setf(&c.LossClearRate, 0.005)
	set(&c.LossClearConsec, 30)
	setf(&c.OKCoverage, 0.75)
	setf(&c.RTTFactor, 1.5)
	setd(&c.RTTAbsMin, 10*time.Millisecond)
	set(&c.RTTMinSamples, 20)
	set(&c.RTTPeriods, 3)
	setf(&c.RTTClearFactor, 1.25)
	setd(&c.RTTClearAbs, 5*time.Millisecond)
	set(&c.BaselineSamples, 60)
	set(&c.IncidentRounds, 5)
	set(&c.IncidentControls, 3)
}

// BucketDur is the length of one statistics bucket: 10 seconds, or ten
// probe intervals when --interval is above one second. The thresholds are
// counts of probes (30 valid ones for a verdict, 20 RTT samples), so the
// windows have to hold as many probes at any interval: with a fixed 60 s
// window a flow probed every 5 s could never collect the 30 probes that
// clear LOSS.
func (c *Config) BucketDur() time.Duration {
	iv := c.Interval
	if iv <= 0 {
		iv = time.Second
	}
	return max(BucketMin, 10*iv)
}

// WindowDur returns the long and the short evaluation window ("5 min" and
// "60 s" at the default interval).
func (c *Config) WindowDur() (long, short time.Duration) {
	return WindowLong * c.BucketDur(), WindowShort * c.BucketDur()
}

// Evaluation cadence and windows.
const (
	BucketMin   = 10 * time.Second
	WindowLong  = 30 // buckets: 5 minutes (300 probe intervals)
	WindowShort = 6  // buckets: 60 seconds (60 probe intervals)
	rttRingSize = 128
	hopRTTRing  = 16
	recentProbe = 8 // per-flow guard ring of completed probes
)

// Transport sends probes. Implementations must not retain arguments.
type Transport interface {
	Send(f *Flow, seq uint32, ttl uint8, ipid uint16) error
}

// AppChecker runs application checks (optional Transport capability):
// open a real TCP connection from the flow's source port, let the plugin
// speak its protocol, close with RST, and report back with
// Core.OnAppResult(id, ...) on the core's goroutine.
type AppChecker interface {
	AppCheck(f *Flow, id uint64, timeout time.Duration)
}

// AppOutcome is how one application check ended. Exactly one of these
// happened; which of them had a TCP handshake follows from the outcome.
type AppOutcome uint8

const (
	AppPassed       AppOutcome = iota // connected, the plugin's protocol check passed
	AppFailed                         // connected, the server failed the protocol
	AppRefused                        // the server answered the SYN with RST
	AppNoAnswer                       // no answer to the SYN
	AppLocal                          // a local problem before the connection (bind, route)
	AppPluginFailed                   // connected, but the plugin itself failed: not the server's fault
)

// Connected reports whether the TCP handshake completed.
func (o AppOutcome) Connected() bool { return o == AppPassed || o == AppFailed || o == AppPluginFailed }

// Local reports a problem on this side: neither an answer nor a loss.
func (o AppOutcome) Local() bool { return o == AppLocal || o == AppPluginFailed }

// StagePlugin is the stage of a check that the plugin itself failed (the
// word of the plugin protocol, also shown as the stage of the failure).
const StagePlugin = "plugin"

// AppResult of one application check.
type AppResult struct {
	Outcome    AppOutcome
	ConnectRTT time.Duration // SYN → SYN/ACK of the real connection (when connected)
	AppTime    time.Duration // the plugin's exchange time
	Stage      string        // where it failed, in the plugin's words: for display only
	Err        string        // its error text: for display only
	Note       string        // a few characters about the answer: for display only
}

// Clock returns the current monotonic and wall-clock time.
type Clock interface {
	Now() (Mono, Wall)
}
