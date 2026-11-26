package core

import (
	"fmt"
	"net/netip"

	"github.com/hotid/mpmtr/internal/stats"
	"github.com/hotid/mpmtr/internal/wire"
)

// Role of a flow within its endpoint.
type Role uint8

const (
	RoleCandidate Role = iota // discovery only, no E2E monitoring
	RoleActive                // monitored E2E
	RoleRetired               // no longer measured; its statistics are kept
)

// Monitored reports whether the role receives E2E probes.
func (r Role) Monitored() bool { return r == RoleActive }

// tupleKey identifies a flow by its local and remote transport addresses.
type tupleKey struct {
	local, remote [16]byte
	lport, rport  wire.Port
}

func mkTuple(local netip.Addr, lport wire.Port, remote netip.Addr, rport wire.Port) tupleKey {
	return tupleKey{local: local.As16(), remote: remote.As16(), lport: lport, rport: rport}
}

// Probe is one controlled SYN.
type Probe struct {
	id    uint64
	flow  *Flow
	class Class
	seq   uint32
	ipid  uint16
	ttl   TTL

	sentMono, deadMono Mono
	sentRT, deadRT     Wall
	txRT               Wall
	txSeen             bool

	completed     bool
	tsval         uint32 // server's TCP timestamp in the SYN/ACK (hasTS)
	hasTS         bool
	burst         bool // one of several parallel discovery hop probes
	completedMono Mono
	outcome       Outcome
	from          netip.Addr
	icmpType      uint8
	icmpCode      uint8
	rxRT          Wall
	lowConf       bool
	sawUnexpected bool
	rstSeen       bool
	weakAck       bool
	gotSynAck     bool
	txIfOK        bool
	mpls          [wire.MaxMPLS]wire.MPLSEntry
	nmpls         int
}

// probeRec is the guard-window record of a completed probe.
type probeRec struct {
	seq     uint32
	class   Class
	ttl     TTL
	replied bool
	outcome Outcome
	endMono Mono
	used    bool
	from    netip.Addr // who answered (hop probes)
}

// Counters are lifetime E2E counters of a flow (never reset by grouping;
// reset only by an explicit user statistics reset).
type Counters struct {
	Sent         uint64 `json:"sent"`
	SynAck       uint64 `json:"syn_ack"`
	Rst          uint64 `json:"rst"`
	Unreach      uint64 `json:"icmp_unreachable"`
	Timeout      uint64 `json:"timeout"`
	Weak         uint64 `json:"weak"`
	Unexpected   uint64 `json:"unexpected"`
	LocalErr     uint64 `json:"local_err"`
	Impaired     uint64 `json:"impaired"`
	Skipped      uint64 `json:"skipped"`
	Late         uint64 `json:"late"`
	Duplicate    uint64 `json:"duplicate"`
	Cancelled    uint64 `json:"cancelled"`
	Invalid      uint64 `json:"invalid"`
	ChallengeAck uint64 `json:"challenge_ack"`
	RstMissing   uint64 `json:"rst_missing"`
	TxTSFallback uint64 `json:"tx_ts_fallback"`
	// EgressMismatch counts probes whose captured egress interface differs
	// from the per-flow route lookup (local route/ECMP not honoured).
	EgressMismatch uint64 `json:"egress_mismatch"`
	// RemoteState counts probes without reply while the remote held state
	// for an earlier probe of the same 4-tuple (not network loss).
	RemoteState uint64          `json:"remote_state_conflict"`
	AppSent     uint64          `json:"app_checks,omitempty"`
	AppOK       uint64          `json:"app_ok,omitempty"`
	AppFail     uint64          `json:"app_failed,omitempty"`
	AppLocal    uint64          `json:"app_local_errors,omitempty"`
	SkipBy      [numSkip]uint64 `json:"skip_by"`
}

// Valid = syn_ack + rst + icmp_unreachable + timeout, plus the application
// checks that got a verdict (the same outcomes the windows count).
func (c *Counters) Valid() uint64 {
	return c.SynAck + c.Rst + c.Unreach + c.Timeout + c.AppOK + c.AppFail
}

// Failures = timeout + icmp_unreachable: TCP only. Application checks have
// counters of their own (AppOK, AppFail).
func (c *Counters) Failures() uint64 { return c.Timeout + c.Unreach }

// bucket is one 10-second E2E statistics bucket.
type bucket struct {
	n                          int64 // bucket number + 1; 0 = empty
	valid, timeout, unreach    uint16
	app, appFail               uint16 // application checks with a verdict, and the failed ones
	pos, skipped, impaired, wk uint16
}

// Window is an aggregate over a span of buckets.
type Window struct {
	Valid     int64 `json:"valid"`
	Timeout   int64 `json:"timeout"`
	Unreach   int64 `json:"icmp_unreachable"`
	App       int64 `json:"app_checks"` // application checks with a verdict
	AppFail   int64 `json:"app_failed"` // of them failed (TCP itself answered)
	Positive  int64 `json:"positive"`
	Skipped   int64 `json:"skipped"`
	Impaired  int64 `json:"impaired_or_local"`
	WeakUnexp int64 `json:"weak_unexp"`
}

// Failures in the window: TCP only.
func (w Window) Failures() int64 { return w.Timeout + w.Unreach }

type window struct{ b [WindowLong + 1]bucket }

func (w *window) at(bn int64) *bucket {
	b := &w.b[bn%int64(len(w.b))]
	if b.n != bn+1 {
		*b = bucket{n: bn + 1}
	}
	return b
}

func inc16(p *uint16) {
	if *p < 0xffff {
		*p++
	}
}

func (w *window) add(bn int64, o Outcome) {
	b := w.at(bn)
	switch o {
	case OutSynAck, OutRst:
		inc16(&b.valid)
		inc16(&b.pos)
	case OutAppOK:
		inc16(&b.valid)
		inc16(&b.pos)
		inc16(&b.app)
	case OutTimeout:
		inc16(&b.valid)
		inc16(&b.timeout)
	case OutAppFail: // TCP answered; the application did not
		inc16(&b.valid)
		inc16(&b.pos)
		inc16(&b.app)
		inc16(&b.appFail)
	case OutICMPUnreach:
		inc16(&b.valid)
		inc16(&b.unreach)
	case OutSkipped:
		inc16(&b.skipped)
	case OutCaptureImpaired, OutLocalError, OutRemoteState:
		inc16(&b.impaired)
	case OutWeak, OutUnexpected:
		inc16(&b.wk)
	}
}

// sum aggregates buckets cur-span+1..cur.
func (w *window) sum(cur int64, span int) Window { return w.sumFrom(cur, span, 0) }

// sumFrom aggregates buckets max(floor, cur-span+1)..cur.
func (w *window) sumFrom(cur int64, span int, floor int64) Window {
	var r Window
	for bn := cur - int64(span) + 1; bn <= cur; bn++ {
		if bn < 0 || bn < floor {
			continue
		}
		b := &w.b[bn%int64(len(w.b))]
		if b.n != bn+1 {
			continue
		}
		r.Valid += int64(b.valid)
		r.Timeout += int64(b.timeout)
		r.Unreach += int64(b.unreach)
		r.App += int64(b.app)
		r.AppFail += int64(b.appFail)
		r.Positive += int64(b.pos)
		r.Skipped += int64(b.skipped)
		r.Impaired += int64(b.impaired)
		r.WeakUnexp += int64(b.wk)
	}
	return r
}

func (w *window) reset() { *w = window{} }

type rttSample struct {
	us uint32
	bn int32
}

// rttState keeps recent RTT samples and lifetime summaries for a flow.
type rttState struct {
	ring     stats.Ring[rttSample]
	n        uint64
	sum      float64
	min, max uint32
	last     uint32
	jit      stats.Jitter
	baseline baseline
	bmed     [4]bucketMed // medians of recent completed buckets
}

// bucketMed caches the RTT median of one completed 10 s bucket, so that
// evaluation over several periods does not depend on the sample ring
// still holding older buckets (it does not at short intervals).
type bucketMed struct {
	bn  int64
	med uint32
	n   int
	ok  bool
}

func (r *rttState) add(us uint32, bn int64) {
	r.ring.Add(rttSample{us: us, bn: int32(bn)})
	if r.n == 0 || us < r.min {
		r.min = us
	}
	if us > r.max {
		r.max = us
	}
	r.n++
	r.sum += float64(us)
	r.last = us
	r.jit.Add(us)
}

// lossEpisodes tracks runs of consecutive valid failures.
type lossEpisodes struct {
	cur, max, episodes, total int
}

func (l *lossEpisodes) add(fail bool) {
	if fail {
		if l.cur == 0 {
			l.episodes++
		}
		l.cur++
		l.total++
		if l.cur > l.max {
			l.max = l.cur
		}
		return
	}
	l.cur = 0
}

// Mean run length of loss episodes.
func (l *lossEpisodes) mean() float64 {
	if l.episodes == 0 {
		return 0
	}
	return float64(l.total) / float64(l.episodes)
}

// InvalidReason marks flows whose measurements cannot be trusted.
type InvalidReason uint8

const (
	ValidFlow InvalidReason = iota
	InvalidLocalNAT
	InvalidSeqRewrite
	InvalidWeakDominant
	InvalidLocalRoute
	InvalidEgressMismatch
)

// Flow is one stable TCP flow (5-tuple + TOS + flow label + routing context).
type Flow struct {
	ID      FlowID // global, stable
	Num     int    // per-endpoint ordinal, shown as F<Num>
	EP      *Endpoint
	Tmpl    wire.FlowTemplate
	IfIndex int
	Gateway netip.Addr
	Role    Role
	key     tupleKey

	active    *Probe
	burst     int // parallel discovery hop probes in flight
	recent    [recentProbe]probeRec
	recentPos int

	// E2E scheduling
	phase       Mono
	nextE2E     Mono
	slot        int64
	e2eGen      uint64
	Executed    int // E2E probes actually executed (sent and resolved)
	everActive  bool
	activeSince Mono
	yieldCount  int
	e2eDeferred bool
	remoteUntil Mono // remote TCP state for an earlier probe suspected until
	// reached: the last probes that could reach the destination. Such a
	// probe can leave a connection on the server (also when its answer was
	// lost on the way back), and the server may keep it for a minute or
	// more when our RST does not reach it.
	reached  [128]uint32
	reachedN int
	lastSeq  uint32
	isnF     uint32 // per-4-tuple ISN offset (RFC 6528 F())

	C         Counters
	win       window
	rtt       rttState
	lastE2E   Mono // when the last E2E probe completed
	episode   lossEpisodes
	sm        flowSM
	fits      []*Group // ambiguous: the routes this flow's incomplete trace fits
	census    bool     // anycast: a census SYN is due on this port
	censusAt  Mono     // when it became due (a watchdog gives up after acStuck)
	acMoved   int      // anycast: answers from another server's clock
	acUnknown int      // anycast: answers matching no known clock
	acOther   *Server
	acStreak  int
	appDueAt  Mono // next application check
	// tupleClean: the last raw probe of the 4-tuple was answered by the
	// destination (and reset by our kernel), so stateful middleboxes hold
	// no half-open state of it. A TTL-limited probe leaves a NAT's entry in
	// SYN_SENT with our sequence; a real connection opened then is accepted
	// only when the kernel's random ISN happens to be later, so the check
	// would stall on a port that was just traced.
	tupleClean bool
	lastSent   uint64 // id of the flow's latest raw probe
	appWant    bool   // a check is due: hop probes wait, the next answered E2E opens it
	appUntil   Mono   // packets of the 4-tuple belong to a real connection until then
	appStage   string // last failed check: where and why
	appErr     string
	appNote    string // what the plugin noted about the last answered check

	route     *RouteObs
	routeHist []*RouteObs
	nextRVer  int

	// hop work
	hopTTL      TTL
	hopLastSent Mono
	focusAt     Mono             // when the last full trace of this port in focus began
	hopAt       Mono             // last hop probe sent (any class)
	ttlNoted    ttlSet           // TTLs where this port's answer is counted for the endpoint
	ttlQuiet    ttlSet           // TTLs this port is counted as having found silent
	traced      bool             // a discovery trace of this port has finished
	hopChanges  map[TTL]*[4]Mono // per TTL: times of the last confirmed responder changes
	traceSlot   bool             // the current E2E slot was given to hop probes (DOWN flow)
	retrace     bool             // a discovery-class sweep re-traces this port after a topology change
	retraceAt   Mono
	sw          *sweep
	inQueue     bool
	retryAt     Mono
	incident    *incident

	group   *Group
	level   Level
	sig     signature
	invalid InvalidReason
}

// Name returns the display name F<n>.
func (f *Flow) Name() string { return fmt.Sprintf("F%d", f.Num) }

// SPort returns the source port.
func (f *Flow) SPort() wire.Port { return f.Tmpl.SPort }

// Busy reports whether a probe is active on the flow.
func (f *Flow) Busy() bool { return f.active != nil }

func (f *Flow) pushRecent(p *Probe, now Mono) {
	f.recent[f.recentPos] = probeRec{seq: p.seq, class: p.class, ttl: p.ttl,
		replied: p.outcome.Positive() || p.outcome == OutTimeExceeded || p.outcome == OutDestReached || p.outcome == OutICMPUnreach || p.outcome == OutWeak,
		outcome: p.outcome, endMono: now, used: true, from: p.from}
	f.recentPos = (f.recentPos + 1) % recentProbe
}

// noteReached remembers a probe that could reach the destination.
func (f *Flow) noteReached(seq uint32) {
	f.reached[f.reachedN%len(f.reached)] = seq
	f.reachedN++
}

// wasReached reports whether seq is one of the last probes that could reach
// the destination.
func (f *Flow) wasReached(seq uint32) bool {
	for i := 0; i < min(f.reachedN, len(f.reached)); i++ {
		if f.reached[i] == seq {
			return true
		}
	}
	return false
}

// recentWithin calls fn for the recent probes still inside the guard
// window, until fn returns false.
func (f *Flow) recentWithin(now, guard Mono, fn func(r *probeRec) bool) {
	for i := range f.recent {
		r := &f.recent[i]
		if r.used && now-r.endMono <= guard {
			if !fn(r) {
				return
			}
		}
	}
}
