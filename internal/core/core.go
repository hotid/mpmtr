package core

import (
	"container/heap"
	"errors"
	"fmt"
	"hash/fnv"
	"math/rand/v2"
	"net/netip"
	"time"

	"github.com/hotid/mpmtr/internal/stats"
	"github.com/hotid/mpmtr/internal/wire"
)

// Route is the result of a per-flow local route lookup.
type Route struct {
	Src     netip.Addr
	IfIndex int
	Gateway netip.Addr
	MSS     uint16
}

// Env provides per-flow local routing and source-port reservation.
type Env interface {
	// Route looks up the route a real TCP socket with these parameters
	// would use (destination, ports, TOS, mark, oif constraints).
	Route(dst netip.Addr, sport, dport wire.Port) (Route, error)
	// Reserve protects (src, sport) against automatic allocation by the
	// kernel. Idempotent per (src, sport).
	Reserve(src netip.Addr, sport wire.Port) error
}

type evKind uint8

const (
	evE2E evKind = iota
	evDeadline
	evFinalize
	evRetry
	evApp // an application check waits for its flow's clean 4-tuple
)

type event struct {
	at   Mono
	kind evKind
	flow *Flow
	p    *Probe
	gen  uint64
}

type evHeap []event

func (h evHeap) Len() int                   { return len(h) }
func (h evHeap) Less(i, j int) bool         { return h[i].at < h[j].at }
func (h evHeap) Swap(i, j int)              { h[i], h[j] = h[j], h[i] }
func (h *evHeap) Push(x any)                { *h = append(*h, x.(event)) }
func (h *evHeap) Pop() any                  { o := *h; n := len(o); e := o[n-1]; *h = o[:n-1]; return e }
func (c *Core) push(e event)                { heap.Push(&c.heap, e) }
func (c *Core) cfgDur(d time.Duration) Mono { return Mono(d) }

// fifo is a bounded queue of flows.
type fifo struct {
	buf        []*Flow
	head, size int
}

func (q *fifo) push(f *Flow) bool {
	if q.size == len(q.buf) {
		nb := make([]*Flow, max(16, 2*len(q.buf)))
		for i := 0; i < q.size; i++ {
			nb[i] = q.buf[(q.head+i)%len(q.buf)]
		}
		q.buf, q.head = nb, 0
	}
	q.buf[(q.head+q.size)%len(q.buf)] = f
	q.size++
	return true
}

func (q *fifo) pop() *Flow {
	if q.size == 0 {
		return nil
	}
	f := q.buf[q.head]
	q.buf[q.head] = nil
	q.head = (q.head + 1) % len(q.buf)
	q.size--
	return f
}

func (q *fifo) pushFront(f *Flow) {
	if q.size == len(q.buf) {
		// Grow through push, then take its element back off the tail: the
		// buffer is twice the size, the queue is what it was.
		q.push(f)
		q.size--
		q.buf[(q.head+q.size)%len(q.buf)] = nil
	}
	q.head = (q.head - 1 + len(q.buf)) % len(q.buf)
	q.buf[q.head] = f
	q.size++
}

type respKey struct {
	addr  netip.Addr
	synth uint64
}

type respBucket struct {
	tb   stats.TokenBucket
	last Mono
}

type dropPeriod struct{ from, to Wall }

// Metrics are the measurer's self-diagnostics.
type Metrics struct {
	CaptureDrops     uint64             `json:"capture_drops"`
	UserDrops        uint64             `json:"user_drops"`
	Unmatched        uint64             `json:"unmatched"`
	Late             uint64             `json:"late"`
	Duplicate        uint64             `json:"duplicate"`
	Unexpected       uint64             `json:"unexpected"`
	Weak             uint64             `json:"weak"`
	ChallengeAck     uint64             `json:"challenge_ack"`
	TxTSFallback     uint64             `json:"tx_ts_fallback"`
	TxNotObserved    uint64             `json:"tx_not_observed"`
	Malformed        uint64             `json:"malformed"`
	SchedSkips       uint64             `json:"sched_skips"`
	SkipBy           [numSkip]uint64    `json:"skip_by"`
	LocalErrors      uint64             `json:"local_errors"`
	SentE2E          uint64             `json:"sent_e2e"`
	SentHop          [numClasses]uint64 `json:"sent_hop"`
	HopDeferWindow   uint64             `json:"hop_defer_window"`
	HopDeferBudget   uint64             `json:"hop_defer_budget"`
	HopDeferResp     uint64             `json:"hop_defer_resp"`
	HopCancelled     uint64             `json:"hop_cancelled"`
	LagMax           Mono               `json:"lag_max"`
	LagSum           Mono               `json:"lag_sum"`
	LagN             uint64             `json:"lag_n"`
	QuoteSeqMismatch uint64             `json:"quote_seq_mismatch"`
	NATDetected      uint64             `json:"nat_detected"`
	Retraced         uint64             `json:"retraced"`
	// MultiAnswer counts hop probes answered by a second, different router
	// (a router that answers a probe and lets it go on as well).
	MultiAnswer     uint64 `json:"multi_answer"`
	PortConflicts   uint64 `json:"port_conflicts"`
	RouteErrors     uint64 `json:"route_errors"`
	WatermarkStalls uint64 `json:"watermark_stalls"`
	ImpairedPeriods uint64 `json:"impaired_periods"`
	RespLimited     int    `json:"resp_limited"` // responders currently rate limited
}

// Core is the measurement core.
type Core struct {
	bucket Mono // length of one statistics bucket (Config.BucketDur)
	cfg    Config
	tr     Transport
	env    Env
	clk    Clock

	now   Mono
	nowRT Wall

	focus  *Flow // the port traced in full every interval (nil: none)
	eps    []*Endpoint
	flows  []*Flow
	tuples map[tupleKey]*Flow
	bySeq  map[uint32]*Probe

	heap   evHeap
	ready  [numClasses]fifo
	drrDef [numClasses]int

	global, reserve stats.TokenBucket
	inflight        int
	resp            map[respKey]*respBucket
	respFresh       map[netip.Addr]freshRec
	hopOwner        map[hopKey]*Flow  // SharedHops: who refreshes a (TTL, responder)
	apps            map[uint64]*Probe // application checks waiting for their result
	respGC          Mono

	watermarkRT  Wall
	lastWMMono   Mono
	drops        [64]dropPeriod
	dropPos      int
	lastDropMono Mono
	impairedNow  bool

	rng       *rand.Rand
	nextProbe uint64
	free      []*Probe

	M       Metrics
	hopRate rateMeter
	e2eRate rateMeter

	evalBN     int64
	epochStart Mono
	epochNum   int

	ev *eventSink

	// FirstEnvErr is the first route/reservation error (for diagnostics).
	FirstEnvErr string
}

// New creates a core.
func New(cfg Config, tr Transport, env Env, clk Clock) *Core {
	cfg.Defaults()
	seed := cfg.Seed
	c := &Core{
		cfg: cfg, tr: tr, env: env, clk: clk,
		tuples:    make(map[tupleKey]*Flow),
		bySeq:     make(map[uint32]*Probe),
		resp:      make(map[respKey]*respBucket),
		respFresh: make(map[netip.Addr]freshRec), hopOwner: make(map[hopKey]*Flow), apps: map[uint64]*Probe{},
		rng:    rand.New(rand.NewPCG(seed^0x9e3779b97f4a7c15, uint64(time.Now().UnixNano()))),
		evalBN: -1,
	}
	burst := max(4, cfg.PPS/100)
	c.global = stats.NewTokenBucket(cfg.PPS*0.9, burst)
	c.reserve = stats.NewTokenBucket(cfg.PPS*0.1, max(1, burst/4))
	c.ev = newEventSink(c)
	c.now, c.nowRT = clk.Now()
	c.bucket = Mono(c.cfg.BucketDur())
	return c
}

// Config returns the effective configuration.
func (c *Core) Config() Config { return c.cfg }

// Endpoint is one (dst_ip, dst_port).
type Endpoint struct {
	ID     EndpointID
	Target string
	Addr   netip.Addr
	Port   wire.Port

	Flows  []*Flow
	byPort map[wire.Port]*Flow
	ports  []wire.Port

	bucket    stats.TokenBucket // all probes of the endpoint (E2E checks this)
	hopBucket stats.TokenBucket // hop share: endpoint limit minus E2E demand
	measuring int               // flows measured end to end now

	disc     discovery
	groups   []*Group
	groupMap map[groupKey]*Group
	// groupIDs remembers the identifier every route of this endpoint was
	// ever given: a route that goes and comes back has the same name, and
	// which of two routes with the same short identifier got the short one
	// does not change during a run.
	groupIDs map[string]groupKey

	agg          EndpointAgg
	state        EPState
	scope        Scope
	emittedState EPState
	emittedScope Scope
	loc          Localization
	locPublished Localization
	incident     *incident
	lastInc      Mono
	hetero       Heterogeneity
	coverage     Coverage
	retired      int
	stopped      []StoppedFlow // measured ports stopped as duplicates of a route
	ttlAns       [256]int32    // discovery: ports that got a reply at TTL t
	ttlSilent    [256]int32    // discovery: ports that found TTL t silent
	ttlSole      [256]netip.Addr
	ttlSoleN     [256]int32
	ttlMulti     [256]bool // discovery: several routers seen at TTL t
	distHint     TTL       // path length estimated from reply TTLs
	ac           *anycastState
}

// StoppedFlow records a measured port that was stopped because its route
// turned out to be one that already has its measured ports.
type StoppedFlow struct {
	Flow   string    `json:"flow"`
	SPort  wire.Port `json:"sport"`
	Group  string    `json:"group"`
	Server string    `json:"server,omitempty"` // anycast: the server another port measures
	At     Wall      `json:"at_unix_ns"`
}

// AddEndpoint registers an endpoint with its source ports (in probing order).
//
// Flow set: with discovery, the first port is measured end to end at once;
// every route that discovery proves distinct then gets cfg.Flows of its
// ports measured, and a measured port is never replaced. Without discovery
// the first cfg.Flows ports are measured.
func (c *Core) AddEndpoint(target string, addr netip.Addr, port wire.Port, ports []wire.Port) (*Endpoint, error) {
	ep := &Endpoint{ID: EndpointID(len(c.eps)), Target: target, Addr: addr, Port: port,
		byPort: make(map[wire.Port]*Flow), ports: ports, groupMap: map[groupKey]*Group{}, groupIDs: map[string]groupKey{}}
	ep.bucket = stats.NewTokenBucket(c.cfg.EndpointPPS, max(2, c.cfg.EndpointPPS/50))
	ep.hopBucket = stats.NewTokenBucket(c.cfg.EndpointPPS, max(1, c.cfg.EndpointPPS/50))
	c.eps = append(c.eps, ep)
	want := c.cfg.Flows
	switch {
	case c.cfg.DiscoverOnly:
		want = 0
	case c.cfg.Discovery:
		want = 1 // the rest follows the routes discovery finds
	}
	for ep.disc.cursor < len(ports) && c.countMonitored(ep) < want {
		f, err := c.newFlow(ep, ports[ep.disc.cursor])
		ep.disc.cursor++
		if err != nil {
			continue
		}
		c.activate(f, RoleActive)
	}
	if want > 0 && c.countMonitored(ep) == 0 {
		return ep, fmt.Errorf("endpoint %s: no usable source port (all %d failed route lookup or reservation)", target, len(ports))
	}
	if c.cfg.Discovery {
		c.startDiscovery(ep)
	}
	if c.cfg.Anycast {
		c.startCensus(ep)
	}
	return ep, nil
}

func (c *Core) countMonitored(ep *Endpoint) int {
	n := 0
	for _, f := range ep.Flows {
		if f.Role.Monitored() {
			n++
		}
	}
	return n
}

// Endpoints returns the registered endpoints.
func (c *Core) Endpoints() []*Endpoint { return c.eps }

var errPortConflict = errors.New("source port conflict")

func (c *Core) newFlow(ep *Endpoint, sport wire.Port) (*Flow, error) {
	if f := ep.byPort[sport]; f != nil {
		return f, nil
	}
	rt, err := c.env.Route(ep.Addr, sport, ep.Port)
	if err != nil {
		c.M.RouteErrors++
		if c.FirstEnvErr == "" {
			c.FirstEnvErr = err.Error()
		}
		return nil, err
	}
	if err := c.env.Reserve(rt.Src, sport); err != nil {
		c.M.PortConflicts++
		if c.FirstEnvErr == "" {
			c.FirstEnvErr = err.Error()
		}
		return nil, fmt.Errorf("%w: %w", errPortConflict, err)
	}
	f := &Flow{ID: FlowID(len(c.flows)), Num: len(ep.Flows) + 1, EP: ep, IfIndex: rt.IfIndex, Gateway: rt.Gateway}
	f.Tmpl = wire.FlowTemplate{Src: rt.Src, Dst: ep.Addr, SPort: sport, DPort: ep.Port,
		TOS: c.cfg.TOS, FlowLabel: c.cfg.FlowLabel, MSS: rt.MSS}
	if f.Tmpl.MSS == 0 {
		f.Tmpl.MSS = 1460
		if ep.Addr.Is6() {
			f.Tmpl.MSS = 1440
		}
	}
	f.key = mkTuple(rt.Src, sport, ep.Addr, ep.Port)
	{
		s16, d16 := rt.Src.As16(), ep.Addr.As16()
		f.isnF = uint32(c.hash64(be64(s16[:8]), be64(s16[8:]), be64(d16[:8]), be64(d16[8:]), uint64(sport)<<16|uint64(ep.Port)))
	}
	f.rtt.ring = stats.NewRing[rttSample](rttRingSize)
	f.sm.init(c.now)
	f.route = newRouteObs(0, c.now)
	f.nextRVer = 1
	f.hopTTL = 1
	if old := c.tuples[f.key]; old != nil {
		f.recent = old.recent
	}
	c.tuples[f.key] = f
	c.flows = append(c.flows, f)
	ep.Flows = append(ep.Flows, f)
	ep.byPort[sport] = f
	return f, nil
}

func (c *Core) hash64(parts ...uint64) uint64 {
	h := fnv.New64a()
	var b [8]byte
	for _, p := range append(parts, c.cfg.Seed) {
		for i := range b {
			b[i] = byte(p >> (8 * i))
		}
		h.Write(b[:])
	}
	return h.Sum64()
}

// retuneHop leaves the hop probes of an endpoint what its measured flows do
// not need: E2E and hop probes together stay within --endpoint-pps.
func (c *Core) retuneHop(ep *Endpoint) {
	demand := float64(ep.measuring) / c.cfg.Interval.Seconds()
	ep.hopBucket.Rate = max(c.cfg.EndpointPPS-demand, c.cfg.EndpointPPS/10)
}

func (c *Core) activate(f *Flow, role Role) {
	if !f.Role.Monitored() {
		f.EP.measuring++
		c.retuneHop(f.EP)
	}
	f.Role = role
	f.everActive = true
	f.activeSince = c.now
	iv := c.cfgDur(c.cfg.Interval)
	f.phase = Mono(c.hash64(uint64(f.EP.ID), uint64(f.Num)) % uint64(iv))
	// First slot: next occurrence of the phase.
	k := (c.now - c.epochStart - f.phase) / iv
	if k < 0 {
		k = 0
	}
	f.slot = int64(k)
	for c.slotTime(f, f.slot) <= c.now {
		f.slot++
	}
	f.e2eGen++
	f.nextE2E = c.slotTime(f, f.slot)
	c.push(event{at: f.nextE2E, kind: evE2E, flow: f, gen: f.e2eGen})
	f.sm.monitoredSince = c.now
}

func (c *Core) deactivate(f *Flow) {
	if !f.Role.Monitored() {
		return
	}
	f.Role = RoleRetired
	f.EP.measuring--
	c.retuneHop(f.EP)
	f.e2eGen++
	// A trace deferred until "after the next E2E probe" would wait forever:
	// no more E2E probes come on this port.
	c.enqueue(f)
	f.EP.retired++
}

// slotTime returns the deterministic E2E slot time k of flow f, with a
// bounded deterministic jitter of ±5% of the interval.
func (c *Core) slotTime(f *Flow, k int64) Mono {
	iv := c.cfgDur(c.cfg.Interval)
	j := Mono(c.hash64(uint64(f.ID), uint64(k))%uint64(iv/10+1)) - iv/20
	return c.epochStart + f.phase + Mono(k)*iv + j
}

// Advance runs everything due at the current clock time and returns the
// next time the core wants to be woken up.
func (c *Core) Advance() Mono {
	c.now, c.nowRT = c.clk.Now()
	for c.heap.Len() > 0 && c.heap[0].at <= c.now {
		e := heap.Pop(&c.heap).(event)
		switch e.kind {
		case evE2E:
			if e.gen == e.flow.e2eGen && e.flow.Role.Monitored() {
				c.e2eSlot(e.flow, e.at)
			}
		case evDeadline:
			if e.p.id == e.gen && !e.p.completed {
				c.deadline(e.p)
			}
		case evFinalize:
			if e.p.id == e.gen && e.p.completed {
				c.finalize(e.p)
			}
		case evApp:
			if f := e.flow; f.appWant && f.active == nil && f.burst == 0 {
				f.appWant = false
				if f.tupleClean && f.Role.Monitored() {
					c.startApp(f)
				} else {
					// The E2E before it got no answer: this round's check is
					// skipped (the E2E loss already counts).
					f.appDueAt = c.now + c.cfgDur(c.cfg.AppInterval)
				}
			}
		case evRetry:
			if e.flow.retryAt == e.at {
				e.flow.retryAt = 0
				c.enqueue(e.flow)
			}
		}
	}
	next := c.runReady()
	c.maybeEval()
	c.ev.flush(false)
	if c.heap.Len() > 0 && (next == 0 || c.heap[0].at < next) {
		next = c.heap[0].at
	}
	ne := c.nextEvalAt()
	if next == 0 || ne < next {
		next = ne
	}
	return next
}

// e2eSlot handles a due E2E slot: send, or record an explicit skip.
func (c *Core) e2eSlot(f *Flow, due Mono) {
	iv := c.cfgDur(c.cfg.Interval)
	lag := c.now - due
	c.M.LagSum += lag
	c.M.LagN++
	if lag > c.M.LagMax {
		c.M.LagMax = lag
	}
	// Schedule the next slot first; never accumulate overdue slots.
	f.slot++
	// After a long pause of the process the slots it slept through are
	// stepped over at once, not one by one.
	if k := int64((c.now-c.epochStart-f.phase)/iv) - 1; k > f.slot {
		f.slot = k
	}
	for c.slotTime(f, f.slot) <= c.now {
		f.slot++
	}
	f.nextE2E = c.slotTime(f, f.slot)
	c.push(event{at: f.nextE2E, kind: evE2E, flow: f, gen: f.e2eGen})

	if c.cfg.ReportCountReached(f) {
		return
	}
	if lag > iv/2 {
		c.skip(f, SkipLag)
		return
	}
	if f.active != nil && f.active.class == ClassApp {
		c.skip(f, SkipApp) // the port is busy with a real connection
		return
	}
	if f.active != nil {
		p := f.active
		switch {
		case p.class != ClassE2E && (f.route.distance == 0 || p.ttl < f.route.distance):
			// A hop probe still waiting cannot reach the destination: cancel
			// it (never a loss) and give the slot to E2E.
			c.complete(p, OutCancelled)
		case p.deadMono-c.now <= iv/5:
			// The previous probe ends within the bounded jitter budget
			// (slot jitter ±5% plus ~10% deferral):
			// send right after it completes instead of skipping.
			f.e2eDeferred = true
			return
		default:
			c.skip(f, SkipBusy)
			return
		}
	}
	if c.appDue(f) {
		if f.tupleClean {
			c.startApp(f)
			return
		}
		// A hop probe left the 4-tuple half-open on stateful middleboxes:
		// this E2E closes it (answer + our reset), hop probes wait, and the
		// check starts right after the E2E (evApp).
		f.appWant = true
	}
	c.tryE2E(f)
}

// tryE2E sends an E2E probe if budgets allow, otherwise records a skip.
func (c *Core) tryE2E(f *Flow) {
	// A DOWN flow's E2E probes run into their timeout, which fills the
	// interval, so a hop probe never finds HopTimeout of room before the
	// next E2E: the route of the failing flow — the trace an outage is
	// localized with — goes stale and a route change on it is never seen.
	// Then every second slot goes to its hop probes (DOWN is already
	// declared; recovery still needs only a few slots), as many in a row as
	// fit the slot: the flow sends no more packets than a healthy one.
	f.traceSlot = false
	if f.sm.avail == AvailDown && c.now-f.hopAt >= 2*c.cfgDur(c.cfg.Interval) {
		if _, ok := c.hopClass(f); ok {
			f.traceSlot = true
			c.skip(f, SkipTrace)
			c.enqueue(f)
			return
		}
	}
	if f.incident != nil && f.sm.consecFail >= 2 {
		f.yieldCount++
		if f.yieldCount%3 == 0 {
			c.skip(f, SkipIncident)
			c.enqueue(f)
			return
		}
	}
	if c.inflight >= c.cfg.MaxInflight {
		c.skip(f, SkipInflight)
		return
	}
	if !c.global.Available(int64(c.now)) {
		c.skip(f, SkipPPS)
		return
	}
	if !f.EP.bucket.Available(int64(c.now)) {
		c.skip(f, SkipEndpointPPS)
		return
	}
	c.global.Take(int64(c.now))
	f.EP.bucket.Take(int64(c.now))
	c.send(f, ClassE2E, TTL(c.cfg.E2ETTL), c.cfgDur(c.cfg.Timeout))
}

// ReportCountReached reports whether report mode has executed Count probes
// on the flow already.
func (cfg Config) ReportCountReached(f *Flow) bool {
	return cfg.ReportCount > 0 && f.Executed >= cfg.ReportCount
}

func (c *Core) skip(f *Flow, r SkipReason) {
	f.C.Skipped++
	f.C.SkipBy[r]++
	c.M.SchedSkips++
	c.M.SkipBy[r]++
	f.win.add(c.bucketNum(c.now), OutSkipped)
}

func (c *Core) allocProbe() *Probe {
	var p *Probe
	if n := len(c.free); n > 0 {
		p = c.free[n-1]
		c.free = c.free[:n-1]
		*p = Probe{}
	} else {
		p = new(Probe)
	}
	c.nextProbe++
	p.id = c.nextProbe
	return p
}

func (c *Core) send(f *Flow, class Class, ttl TTL, timeout Mono) {
	c.sendProbe(f, class, ttl, timeout, false)
}

// sendProbe sends one probe. A burst probe (parallel discovery TTLs below
// the known path length) does not occupy the flow's single active slot: it
// never reaches the destination, and its ICMP reply is matched by the
// quoted sequence number.
func (c *Core) sendProbe(f *Flow, class Class, ttl TTL, timeout Mono, burst bool) {
	p := c.allocProbe()
	p.burst = burst
	p.flow, p.class, p.ttl = f, class, ttl
	f.tupleClean, f.lastSent = false, p.id // until an answer from the destination closes it
	// ISN = M + F(4-tuple) + small random jitter, M = 4 µs realtime clock
	// (RFC 6528 structure, as real TCP stacks do). Sequence numbers of a
	// 4-tuple therefore always move forward — within a run and across runs.
	// Stateful middleboxes (conntrack/NAT) accept a re-sent SYN on a 4-tuple
	// still in SYN_SENT only when its seq is after the previous one
	// (RFC 793 re-initialization); a SYN with an earlier seq is dropped as
	// INVALID, which would be loss made by the measurer.
	for {
		p.seq = uint32(c.nowRT/4000) + f.isnF + c.rng.Uint32()%1024
		if f.lastSeq != 0 && int32(p.seq-f.lastSeq) <= 0 {
			p.seq = f.lastSeq + 1 + c.rng.Uint32()%1024
		}
		f.lastSeq = p.seq
		if p.seq == 0 {
			continue
		}
		if _, dup := c.bySeq[p.seq]; dup {
			continue
		}
		break
	}
	if d := f.route.distance; d == 0 || ttl >= d {
		f.noteReached(p.seq) // not a probe that expires on the way
	}
	p.ipid = uint16(c.rng.Uint32()%0xfffe) + 1
	p.sentMono, p.sentRT = c.now, c.nowRT
	if class == ClassDiscovery || class == ClassIncident || class == ClassRefresh {
		f.hopAt = c.now
	}
	p.deadMono, p.deadRT = c.now+timeout, c.nowRT.Add(time.Duration(timeout))
	if class == ClassE2E {
		f.C.Sent++
		c.M.SentE2E++
		c.e2eRate.add(c.now)
	} else {
		c.M.SentHop[class]++
		c.hopRate.add(c.now)
	}
	if err := c.tr.Send(f, p.seq, ttl.Byte(), p.ipid); err != nil {
		c.M.LocalErrors++
		p.flow = f
		p.completed = true
		p.outcome = OutLocalError
		c.record(p)
		c.free = append(c.free, p)
		return
	}
	if burst {
		f.burst++
	} else {
		f.active = p
	}
	c.bySeq[p.seq] = p
	c.inflight++
	c.push(event{at: p.deadMono, kind: evDeadline, p: p, gen: p.id})
}

// deadline handles a probe deadline. The timeout is only declared once the
// capture watermark proves that every packet up to the deadline has been
// delivered (or that drops happened in that period).
func (c *Core) deadline(p *Probe) {
	if p.class == ClassApp {
		c.finishApp(p, AppResult{Outcome: AppLocal, Stage: StagePlugin, Err: "no result in time"})
		return
	}
	if c.watermarkRT < p.deadRT {
		if c.now-p.deadMono > Mono(time.Second) {
			c.M.WatermarkStalls++
			c.complete(p, OutCaptureImpaired)
			return
		}
		c.push(event{at: c.now + Mono(5*time.Millisecond), kind: evDeadline, p: p, gen: p.id})
		return
	}
	o := OutTimeout
	switch {
	case c.dropOverlap(p.sentRT, p.deadRT):
		// Capture lost packets while this probe waited (possibly its own
		// SYN capture or its reply): measurement impaired, not a loss.
		o = OutCaptureImpaired
	case !p.txSeen:
		// Our own SYN was never seen leaving: local problem, not a loss.
		c.M.TxNotObserved++
		o = OutLocalError
	case p.sawUnexpected:
		o = OutUnexpected
	case p.class == ClassE2E && p.flow.remoteUntil > p.sentMono:
		o = OutRemoteState
	}
	c.complete(p, o)
}

func (c *Core) dropOverlap(from, to Wall) bool {
	for _, d := range c.drops {
		if d.to != 0 && d.from <= to && d.to >= from {
			return true
		}
	}
	return false
}

// complete fixes the outcome, frees the flow for the next probe and moves
// the probe into the guard window. Statistics are recorded at finalize.
func (c *Core) complete(p *Probe, o Outcome) {
	if p.completed {
		return
	}
	f := p.flow
	p.completed = true
	p.completedMono = c.now
	p.outcome = o
	if f.active == p {
		f.active = nil
	}
	if p.burst {
		f.burst--
	}
	c.inflight--
	f.pushRecent(p, c.now)
	if o == OutCancelled {
		c.M.HopCancelled++
	}
	if c.finalizable(p) {
		c.finalize(p)
	} else {
		c.push(event{at: c.now + Mono(200*time.Millisecond), kind: evFinalize, p: p, gen: p.id})
	}
	if f.e2eDeferred && p.class == ClassE2E {
		f.e2eDeferred = false
		if f.Role.Monitored() && !c.cfg.ReportCountReached(f) {
			c.tryE2E(f)
			return
		}
	}
	c.enqueue(f)
}

func (c *Core) finalizable(p *Probe) bool {
	switch p.outcome {
	case OutSynAck, OutRst, OutDestReached, OutTimeExceeded, OutICMPUnreach, OutWeak:
	default:
		return true
	}
	if !p.txSeen {
		return false
	}
	if p.gotSynAck {
		return p.rstSeen
	}
	return true
}

func (c *Core) finalize(p *Probe) {
	if p.id == 0 {
		return
	}
	if p.gotSynAck && !p.rstSeen {
		p.flow.C.RstMissing++
	}
	delete(c.bySeq, p.seq)
	if p.txSeen && !p.txIfOK {
		p.flow.C.EgressMismatch++
	}
	c.record(p)
	p.id = 0
	c.free = append(c.free, p)
}

// rttUs returns the probe RTT in microseconds and whether the kernel TX
// timestamp was used.
func (c *Core) rttUs(p *Probe) (uint32, bool) {
	start := p.sentRT
	kern := false
	if p.txSeen && p.txRT != 0 {
		// Sanity: the captured TX timestamp must be close to our send time.
		if d := p.txRT.Sub(p.sentRT); d > -50*time.Millisecond && d < 50*time.Millisecond {
			start, kern = p.txRT, true
		}
	}
	d := p.rxRT - start
	if d < 0 {
		d = 0
	}
	return uint32(d / 1000), kern
}

// enqueue offers a free flow to the hop scheduler if it has hop work.
func (c *Core) enqueue(f *Flow) {
	if f.inQueue || f.active != nil || f.retryAt != 0 {
		return
	}
	cl, ok := c.hopClass(f)
	if !ok {
		return
	}
	f.inQueue = true
	c.ready[cl].push(f)
}

var drrWeight = [numClasses]int{0, 6, 3, 1, 2, 0} // e2e and app (not queued), incident, refresh, discovery, census

// runReady dispatches hop work using deficit round robin across the
// incident, refresh and discovery classes, under global/reserve PPS,
// per-endpoint PPS, max inflight, per-responder budgets and per-flow
// serialization. Returns the earliest wake time needed for blocked work.
func (c *Core) runReady() Mono {
	var wake Mono
	setWake := func(t Mono) {
		if wake == 0 || t < wake {
			wake = t
		}
	}
	for iter := 0; iter < 100000; iter++ {
		progressed := false
		for cl := ClassIncident; cl < numClasses; cl++ {
			q := &c.ready[cl]
			if q.size == 0 {
				c.drrDef[cl] = 0
				continue
			}
			c.drrDef[cl] += drrWeight[cl]
			for c.drrDef[cl] > 0 && q.size > 0 {
				if c.inflight >= c.cfg.MaxInflight {
					return c.now + Mono(time.Millisecond)
				}
				if c.global.Tokens(int64(c.now)) < c.global.Burst/2+1 && !c.reserve.Available(int64(c.now)) {
					setWake(Mono(min(c.global.NextAt(int64(c.now)), c.reserve.NextAt(int64(c.now)))))
					return wake
				}
				f := q.pop()
				f.inQueue = false
				r := c.tryHop(f)
				switch r {
				case hopSent:
					c.drrDef[cl]--
					progressed = true
				case hopBlockedEP:
					f.inQueue = true
					q.pushFront(f)
					setWake(Mono(f.EP.hopBucket.NextAt(int64(c.now))))
					c.drrDef[cl] = 0
				default:
					progressed = true
				}
				if r == hopBlockedEP {
					break
				}
			}
		}
		if !progressed {
			break
		}
	}
	return wake
}

// takeHopToken draws hop probes from the global bucket only while it keeps
// headroom for E2E, otherwise from the hop reserve (so hop classes neither
// starve nor take E2E's tokens).
func (c *Core) takeHopToken() bool {
	if c.global.Tokens(int64(c.now)) >= c.global.Burst/2+1 && c.global.Take(int64(c.now)) {
		return true
	}
	return c.reserve.Take(int64(c.now))
}

type rateMeter struct {
	sec   [8]uint32
	stamp [8]int64
}

func (r *rateMeter) add(now Mono) {
	s := int64(now / Mono(time.Second))
	i := s % 8
	if r.stamp[i] != s {
		r.stamp[i], r.sec[i] = s, 0
	}
	r.sec[i]++
}

// rate returns the average per-second rate over the last complete seconds.
func (r *rateMeter) rate(now Mono) float64 {
	s := int64(now / Mono(time.Second))
	var n, k float64
	for d := int64(1); d <= 5; d++ {
		i := (s - d) % 8
		if i < 0 {
			continue
		}
		k++
		if r.stamp[i] == s-d {
			n += float64(r.sec[i])
		}
	}
	if k == 0 {
		return 0
	}
	return n / k
}

// OnWatermark is called by the capture side after draining: every packet
// with a kernel timestamp <= rt has been delivered, and drops counts the
// packets lost (kernel ring + userspace queue) since the previous call.
func (c *Core) OnWatermark(rt Wall, kernelDrops, userDrops uint64) {
	c.OnWatermarkDrops(rt, kernelDrops, userDrops, 0, 0)
}

// OnWatermarkDrops is OnWatermark with the realtime interval in which the
// drops happened (0 = unknown: the interval since the previous watermark,
// up to now, is assumed). The recorded period is padded conservatively.
func (c *Core) OnWatermarkDrops(rt Wall, kernelDrops, userDrops uint64, dropFrom, dropTo Wall) {
	c.now, c.nowRT = c.clk.Now()
	if kernelDrops+userDrops > 0 {
		from := c.watermarkRT.Add(-20 * time.Millisecond)
		if dropFrom != 0 {
			from = min(from, dropFrom.Add(-20*time.Millisecond))
		}
		if c.watermarkRT == 0 {
			from = 0
		}
		to := max(rt, dropTo, c.nowRT)
		c.drops[c.dropPos] = dropPeriod{from: from, to: to}
		c.dropPos = (c.dropPos + 1) % len(c.drops)
		c.M.CaptureDrops += kernelDrops
		c.M.UserDrops += userDrops
		c.lastDropMono = c.now
		c.M.ImpairedPeriods++
	}
	if rt > c.watermarkRT {
		c.watermarkRT = rt
	}
	c.lastWMMono = c.now
}

// OnLocalError records a transport-level error not tied to one probe.
func (c *Core) OnLocalError() { c.M.LocalErrors++ }

// OnMalformed counts packets the receiver could not parse.
func (c *Core) OnMalformed(n uint64) { c.M.Malformed += n }

// Now returns the core clock as of the last Advance.
func (c *Core) Now() Mono { return c.now }

func (c *Core) bucketNum(t Mono) int64 { return int64((t - c.epochStart) / c.bucket) }

// RevalidateRoutes re-runs the per-flow route lookup for monitored flows.
// A flow whose source address, egress interface or gateway changed gets a
// new identity: the old Flow is retired with its statistics and marked
// local_route_changed, and a new Flow (new ID) continues on that port.
// Measurements before and after the change are never mixed.
func (c *Core) RevalidateRoutes() (changed int) {
	c.now, c.nowRT = c.clk.Now()
	for _, ep := range c.eps {
		for _, f := range append([]*Flow(nil), ep.Flows...) {
			if !f.Role.Monitored() || f.invalid != ValidFlow {
				continue
			}
			rt, err := c.env.Route(ep.Addr, f.SPort(), ep.Port)
			if err != nil {
				c.M.RouteErrors++
				continue
			}
			if rt.Src == f.Tmpl.Src && rt.IfIndex == f.IfIndex && rt.Gateway == f.Gateway {
				continue
			}
			role := f.Role
			c.deactivate(f)
			f.invalid = InvalidLocalRoute
			delete(ep.byPort, f.SPort())
			nf, err := c.newFlow(ep, f.SPort())
			if err != nil {
				continue
			}
			nf.recent = f.recent
			c.activate(nf, role)
			changed++
			c.ev.flowInvalid(f)
		}
	}
	return changed
}

// ReportDone reports whether every monitored flow executed the configured
// number of E2E probes (report mode).
func (c *Core) ReportDone() bool {
	if c.cfg.ReportCount == 0 {
		return false
	}
	if c.cfg.Discovery && !c.DiscoveryDone() {
		return false // more routes (and measured ports) may still come
	}
	for _, ep := range c.eps {
		if ep.ac != nil && ep.ac.status == ACRunning {
			return false // more servers (and measured ports) may still come
		}
	}
	for _, ep := range c.eps {
		for _, f := range ep.Flows {
			if f.Role.Monitored() && f.invalid == ValidFlow && f.Executed < c.cfg.ReportCount {
				return false
			}
			if f.active != nil && f.active.class == ClassE2E {
				return false
			}
		}
	}
	return true
}

// ReportProgress returns executed and target E2E probe counts.
func (c *Core) ReportProgress() (done, total int) {
	for _, ep := range c.eps {
		for _, f := range ep.Flows {
			if f.Role.Monitored() && f.invalid == ValidFlow {
				done += min(f.Executed, c.cfg.ReportCount)
				total += c.cfg.ReportCount
			}
		}
	}
	return
}

// Metrics returns a copy of the measurer self-diagnostics.
func (c *Core) Metrics() Metrics { return c.M }
