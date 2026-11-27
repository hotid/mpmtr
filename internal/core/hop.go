package core

import (
	"net/netip"
	"slices"
	"time"

	"github.com/hotid/mpmtr/internal/stats"
	"github.com/hotid/mpmtr/internal/wire"
)

type respCount struct {
	addr netip.Addr
	n    uint32
}

// HopStat holds the observations of one (flow, TTL) within a route version.
type HopStat struct {
	Sent, Replies, Timeouts uint32
	Cancelled, Other        uint32 // cancelled / impaired / local / weak: never loss
	LowConf                 uint32 // quote_seq_mismatch fallback matches
	Dest                    uint32 // destination reached at this TTL
	resp                    [4]respCount
	cur, pending            netip.Addr
	pendN                   uint8
	Unstable                bool
	rtt                     stats.Ring[uint32]
	Min, Max, Last          uint32
	jit                     stats.Jitter
	LastProbe, LastReply    Mono
	UnreachSeen             bool
	ICMPType, ICMPCode      uint8
	MPLS                    [wire.MaxMPLS]wire.MPLSEntry
	NMPLS                   int
	// inferred: not probed by this flow in discovery; every traced port of
	// the endpoint showed this router here (--shared-hops prefix skip).
	inferred netip.Addr
	// through: routers that answered probes sent with this TTL and probes
	// sent with a larger one. A router at position k of a path gets a probe
	// sent with a larger TTL while it still has TTL to spare and forwards
	// it, so it answers only probes sent with TTL <= k: its position is the
	// largest TTL it answered, and its answers to smaller ones say nothing
	// about who is there. (Some routers both answer a probe and forward it:
	// one probe sent with TTL 3 is then answered by the routers of TTL 3, 4
	// and 5.) The rule uses the forward path only: not the TTL the answers
	// arrive with, not their order.
	through [4]netip.Addr
}

// responders calls fn for every responder that answered for this TTL itself.
func (h *HopStat) responders(fn func(a netip.Addr, n uint32)) {
	for _, r := range h.resp {
		if r.addr.IsValid() && r.n > 0 && !h.isThrough(r.addr) {
			fn(r.addr, r.n)
		}
	}
}

func (h *HopStat) isThrough(a netip.Addr) bool {
	return a.IsValid() && slices.Contains(h.through[:], a)
}

// setThrough marks a as a router of a later TTL: it is not this hop's
// router, whatever was assumed so far.
func (h *HopStat) setThrough(a netip.Addr) {
	if h.cur == a {
		h.cur = netip.Addr{}
	}
	if h.pending == a {
		h.pending, h.pendN = netip.Addr{}, 0
	}
	if h.isThrough(a) {
		return
	}
	for i := range h.through {
		if !h.through[i].IsValid() {
			h.through[i] = a
			return
		}
	}
}

// answeredLater reports whether a answered a probe sent with a TTL above t.
func (r *RouteObs) answeredLater(t TTL, a netip.Addr) bool {
	for u := t + 1; u <= r.top(); u++ {
		if r.hops[u-1].count(a) > 0 {
			return true
		}
	}
	return false
}

// laterOnEndpoint reports whether some port of the endpoint saw a answer at
// a TTL above t.
func (c *Core) laterOnEndpoint(ep *Endpoint, t TTL, a netip.Addr) bool {
	for _, f := range ep.Flows {
		if f.route != nil && f.route.answeredLater(t, a) {
			return true
		}
	}
	return false
}

// place records that a answered a probe sent with TTL t and reports whether
// its position is a later TTL (see HopStat.through).
func (r *RouteObs) place(t TTL, a netip.Addr) bool {
	h := r.hop(t)
	h.addResp(a)
	for u := TTL(1); u < t; u++ {
		if o := &r.hops[u-1]; o.count(a) > 0 {
			o.setThrough(a)
		}
	}
	if r.answeredLater(t, a) {
		h.setThrough(a)
		return true
	}
	return false
}

// alsoAnswered: another router answered a hop probe that already has its
// answer. It is one more observation of who answers at that TTL.
func (c *Core) alsoAnswered(f *Flow, r *probeRec, p *wire.Packet) {
	if r.class == ClassE2E || r.class == ClassApp || r.class == ClassCensus || r.outcome != OutTimeExceeded ||
		!r.from.IsValid() || p.Src == r.from {
		return
	}
	if te := (!p.V6 && p.ICMPType == wire.ICMP4TimeExceed) || (p.V6 && p.ICMPType == wire.ICMP6TimeExceed); !te {
		return
	}
	c.M.MultiAnswer++
	c.observeResponder(f, r.ttl, p.Src)
}

func (h *HopStat) count(a netip.Addr) uint32 {
	for _, r := range h.resp {
		if r.addr == a {
			return r.n
		}
	}
	return 0
}

func (h *HopStat) addResp(a netip.Addr) {
	for i := range h.resp {
		if h.resp[i].addr == a {
			h.resp[i].n++
			return
		}
	}
	// replace the least frequent slot
	mi := 0
	for i := range h.resp {
		if !h.resp[i].addr.IsValid() {
			mi = i
			break
		}
		if h.resp[i].n < h.resp[mi].n {
			mi = i
		}
	}
	h.resp[mi] = respCount{addr: a, n: 1}
}

// multi reports how many distinct responders were seen at least twice.
func (h *HopStat) multi() int {
	n := 0
	h.responders(func(_ netip.Addr, k uint32) {
		if k >= 2 {
			n++
		}
	})
	return n
}

// RouteObs is one version of the observed route of a flow.
type RouteObs struct {
	Ver        int
	Start, End Mono
	hops       []HopStat
	distance   TTL // min TTL at which the destination answered (confirmed); 0 = UNKNOWN
	distPend   TTL
	distPendN  int
	unreachTTL TTL // ICMP unreachable ended the path here
	maxReplied TTL
	sweeps     int
	Reason     RouteChange // why the previous version ended

	E2EValid, E2EFail uint64
	RTTSum            float64
	RTTN              uint64
}

func newRouteObs(ver int, now Mono) *RouteObs { return &RouteObs{Ver: ver, Start: now} }

func (r *RouteObs) hop(ttl TTL) *HopStat {
	for r.top() < ttl {
		r.hops = append(r.hops, HopStat{rtt: stats.NewRing[uint32](hopRTTRing)})
	}
	return &r.hops[ttl-1]
}

func (r *RouteObs) hopIf(ttl TTL) *HopStat {
	if ttl < 1 || ttl > r.top() {
		return nil
	}
	return &r.hops[ttl-1]
}

// top is the last hop the route has an observation for.
func (r *RouteObs) top() TTL { return TTL(len(r.hops)) }

// Distance returns the confirmed distance (0 = UNKNOWN).
func (r *RouteObs) Distance() TTL { return r.distance }

// sweep is a serial TTL sweep on one flow (discovery, incident or refresh).
type sweep struct {
	// Parallel TTLs (discovery): TTLs [burstLo, burstEnd) are probed at
	// once, in rounds, until each answered or ran out of tries.
	burstLo, burstEnd TTL
	burstDone         bool
	bDone, bFly       [64]bool
	bTries            [64]uint8
	bDest             TTL

	class  Class
	pass   int
	passes int
	ttl    TTL
	tries  int
	other  int
	limit  TTL
	endTTL TTL
	done   bool
	focus  bool // a full trace of the port in focus (see focus.go)
}

func (c *Core) startSweep(f *Flow, cl Class, passes int) {
	limit := c.cfg.MaxTTL
	if f.route.distance > 0 {
		limit = f.route.distance
	}
	f.sw = &sweep{class: cl, pass: 1, passes: passes, ttl: 1, limit: limit}
	c.enqueue(f)
}

// skipSharedPrefix (--shared-hops, discovery): a TTL where every traced
// port saw the same single router (>= 8 ports) is taken as known instead of
// probed; every 8th port still traces it, so a second router there stops
// the skipping.
func (c *Core) skipSharedPrefix(f *Flow) {
	sw := f.sw
	if !c.cfg.SharedHops || sw == nil || sw.class != ClassDiscovery || f.ID%8 == 0 || sw.tries > 0 {
		return
	}
	ep := f.EP
	for t := sw.ttl; t < TTL(len(ep.ttlSole)) && t < sw.limit; t++ {
		if ep.ttlMulti[t] || ep.ttlSoleN[t] < 8 {
			return
		}
		// only a prefix: every lower TTL must be known for this flow too
		if t > 1 {
			if h := f.route.hopIf(t - 1); h == nil || (!h.inferred.IsValid() && h.Replies == 0) {
				return
			}
		}
		f.route.hop(t).inferred = ep.ttlSole[t]
		sw.ttl = t + 1
	}
}

func (c *Core) triesFor(f *Flow, sw *sweep) int {
	if sw.class == ClassDiscovery && sw.pass == 1 {
		return c.triesAt(f, sw.ttl)
	}
	if h := f.route.hopIf(sw.ttl); h != nil && h.Replies == 1 {
		return 2
	}
	return 1
}

// minDist is the shortest known path length of the endpoint's ports.
func (ep *Endpoint) minDist() TTL {
	d := TTL(0)
	for _, f := range ep.Flows {
		if r := f.route.distance; r > 0 && (d == 0 || r < d) {
			d = r
		}
	}
	return d
}

// tryBurst sends the next round of parallel discovery TTLs; ok=false means
// the sweep continues one TTL at a time.
func (c *Core) tryBurst(f *Flow, ht Mono) (hopResult, bool) {
	sw := f.sw
	if sw == nil || sw.pass != 1 || sw.burstDone {
		return 0, false
	}
	if sw.burstEnd == 0 {
		c.skipSharedPrefix(f)
		d := f.EP.minDist()
		if d == 0 && f.EP.distHint >= 5 {
			// No traced length yet: stay 2 TTLs below the length estimated
			// from the destination's reply TTL (reverse path may differ).
			d = f.EP.distHint - 2
		}
		if d == 0 {
			return 0, false // nothing known: TTLs could reach the destination
		}
		end := min(d, sw.limit+1, TTL(len(sw.bDone)))
		if end-sw.ttl < 2 {
			sw.burstDone = true
			return 0, false
		}
		sw.burstLo, sw.burstEnd = sw.ttl, end
	}
	for t := sw.burstLo; t < sw.burstEnd; t++ {
		if sw.bFly[t] {
			return hopNoWork, true // round still settling; burstStep re-enqueues
		}
	}
	sent := 0
	var wake Mono
	for t := sw.burstLo; t < sw.burstEnd; t++ {
		if sw.bDone[t] {
			continue
		}
		rb := c.respBucketFor(c.respKeyFor(f, t))
		if !rb.tb.Available(int64(c.now)) {
			c.M.HopDeferResp++
			if at := Mono(rb.tb.NextAt(int64(c.now))); wake == 0 || at < wake {
				wake = at
			}
			continue
		}
		if !f.EP.hopBucket.Available(int64(c.now)) || !c.takeHopToken() {
			break
		}
		rb.tb.Take(int64(c.now))
		f.EP.hopBucket.Take(int64(c.now))
		sw.bFly[t] = true
		c.sendProbe(f, sw.class, t, ht, true)
		sent++
	}
	switch {
	case sent > 0 || f.burst > 0:
		return hopSent, true
	case wake > 0:
		f.retryAt = wake
		c.push(event{at: wake, kind: evRetry, flow: f})
		return hopDeferred, true
	}
	return hopBlockedEP, true
}

// burstStep records one parallel probe's result; when every TTL of the
// burst is settled the sweep continues one TTL at a time from its end.
func (c *Core) burstStep(f *Flow, p *Probe) {
	sw := f.sw
	t := p.ttl
	if sw == nil || sw.burstEnd == 0 || t < sw.burstLo || t >= sw.burstEnd {
		return
	}
	sw.bFly[t] = false
	switch p.outcome {
	case OutTimeExceeded:
		sw.bDone[t] = true
		c.noteTTLAnswer(f, t, p.from)
	case OutDestReached, OutICMPUnreach:
		sw.bDone[t] = true
		if sw.bDest == 0 || t < sw.bDest {
			sw.bDest = t
		}
	case OutTimeout:
		sw.bTries[t]++
		if int(sw.bTries[t]) >= c.triesAt(f, t) {
			sw.bDone[t] = true
			c.noteTTLSilent(f, t)
		}
	default:
		sw.bTries[t]++
		if sw.bTries[t] > 5 {
			sw.bDone[t] = true
		}
	}
	for u := sw.burstLo; u < sw.burstEnd; u++ {
		if sw.bFly[u] {
			return // round still settling
		}
	}
	defer c.enqueue(f)
	for u := sw.burstLo; u < sw.burstEnd; u++ {
		if !sw.bDone[u] {
			return // next round
		}
	}
	sw.ttl = sw.burstEnd
	if sw.bDest > 0 {
		sw.ttl = sw.bDest // shorter path: confirm the destination serially
	}
	sw.burstEnd, sw.burstDone = 0, true
	sw.tries, sw.other = 0, 0
}

// noteTTLAnswer counts the ports that saw a responder at TTL t (a port
// counts once, however often it is traced: the shared-hop rule needs eight
// different ports, not eight answers to one).
func (c *Core) noteTTLAnswer(f *Flow, t TTL, from netip.Addr) {
	ep := f.EP
	if t >= TTL(len(ep.ttlAns)) {
		return
	}
	first := f.ttlNoted.set(t)
	if first {
		ep.ttlAns[t]++
	}
	switch {
	case !ep.ttlSole[t].IsValid():
		ep.ttlSole[t], ep.ttlSoleN[t] = from, 1
	case ep.ttlSole[t] != from:
		ep.ttlMulti[t] = true
	case first:
		ep.ttlSoleN[t]++
	}
}

// noteTTLSilent counts the ports that found TTL t silent (once per port).
func (c *Core) noteTTLSilent(f *Flow, t TTL) {
	if ep := f.EP; t < TTL(len(ep.ttlSilent)) && f.ttlQuiet.set(t) {
		ep.ttlSilent[t]++
	}
}

// ttlSet is a set of TTLs.
type ttlSet [4]uint64

// set adds t and reports whether it was new.
func (s *ttlSet) set(t TTL) bool {
	w, b := &s[(t>>6)&3], uint64(1)<<(t&63)
	if *w&b != 0 {
		return false
	}
	*w |= b
	return true
}

func (c *Core) sweepStep(f *Flow, p *Probe) {
	if p.burst {
		c.burstStep(f, p)
		return
	}
	sw := f.sw
	if sw == nil || sw.done || p.class != sw.class || p.ttl != sw.ttl {
		return
	}
	endPass := false
	switch p.outcome {
	case OutTimeExceeded:
		c.noteTTLAnswer(f, sw.ttl, p.from)
		sw.ttl++
		sw.tries, sw.other = 0, 0
	case OutDestReached, OutICMPUnreach:
		sw.endTTL = sw.ttl
		endPass = true
	case OutTimeout:
		sw.tries++
		if sw.tries >= c.triesFor(f, sw) {
			c.noteTTLSilent(f, sw.ttl)
			sw.ttl++
			sw.tries, sw.other = 0, 0
		}
	default:
		sw.other++
		if sw.other > 5 {
			sw.ttl++
			sw.tries, sw.other = 0, 0
		}
	}
	if sw.ttl > sw.limit {
		endPass = true
	}
	if !endPass {
		return
	}
	f.route.sweeps++
	if sw.pass < sw.passes {
		sw.pass++
		sw.ttl, sw.tries, sw.other = 1, 0, 0
		switch {
		case sw.endTTL > 0:
			sw.limit = sw.endTTL
		case f.route.distance > 0:
			sw.limit = f.route.distance
		default:
			// Destination not reached: pass 1 already went to max TTL;
			// confirmation passes cover the responsive part plus margin.
			sw.limit = min(c.cfg.MaxTTL, f.route.maxReplied+3)
		}
		sw.endTTL = 0
		return
	}
	sw.done = true
	f.sw = nil
	switch sw.class {
	case ClassDiscovery:
		if f.retrace {
			f.retrace = false
			break
		}
		c.discCandidateDone(f)
	case ClassIncident:
		c.incidentFlowDone(f)
	}
}

// hopClass returns the class of the hop work the flow has pending.
func (c *Core) hopClass(f *Flow) (Class, bool) {
	if f.sw != nil && !f.sw.done {
		return f.sw.class, true
	}
	if f.census && f.invalid == ValidFlow {
		return ClassCensus, true
	}
	if c.focus != nil && c.focus.invalid != ValidFlow {
		c.focus = nil // it can no longer be measured: nobody waits for it
	}
	if c.focus != nil { // with a port in focus the others' hop refresh waits
		return ClassRefresh, f == c.focus && c.cfg.Discovery && f.invalid == ValidFlow
	}
	if c.cfg.Discovery && f.Role.Monitored() && f.invalid == ValidFlow {
		return ClassRefresh, true
	}
	return 0, false
}

type hopResult uint8

const (
	hopNoWork hopResult = iota
	hopSent
	hopDeferred
	hopBlockedEP
)

func (c *Core) refreshLimit(f *Flow) TTL {
	if f.route.distance > 0 {
		return f.route.distance
	}
	// Distance not known yet (a port measured without being traced, e.g.
	// one the anycast census chose): reach past silent routers up to the
	// farthest destination seen on this endpoint, or the trace never
	// completes and the port never joins its route.
	return min(c.cfg.MaxTTL, max(1, f.route.maxReplied+2, c.epMaxDist(f.EP)+1))
}

// epMaxDist is the longest known distance to the endpoint (0 if none).
func (c *Core) epMaxDist(ep *Endpoint) TTL {
	d := TTL(0)
	for _, g := range ep.groups {
		if g.Sig.distKnown {
			d = max(d, TTL(len(g.Sig.hops)+1))
		}
	}
	return d
}

type freshRec struct {
	at   Mono
	flow FlowID
}

// nextHopTTL selects the TTL to probe next for the given class.
func (c *Core) nextHopTTL(f *Flow, cl Class) TTL {
	if cl == ClassCensus {
		return TTL(c.cfg.E2ETTL)
	}
	if cl != ClassRefresh {
		c.skipSharedPrefix(f)
		return f.sw.ttl
	}
	L := c.refreshLimit(f)
	if f.hopTTL < 1 || f.hopTTL > L {
		f.hopTTL = 1
	}
	t := f.hopTTL
	for i := TTL(0); i < L; i++ {
		if !c.dedupSkip(f, t) {
			return t
		}
		t = t%L + 1
	}
	return f.hopTTL
}

// dedupSkip implements shared-prefix deduplication: a confirmed hop whose
// responder was refreshed very recently by another flow of a confirmed
// group can be skipped for a while. It is purely a budget optimization —
// nothing is copied into this flow's statistics, and each flow still
// re-probes every hop within dedupMaxAge, before its row would turn stale
// (hopStale: three buckets).
func (c *Core) dedupSkip(f *Flow, t TTL) bool {
	if c.cfg.SharedHops {
		if h := f.route.hopIf(t); h != nil && h.cur.IsValid() && !h.Unstable {
			if o, ok := c.hopOwner[hopKey{ttl: t, addr: h.cur}]; ok && o != f && o.Role.Monitored() {
				return true
			}
		}
	}
	if f.level != LevelConfirmed {
		return false
	}
	h := f.route.hopIf(t)
	if h == nil || !h.cur.IsValid() || h.Unstable || h.LastProbe == 0 || c.now-h.LastProbe > c.dedupMaxAge() {
		return false
	}
	fr, ok := c.respFresh[h.cur]
	return ok && fr.flow != f.ID && c.now-fr.at < Mono(5*time.Second)
}

// dedupMaxAge: how long a flow may leave a hop to the other flows. Two
// buckets: a flow probes one TTL per interval and a bucket is ten, so the
// round after the limit fits before the third bucket ends.
func (c *Core) dedupMaxAge() Mono { return 2 * c.bucket }

func (c *Core) respKeyFor(f *Flow, ttl TTL) respKey {
	if h := f.route.hopIf(ttl); h != nil {
		if h.cur.IsValid() {
			return respKey{addr: h.cur}
		}
		best := respCount{}
		for _, r := range h.resp {
			if r.n > best.n {
				best = r
			}
		}
		if best.addr.IsValid() {
			return respKey{addr: best.addr}
		}
	}
	// Unknown responder: conservative key from egress, gateway, TTL and the
	// previous known hop. Not a claim of router identity.
	var prev netip.Addr
	if h := f.route.hopIf(ttl - 1); h != nil {
		prev = h.cur
	}
	g := f.Gateway.As16()
	p16 := prev.As16()
	return respKey{synth: c.hash64(uint64(f.IfIndex), uint64(ttl), be64(g[:8]), be64(g[8:]), be64(p16[:8]), be64(p16[8:]))}
}

func be64(b []byte) uint64 {
	var v uint64
	for _, x := range b {
		v = v<<8 | uint64(x)
	}
	return v
}

func (c *Core) respBucketFor(k respKey) *respBucket {
	rb := c.resp[k]
	if rb == nil {
		rb = &respBucket{tb: stats.NewTokenBucket(c.cfg.ResponderPPS, max(1, c.cfg.ResponderPPS))}
		c.resp[k] = rb
	}
	rb.last = c.now
	return rb
}

func (c *Core) gcResp() {
	if c.now-c.respGC < Mono(time.Minute) {
		return
	}
	c.respGC = c.now
	for k, rb := range c.resp {
		if c.now-rb.last > Mono(time.Minute) {
			delete(c.resp, k)
		}
	}
	for k, fr := range c.respFresh {
		if c.now-fr.at > Mono(time.Minute) {
			delete(c.respFresh, k)
		}
	}
}

func (c *Core) tryHop(f *Flow) hopResult {
	if f.active != nil || f.burst > 0 || f.appWant {
		return hopNoWork
	}
	if f == c.focus && c.cfg.Discovery && f.invalid == ValidFlow {
		if wait := c.focusSweep(f); wait > 0 {
			f.retryAt = c.now + wait
			c.push(event{at: f.retryAt, kind: evRetry, flow: f})
			return hopDeferred
		}
	}
	cl, ok := c.hopClass(f)
	if !ok {
		return hopNoWork
	}
	ht := c.cfgDur(c.cfg.HopTimeout)
	if (cl == ClassDiscovery || (f.sw != nil && f.sw.focus)) && !(f.Role.Monitored() && !c.cfg.ReportCountReached(f) && f.nextE2E-c.now-Mono(2*time.Millisecond) < ht) {
		if r, ok := c.tryBurst(f, ht); ok {
			return r
		}
	}
	if f.Role.Monitored() && !c.cfg.ReportCountReached(f) {
		room := f.nextE2E - c.now - Mono(2*time.Millisecond)
		if room < ht {
			c.M.HopDeferWindow++
			return hopDeferred // re-offered when the next E2E completes
		}
	}
	if cl == ClassRefresh {
		iv := c.cfgDur(c.cfg.Interval)
		if f.hopLastSent != 0 && c.now-f.hopLastSent < iv && !f.traceSlot {
			f.retryAt = f.hopLastSent + iv
			c.push(event{at: f.retryAt, kind: evRetry, flow: f})
			return hopDeferred
		}
	}
	ttl := c.nextHopTTL(f, cl)
	if ttl < 1 {
		return hopNoWork
	}
	isDest := f.route.distance > 0 && ttl >= f.route.distance
	if cl == ClassCensus {
		isDest, ht = true, c.cfgDur(c.cfg.Timeout)
	}
	var rb *respBucket
	if !isDest {
		rb = c.respBucketFor(c.respKeyFor(f, ttl))
		if !rb.tb.Available(int64(c.now)) {
			c.M.HopDeferResp++
			f.retryAt = Mono(rb.tb.NextAt(int64(c.now)))
			c.push(event{at: f.retryAt, kind: evRetry, flow: f})
			return hopDeferred
		}
	}
	if !f.EP.hopBucket.Available(int64(c.now)) {
		return hopBlockedEP
	}
	if !c.takeHopToken() {
		return hopBlockedEP
	}
	if rb != nil {
		rb.tb.Take(int64(c.now))
	}
	f.EP.hopBucket.Take(int64(c.now))
	if cl == ClassRefresh {
		f.hopLastSent = c.now
		f.hopTTL = ttl%c.refreshLimit(f) + 1
	}
	c.send(f, cl, ttl, ht)
	return hopSent
}

// dropSweep ends the trace of a flow that can no longer be measured, so that
// whoever waits for it (discovery, an incident) is not held up.
func (c *Core) dropSweep(f *Flow) {
	sw := f.sw
	if sw == nil {
		return
	}
	sw.done = true
	f.sw = nil
	switch sw.class {
	case ClassDiscovery:
		if f.retrace {
			f.retrace = false
			break
		}
		c.discCandidateDone(f)
	case ClassIncident:
		c.incidentFlowDone(f)
	}
}

// recordHop stores a finalized hop probe in the flow's current route version.
func (c *Core) recordHop(p *Probe) {
	f := p.flow
	if f.invalid != ValidFlow {
		c.dropSweep(f)
		return
	}
	t := p.ttl
	r := f.route
	h := r.hop(t)
	h.LastProbe = c.now
	switch p.outcome {
	case OutTimeExceeded, OutDestReached, OutICMPUnreach:
		h.Sent++
		h.Replies++
		if p.lowConf {
			h.LowConf++
		}
		// Timing only from the router of this TTL: the answer of a later
		// router measures another device.
		if us, _ := c.rttUs(p); !h.isThrough(p.from) && !r.answeredLater(t, p.from) {
			h.rtt.Add(us)
			if h.rtt.Len() == 1 || us < h.Min {
				h.Min = us
			}
			if us > h.Max {
				h.Max = us
			}
			h.Last = us
			h.jit.Add(us)
		}
		h.LastReply = c.now
		if p.nmpls > 0 {
			h.MPLS, h.NMPLS = p.mpls, p.nmpls
		}
		if t > r.maxReplied {
			r.maxReplied = t
		}
		if p.outcome == OutDestReached {
			h.Dest++
			c.observeDest(f, t)
		} else {
			if p.outcome == OutICMPUnreach {
				h.UnreachSeen = true
				h.ICMPType, h.ICMPCode = p.icmpType, p.icmpCode
				r.unreachTTL = t
			}
			c.observeResponder(f, t, p.from)
			c.respFresh[p.from] = freshRec{at: c.now, flow: f.ID}
		}
	case OutTimeout:
		h.Sent++
		h.Timeouts++
	case OutCancelled:
		h.Cancelled++
	default:
		h.Other++
	}
	c.sweepStep(f, p)
}

// observeDest records the destination answering at TTL t.
func (c *Core) observeDest(f *Flow, t TTL) {
	r := f.route
	switch {
	case r.distance == 0:
		// The destination answering a TTL-limited SYN is unambiguous (strict
		// correlation): the first answer sets the distance. A later shorter
		// distance still needs two answers (route change).
		r.distance = t
		r.distPend, r.distPendN = 0, 0
	case t < r.distance && r.sweeps == 0:
		// Still the first trace of this route: parallel TTLs that reach the
		// destination are answered in any order, and every answer is as
		// good as the first. The distance is the lowest of them.
		r.distance = t
		r.distPend, r.distPendN = 0, 0
	case t < r.distance:
		if r.distPend == t {
			r.distPendN++
		} else {
			r.distPend, r.distPendN = t, 1
		}
		if r.distPendN >= 2 {
			c.routeChanged(f, t, netip.Addr{}, netip.Addr{}, ChangeShorter)
			f.route.distance = t
		}
	default:
		if t == r.distance {
			r.distPend, r.distPendN = 0, 0
		}
	}
}

// observeResponder implements route change detection at one TTL: a new
// responder must be confirmed by two consecutive agreeing replies.
func (c *Core) observeResponder(f *Flow, t TTL, a netip.Addr) {
	r := f.route
	h := r.hop(t)
	if r.place(t, a) {
		return // a router of a later TTL: not a change here
	}
	if !h.cur.IsValid() {
		if h.pending == a {
			h.pendN++
		} else {
			h.pending, h.pendN = a, 1
		}
		if h.pendN >= 2 {
			h.cur, h.pending, h.pendN = a, netip.Addr{}, 0
		}
		return
	}
	if a == h.cur {
		h.pending, h.pendN = netip.Addr{}, 0
		return
	}
	if h.pending == a {
		h.pendN++
	} else {
		h.pending, h.pendN = a, 1
	}
	if h.multi() >= 2 && h.pendN < 2 {
		return
	}
	if h.pendN < 2 {
		return
	}
	// Confirmed change at this TTL — unless other ports of the endpoint saw
	// one of the two routers answer at a later TTL: this port lost the
	// answers that would place it, and the path did not change.
	old := h.cur
	if c.laterOnEndpoint(f.EP, t, old) {
		h.setThrough(old)
		h.cur = a
		return
	}
	if c.laterOnEndpoint(f.EP, t, a) {
		h.setThrough(a)
		return
	}
	// The history of changes belongs to the flow, not to the route version:
	// every confirmed change starts a new version with empty hop records.
	if f.hopChanges == nil {
		f.hopChanges = map[TTL]*[4]Mono{}
	}
	ch := f.hopChanges[t]
	if ch == nil {
		ch = new([4]Mono)
		f.hopChanges[t] = ch
	}
	n := 0
	for _, ts := range ch {
		if ts != 0 && c.now-ts < Mono(5*time.Minute) {
			n++
		}
	}
	copy(ch[1:], ch[:3])
	ch[0] = c.now
	if n >= 2 {
		// Flapping between responders: per-packet balancing or unstable
		// responder. Mark instead of reporting route changes.
		h.Unstable = true
		h.cur, h.pending, h.pendN = a, netip.Addr{}, 0
		return
	}
	if t >= r.distance && r.distance > 0 {
		c.routeChanged(f, t, old, a, ChangeLonger)
		return
	}
	c.routeChanged(f, t, old, a, ChangeResponder)
}

// routeChanged archives the current route version (with its statistics) and
// starts a new one. New measurements are never attributed to the old one.
func (c *Core) routeChanged(f *Flow, t TTL, old, nu netip.Addr, reason RouteChange) {
	prev := f.route
	prev.End = c.now
	nr := newRouteObs(f.nextRVer, c.now)
	f.nextRVer++
	nr.Reason = reason
	if nu.IsValid() {
		h := nr.hop(t)
		h.cur = nu
		h.addResp(nu)
		h.resp[0].n = 2
	}
	// Keep the prior distance as a hint only when it is not what changed.
	if reason == ChangeResponder {
		nr.distPend, nr.distPendN = prev.distance, 1
	}
	f.routeHist = append(f.routeHist, prev)
	if len(f.routeHist) > 4 {
		f.routeHist = f.routeHist[1:]
	}
	f.route = nr
	c.ev.routeChanged(f, t, old, nu, reason)
	if reason == ChangeResponder {
		c.retraceAfterChange(f, t, old)
	}
	// Rebuild the observation quickly (topology refresh priority).
	if f.sw == nil && c.cfg.Discovery {
		c.startSweep(f, ClassRefresh, 2)
	}
}

type hopKey struct {
	ttl  TTL
	addr netip.Addr
}

// buildHopOwners picks, for every (TTL, responder) seen by measured flows,
// the lowest-numbered flow that refreshes it (SharedHops).
func (c *Core) buildHopOwners() {
	if !c.cfg.SharedHops {
		return
	}
	clear(c.hopOwner)
	for _, ep := range c.eps {
		for _, f := range ep.Flows {
			if !f.Role.Monitored() || f.invalid != ValidFlow {
				continue
			}
			for t := TTL(1); t <= f.route.top(); t++ {
				h := f.route.hopIf(t)
				if h == nil || !h.cur.IsValid() || h.Unstable {
					continue
				}
				k := hopKey{ttl: t, addr: h.cur}
				if _, ok := c.hopOwner[k]; !ok { // endpoints and flows in order: first = lowest
					c.hopOwner[k] = f
				}
			}
		}
	}
}

// triesAt: discovery tries at TTL t. A TTL that never answered for any port
// of this endpoint while several ports found it silent gets one try.
func (c *Core) triesAt(f *Flow, t TTL) int {
	if ep := f.EP; t < TTL(len(ep.ttlAns)) && ep.ttlAns[t] == 0 && ep.ttlSilent[t] >= 3 {
		return 1
	}
	return 2
}

// retraceAfterChange: a confirmed responder change at TTL t on one port
// means the topology moved there. Ports that are not measured are traced
// once and never refreshed, so every one whose trace still shows the old
// responder at t keeps a route that may no longer exist (an upstream switch
// moves them all), and a trace that the change cut in the middle mixes both
// paths into a route that never existed. They are traced again from
// scratch; ports that still take the old path rebuild that route.
func (c *Core) retraceAfterChange(by *Flow, t TTL, old netip.Addr) {
	if !c.cfg.Discovery || !old.IsValid() {
		return
	}
	for _, f := range by.EP.Flows {
		if f == by || f.Role.Monitored() || f.invalid != ValidFlow || f.sw != nil || f.census || len(f.route.hops) == 0 {
			continue
		}
		if f.retraceAt != 0 && c.now-f.retraceAt < Mono(time.Minute) {
			continue
		}
		h := f.route.hopIf(t)
		if h == nil || (h.count(old) == 0 && h.inferred != old) {
			continue
		}
		f.retraceAt = c.now
		f.routeHist = append(f.routeHist, f.route)
		if len(f.routeHist) > 4 {
			f.routeHist = f.routeHist[1:]
		}
		f.route.End = c.now
		f.route = newRouteObs(f.nextRVer, c.now)
		f.nextRVer++
		f.route.Reason = ChangeRetrace
		f.retrace = true
		c.M.Retraced++
		c.startSweep(f, ClassDiscovery, 1)
	}
}
