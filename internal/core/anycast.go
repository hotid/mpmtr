package core

import (
	"cmp"
	"math"
	"slices"
	"sort"
	"time"

	"github.com/hotid/mpmtr/internal/wire"
)

// Anycast mode: several servers answer one destination address; a load
// balancer picks the server by hashing the 4-tuple, so a source port keeps
// reaching the same server. Servers are told apart by their TCP timestamp
// clocks: TSval − t·Hz (mod 2^32) is constant per server (Linux keeps one
// offset per address pair on such fleets). A census sends one SYN from
// every port of the range, clusters the clock offsets into servers, maps
// each port to its server, and stops when new ports keep landing on known
// servers. Every server then gets --flows measured ports.
//
// Clustering rules: rates 1000/250/100 Hz, tolerance 50 ms plus half a
// SYN-cookie quantum (64 ticks), a server needs >= 3 answers from >= 2
// ports spread in time. Where the server's kernel randomizes the offset per
// connection (Linux with tcp_timestamps=1 that mixes the ports into the
// offset) every port looks like its own clock: then the servers cannot be
// told apart and the mode says so.
// tcp_timestamps=2 on the servers removes the offset: one clock per machine.

const (
	acQuant      = 64 // SYN-cookie TSval keeps the upper bits only
	acTolMs      = 50
	acMinAnswers = 3
	acMinPorts   = 2
	acInFlight   = 64 // census SYNs in flight per endpoint
)

// ClockRate is the tick rate of a server's TCP timestamp clock, in ticks per
// second. A server has one of the rates the census tries; two servers have
// the same rate when the values are equal, and they are only ever these.
type ClockRate float64

const (
	Rate1000 ClockRate = 1000
	Rate250  ClockRate = 250
	Rate100  ClockRate = 100
)

var acRates = []ClockRate{Rate1000, Rate250, Rate100}

// AnycastStatus of an endpoint's census.
type AnycastStatus string

const (
	ACRunning        AnycastStatus = "running"
	ACDone           AnycastStatus = "done"
	ACUnidentifiable AnycastStatus = "unidentifiable" // per-connection clocks
	ACNoTimestamps   AnycastStatus = "no_timestamps"  // replies carry no TCP timestamp
)

type acAnswer struct {
	port  wire.Port
	tsval uint32
	rt    Wall // kernel receive time
}

// Server is one machine behind the anycast address.
type Server struct {
	ID     int
	Hz     ClockRate
	Offset uint32
	ports  []wire.Port // ports the census saw reaching it
	seen   Mono
	// confirmed: a measured port's E2E answers came on this clock — the
	// server is real, not a census artefact.
	confirmed bool
}

// Name is "S<n>".
func (s *Server) Name() string { return "S" + acItoa(s.ID) }

type anycastState struct {
	status      AnycastStatus
	cursor      int // next index into ep.ports
	explored    int // census answers + timeouts
	noTS        int
	inflight    int
	stuck       int // census SYNs the watchdog gave up on
	answers     []acAnswer
	sinceNew    int
	lastCount   int
	unclustered int
	servers     []*Server
	nextID      int
	portSrv     map[wire.Port]*Server
	moved       int         // measured-port answers that came from another server's clock
	unknownClk  int         // measured-port answers matching no known server's clock
	accepted    int         // answers on a server's clock at the last clustering
	phantoms    int         // census servers dropped: never confirmed, and every port measured for them answered on another clock
	again       []wire.Port // ports to ask once more (their answer fitted no server yet)
	passes      int         // extra passes done over unassigned ports
}

func acItoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [20]byte
	n := len(b)
	for i > 0 {
		n--
		b[n] = byte('0' + i%10)
		i /= 10
	}
	return string(b[n:])
}

func (c *Core) startCensus(ep *Endpoint) {
	ep.ac = &anycastState{status: ACRunning, portSrv: map[wire.Port]*Server{}, nextID: 1}
	c.censusFill(ep)
}

// censusFill keeps acInFlight census SYNs going over the ports in order.
func (c *Core) censusFill(ep *Endpoint) {
	a := ep.ac
	for a.status == ACRunning && a.inflight < acInFlight && len(a.again) > 0 {
		f := ep.byPort[a.again[0]]
		a.again = a.again[1:]
		if f == nil || f.Role.Monitored() || f.census {
			continue
		}
		f.census, f.censusAt = true, c.now
		a.inflight++
		c.enqueue(f)
	}
	for a.status == ACRunning && a.inflight < acInFlight && a.cursor < len(ep.ports) && a.passes == 0 {
		f, err := c.newFlow(ep, ep.ports[a.cursor])
		a.cursor++
		if err != nil {
			continue
		}
		if f.Role.Monitored() {
			continue // its E2E probes answer the same question
		}
		f.census, f.censusAt = true, c.now
		a.inflight++
		c.enqueue(f)
	}
	if a.status == ACRunning && a.inflight == 0 && len(a.again) == 0 && (a.cursor >= len(ep.ports) || a.passes > 0) {
		if !c.censusAgain(ep) {
			c.censusEnd(ep)
		}
	}
}

// acStuck: a census SYN not sent and answered within this long is given
// up (the port's other work kept it busy); its port stays unasked.
const acStuck = Mono(10 * time.Second)

// censusWatchdog keeps the census moving when a due census SYN never got
// its turn, so the census always ends.
func (c *Core) censusWatchdog(ep *Endpoint) {
	a := ep.ac
	if a == nil || a.status != ACRunning || a.inflight == 0 {
		return
	}
	gave := false
	for _, f := range ep.Flows {
		if f.census && c.now-f.censusAt > acStuck && (f.active == nil || f.active.class != ClassCensus) {
			f.census = false
			a.inflight--
			a.stuck++
			gave = true
		}
	}
	if gave {
		c.censusFill(ep)
	}
}

// censusAgain: before ending, ask the ports whose answer fitted no server
// twice more (servers the balancer gives few ports to need >= 3 answers
// spread in time). Returns false when there is nothing left to ask.
func (c *Core) censusAgain(ep *Endpoint) bool {
	a := ep.ac
	if a.passes >= 2 {
		return false
	}
	c.acCluster(ep)
	seen := map[wire.Port]bool{}
	for _, x := range a.answers {
		if a.portSrv[x.port] == nil && !seen[x.port] {
			seen[x.port] = true
			a.again = append(a.again, x.port)
		}
	}
	a.passes++
	if len(a.again) == 0 {
		return false
	}
	c.censusFill(ep)
	return true
}

func (c *Core) recordCensus(p *Probe) {
	f := p.flow
	ep := f.EP
	due := f.census
	f.census = false
	a := ep.ac
	if a == nil || !due {
		return // the watchdog already gave up on it
	}
	a.inflight--
	if a.status != ACRunning {
		return
	}
	a.explored++
	a.sinceNew++
	switch {
	case p.outcome == OutDestReached && p.hasTS:
		c.acAdd(ep, f.SPort(), p.tsval, p.rxRT)
	case p.outcome == OutDestReached:
		a.noTS++
	}
	if a.unclustered >= 32 || a.inflight == 0 {
		c.acCluster(ep)
		c.acCheckStop(ep)
	}
	c.censusFill(ep)
}

// acObserve takes the server clock of a measured port's E2E answer: it
// feeds the clustering and checks that the port still reaches its server.
func (c *Core) acObserve(p *Probe) {
	f := p.flow
	ep := f.EP
	if ep.ac == nil {
		return
	}
	if s := ep.ac.portSrv[f.SPort()]; s != nil && ep.ac.status == ACDone {
		if acMatch(s, p.tsval, p.rxRT) {
			s.seen, s.confirmed = c.now, true
			f.acOther, f.acStreak = nil, 0
		} else {
			var other *Server
			for _, o := range ep.ac.servers {
				if o != s && acMatch(o, p.tsval, p.rxRT) {
					other = o
					break
				}
			}
			if other != nil {
				ep.ac.moved++
				f.acMoved++
				if f.acOther == other {
					f.acStreak++
				} else {
					f.acOther, f.acStreak = other, 1
				}
				if f.acStreak >= 3 {
					c.acMovePort(ep, f, s, other)
				}
			} else {
				ep.ac.unknownClk++
				f.acUnknown++
				f.acOther, f.acStreak = nil, 0
			}
		}
	}
	if s := ep.ac.portSrv[f.SPort()]; s == nil && ep.ac.status == ACDone {
		// A measured port the census never placed (it was measured from
		// the start, or answered too seldom): it joins the known server
		// whose clock it keeps answering on.
		var other *Server
		for _, o := range ep.ac.servers {
			if acMatch(o, p.tsval, p.rxRT) {
				other = o
				break
			}
		}
		switch {
		case other == nil:
			f.acOther, f.acStreak = nil, 0
		case f.acOther == other:
			f.acStreak++
		default:
			f.acOther, f.acStreak = other, 1
		}
		if other != nil && f.acStreak >= 3 {
			ep.ac.portSrv[f.SPort()] = other
			if !slices.Contains(other.ports, f.SPort()) {
				other.ports = append(other.ports, f.SPort())
				slices.Sort(other.ports)
			}
			other.seen, other.confirmed = c.now, true
			f.acOther, f.acStreak = nil, 0
		}
	}
	if ep.ac.status == ACRunning {
		c.acAdd(ep, f.SPort(), p.tsval, p.rxRT)
	}
}

// routeNeeds: f is one of the --flows measured ports of its route (the
// lowest-numbered ones), so the route would lose its measurement without it.
func (c *Core) routeNeeds(f *Flow) bool {
	g := f.group
	if g == nil {
		return false
	}
	cands := append(append([]*Flow(nil), g.Members...), g.Tentative...)
	slices.SortFunc(cands, func(a, b *Flow) int { return cmp.Compare(a.ID, b.ID) })
	k := 0
	for _, x := range cands {
		if !x.Role.Monitored() {
			continue
		}
		if x == f {
			return k < c.cfg.Flows
		}
		k++
	}
	return false
}

func (c *Core) acAdd(ep *Endpoint, port wire.Port, tsval uint32, rt Wall) {
	a := ep.ac
	if len(a.answers) >= 20000 {
		return
	}
	a.answers = append(a.answers, acAnswer{port: port, tsval: tsval, rt: rt})
	a.unclustered++
}

func acTolTicks(hz ClockRate) uint32 { return uint32(math.Round(acTolMs*float64(hz)/1000)) + acQuant/2 }

func acOffset(tsval uint32, rt Wall, hz ClockRate) uint32 {
	ticks := int64(math.Floor(float64(rt) * float64(hz) / 1e9))
	return tsval + acQuant/2 - uint32(ticks)
}

func acMatch(s *Server, tsval uint32, rt Wall) bool {
	d := int64(int32(acOffset(tsval, rt, s.Hz) - s.Offset))
	return d >= -int64(2*acTolTicks(s.Hz)) && d <= int64(2*acTolTicks(s.Hz))
}

// acMinSpan: answers close in time fit a clock of any rate; a new clock is
// believed only when its answers are spread enough for the nearest other
// rate to drift out of the tolerance twice over.
func acMinSpan(hz ClockRate) time.Duration {
	nearest := math.Inf(1)
	for _, r := range acRates {
		if r != hz {
			nearest = min(nearest, math.Abs(float64(r-hz)))
		}
	}
	return time.Duration(2 * float64(acTolTicks(hz)) / nearest * float64(time.Second))
}

type acGroup struct {
	hz      ClockRate
	members []int
	offsets []uint32
}

// acValid: a cluster that can be one server's clock — narrow (all offsets
// within the tolerance of the centre; single linkage over a dense census
// otherwise chains the drifting offsets of other-rate clocks into one long
// "cluster"), seen from >= 2 ports, spread in time (acMinSpan).
func acValid(ans []acAnswer, g acGroup) bool {
	if len(g.members) < acMinAnswers {
		return false
	}
	c := acCenter(g.offsets)
	tol := int64(acTolTicks(g.hz))
	ports := map[wire.Port]bool{}
	lo, hi := Wall(math.MaxInt64), Wall(math.MinInt64)
	for k, m := range g.members {
		if d := int64(int32(g.offsets[k] - c)); d > tol || d < -tol {
			return false
		}
		ports[ans[m].port] = true
		lo, hi = min(lo, ans[m].rt), max(hi, ans[m].rt)
	}
	return len(ports) >= acMinPorts && hi.Sub(lo) >= acMinSpan(g.hz)
}

// acClusterTS clusters greedily (one largest cluster over
// all candidate rates per step), accepting only clusters that can be a
// server (acValid) so that rejected ones do not take points from real ones.
func acClusterTS(ans []acAnswer) []acGroup {
	remaining := make([]int, len(ans))
	for i := range remaining {
		remaining[i] = i
	}
	clusterAt := func(idx []int, hz ClockRate) []acGroup {
		offs := make([]uint32, len(idx))
		for k, i := range idx {
			offs[k] = acOffset(ans[i].tsval, ans[i].rt, hz)
		}
		tol := acTolTicks(hz)
		order := make([]int, len(idx))
		for i := range order {
			order[i] = i
		}
		sort.Slice(order, func(a, b int) bool { return offs[order[a]] < offs[order[b]] })
		var gs []acGroup
		cur := acGroup{hz: hz}
		flush := func() {
			if len(cur.members) > 0 {
				gs = append(gs, cur)
			}
			cur = acGroup{hz: hz}
		}
		for k, o := range order {
			if k > 0 && offs[o]-offs[order[k-1]] > tol {
				flush()
			}
			cur.members = append(cur.members, idx[o])
			cur.offsets = append(cur.offsets, offs[o])
		}
		flush()
		// wrap-around on the 2^32 circle
		if len(gs) > 1 {
			f, l := gs[0], gs[len(gs)-1]
			if f.offsets[0]-l.offsets[len(l.offsets)-1] <= tol {
				gs[0] = acGroup{hz: hz, members: append(append([]int{}, l.members...), f.members...),
					offsets: append(append([]uint32{}, l.offsets...), f.offsets...)}
				gs = gs[:len(gs)-1]
			}
		}
		return gs
	}
	var out []acGroup
	for len(remaining) > 0 {
		var best acGroup
		for _, hz := range acRates {
			for _, g := range clusterAt(remaining, hz) {
				if len(g.members) > len(best.members) && acValid(ans, g) {
					best = g
				}
			}
		}
		if len(best.members) == 0 {
			break
		}
		out = append(out, best)
		used := map[int]bool{}
		for _, m := range best.members {
			used[m] = true
		}
		rest := remaining[:0:0]
		for _, i := range remaining {
			if !used[i] {
				rest = append(rest, i)
			}
		}
		remaining = rest
	}
	return out
}

func acCenter(offs []uint32) uint32 {
	ref := offs[0]
	d := make([]int64, len(offs))
	for i, v := range offs {
		d[i] = int64(int32(v - ref))
	}
	slices.Sort(d)
	return ref + uint32(d[len(d)/2])
}

// acCluster recomputes the servers from all answers. Server numbers are
// kept by clock: a cluster matching a known server's clock keeps its
// number; a clock nobody had gets the next number.
func (c *Core) acCluster(ep *Endpoint) {
	a := ep.ac
	a.unclustered = 0
	if len(a.answers) == 0 {
		return
	}
	accepted := 0
	portVotes := map[wire.Port]map[*Server]int{}
	var servers []*Server
	for _, g := range acClusterTS(a.answers) {
		ports := map[wire.Port]bool{}
		for _, m := range g.members {
			ports[a.answers[m].port] = true
		}
		center := acCenter(g.offsets)
		var s *Server
		for _, old := range a.servers {
			d := int64(int32(center - old.Offset))
			if old.Hz == g.hz && d >= -int64(2*acTolTicks(g.hz)) && d <= int64(2*acTolTicks(g.hz)) && !slices.Contains(servers, old) {
				s = old
				break
			}
		}
		if s == nil {
			s = &Server{ID: a.nextID}
			a.nextID++
		}
		s.Hz, s.Offset, s.ports = g.hz, center, s.ports[:0]
		for p := range ports {
			s.ports = append(s.ports, p)
		}
		slices.Sort(s.ports)
		servers = append(servers, s)
		accepted += len(g.members)
		for _, m := range g.members {
			p := a.answers[m].port
			if portVotes[p] == nil {
				portVotes[p] = map[*Server]int{}
			}
			portVotes[p][s]++
		}
	}
	slices.SortFunc(servers, func(x, y *Server) int { return cmp.Compare(x.ID, y.ID) })
	a.servers = servers
	a.accepted = accepted
	clear(a.portSrv)
	for p, votes := range portVotes {
		var best *Server
		for s, n := range votes {
			if best == nil || n > votes[best] || n == votes[best] && s.ID < best.ID {
				best = s
			}
		}
		a.portSrv[p] = best
	}
	if len(a.servers) > a.lastCount {
		a.lastCount, a.sinceNew = len(a.servers), 0
	}
	// Per-connection clocks: plenty of answers (several per server even
	// for ~50 servers), yet few of them on a clock shared by several ports.
	if len(a.answers) >= 256 && accepted*10 < len(a.answers)*3 {
		a.status = ACUnidentifiable
		a.servers = nil
		clear(a.portSrv)
	}
}

func (c *Core) acCheckStop(ep *Endpoint) {
	a := ep.ac
	if a.status != ACRunning {
		return
	}
	if a.noTS >= 32 && len(a.answers) == 0 {
		a.status = ACNoTimestamps
		return
	}
	// Stop early only when new ports stopped bringing new servers AND every
	// answer so far is on a named server's clock. An answer on a clock
	// nobody has is most likely a server the balancer gives few ports to,
	// not yet seen often enough to be named: then the whole range is asked.
	quiet := max(64, 8*len(a.servers))
	if a.passes == 0 && a.explored >= 128 && a.sinceNew >= quiet && a.accepted == len(a.answers) {
		if a.accepted*10 < len(a.answers)*3 {
			// Nothing converged on shared clocks: per-connection clocks.
			a.status, a.servers = ACUnidentifiable, nil
			clear(a.portSrv)
			return
		}
		a.cursor = len(ep.ports) // no new ports; the extra passes follow
	}
}

// AnycastAnswers returns the census answers (port, TSval, receive time) of
// endpoint i — diagnostics.
func (c *Core) AnycastAnswers(i EndpointID) [][3]int64 {
	var out [][3]int64
	if i >= 0 && i < EndpointID(len(c.eps)) && c.eps[i].ac != nil {
		for _, x := range c.eps[i].ac.answers {
			out = append(out, [3]int64{int64(x.port), int64(x.tsval), int64(x.rt)})
		}
	}
	return out
}

func (c *Core) censusEnd(ep *Endpoint) {
	a := ep.ac
	c.acCluster(ep)
	if a.status == ACRunning {
		a.status = ACDone
	}
	for _, f := range ep.Flows {
		f.census = false
	}
	a.inflight = 0
	c.acAssign(ep)
}

// acAssign gives every server --flows measured ports (lowest ports first);
// a measured port is never swapped out.
func (c *Core) acAssign(ep *Endpoint) {
	a := ep.ac
	if a == nil || c.cfg.DiscoverOnly || (a.status != ACRunning && a.status != ACDone) {
		return
	}
	have := map[*Server]int{}
	for _, f := range ep.Flows {
		if f.Role.Monitored() {
			if s := a.portSrv[f.SPort()]; s != nil {
				have[s]++
			}
		}
	}
	for _, s := range a.servers {
		for _, p := range s.ports {
			if have[s] >= c.cfg.Flows {
				break
			}
			f := ep.byPort[p]
			if f == nil || f.Role != RoleCandidate || f.invalid != ValidFlow || a.portSrv[p] != s {
				continue
			}
			c.activate(f, RoleActive)
			have[s]++
		}
	}
}

// acMovePort: a measured port keeps answering on another known server's
// clock — it reaches that server (the census put it on a wrong or phantom
// clock, or the balancer moved it). The port follows its server, and the
// server it leaves gets the next of its ports measured. One port that was
// not its own says nothing about the others, so the server stays while a
// port of it is left to measure. A server that no answer ever confirmed and
// that has no such port left is dropped: a clock the census made up out of
// other servers' answers, or a server that left the pool before it was
// measured (the two look the same from here). Silence alone never drops a
// server. A duplicate measured port of the new server stops, unless its
// route needs it.
func (c *Core) acMovePort(ep *Endpoint, f *Flow, from, to *Server) {
	a := ep.ac
	port := f.SPort()
	a.portSrv[port] = to
	from.ports = slices.DeleteFunc(from.ports, func(p wire.Port) bool { return p == port })
	if !slices.Contains(to.ports, port) {
		to.ports = append(to.ports, port)
		slices.Sort(to.ports)
	}
	f.acOther, f.acStreak = nil, 0
	n := 0
	for _, g := range c.measuredOf(ep, to) {
		if g != f {
			n++
		}
	}
	if n >= c.cfg.Flows && !c.routeNeeds(f) {
		c.deactivate(f)
		ep.stopped = append(ep.stopped, StoppedFlow{Flow: f.Name(), SPort: port, Server: to.Name(), At: c.nowRT})
	}
	c.acAssign(ep)
	if !from.confirmed && len(c.measuredOf(ep, from)) == 0 {
		a.servers = slices.DeleteFunc(a.servers, func(s *Server) bool { return s == from })
		for p, s := range a.portSrv {
			if s == from {
				delete(a.portSrv, p)
			}
		}
		a.phantoms++
	}
}

// acRepresents: f is one of the --flows measured ports of its server (anycast),
// so it stays measured even when its route has enough measured ports.
func (c *Core) acRepresents(f *Flow) bool {
	a := f.EP.ac
	if a == nil {
		return false
	}
	s := a.portSrv[f.SPort()]
	if s == nil {
		return false
	}
	k := 0
	for _, p := range s.ports {
		g := f.EP.byPort[p]
		if g == nil || !g.Role.Monitored() || a.portSrv[p] != s {
			continue
		}
		if g == f {
			return k < c.cfg.Flows
		}
		k++
	}
	return false
}

// ServerOf returns the server a port reaches (nil if not known).
func (ep *Endpoint) ServerOf(port wire.Port) *Server {
	if ep.ac == nil {
		return nil
	}
	return ep.ac.portSrv[port]
}
