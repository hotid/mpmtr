package core

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/hotid/mpmtr/internal/wire"
)

func monitored(ep *Endpoint) []*Flow {
	var out []*Flow
	for _, f := range ep.Flows {
		if f.Role.Monitored() {
			out = append(out, f)
		}
	}
	return out
}

// A: 15 flows without loss, one with 100% timeout → LOSS/PARTIAL, the
// failing flow is identified.
func TestOneDeadFlow(t *testing.T) {
	good := linear(5, 20*time.Millisecond)
	dead := linear(5, 20*time.Millisecond)
	dead.loss = 1
	var bad *Flow
	s := newSim(t, simpleCfg(), func(f *Flow, _ Mono) *simPath {
		if f == bad {
			return dead
		}
		return good
	})
	ep := s.add(256)
	bad = monitored(ep)[3]
	s.run(90 * time.Second)
	s.c.Flush()
	c := s.c
	c.evalEndpoint(ep)
	if ep.state != EPLoss || ep.scope != ScopePartial {
		t.Fatalf("endpoint %s/%s, want LOSS/PARTIAL", ep.state, ep.scope)
	}
	if bad.State() != FDown {
		t.Fatalf("bad flow %s", bad.State())
	}
	for _, f := range monitored(ep) {
		if f != bad && f.State() != FOK {
			t.Fatalf("flow %s state %s", f.Name(), f.State())
		}
	}
	if ep.agg.Down != 1 || ep.agg.OK != 15 {
		t.Fatalf("agg %+v", ep.agg)
	}
	// The single bad flow must be visible regardless of the low average.
	if ep.agg.WorstFlow != bad.Name() || ep.agg.WorstFailure < 0.99 {
		t.Fatalf("worst %s %.2f", ep.agg.WorstFlow, ep.agg.WorstFailure)
	}
	if s.count(EvPartialPathFailure) != 1 || s.count(EvEndpointLoss) != 0 {
		t.Fatalf("events: %v", evTypes(s.events))
	}
	if !contains(ep.loc.BadFlows, bad.Name()) {
		t.Fatalf("localization %+v", ep.loc)
	}
}

// B: zero valid probes → UNKNOWN, never 0% or 100%.
func TestNoValid(t *testing.T) {
	s := newSim(t, simpleCfg(), func(f *Flow, _ Mono) *simPath { return linear(3, 10*time.Millisecond) })
	s.sendErr = func(*Flow) bool { return true }
	ep := s.add(64)
	s.run(60 * time.Second)
	snap := s.c.Snapshot(SnapOpts{Only: AllEndpoints})
	e := snap.Endpoints[0]
	if e.State != EPUnknown {
		t.Fatalf("state %s", e.State)
	}
	if e.W5.FailureRate != nil || e.W5.TimeoutRate != nil {
		t.Fatal("rates must be unknown with zero valid samples")
	}
	for _, f := range snap.Endpoints[0].Flows {
		if f.State != FUnknown || f.W5.FailureRate != nil {
			t.Fatalf("flow %s state %s", f.Name, f.State)
		}
		if f.C.LocalErr == 0 || f.C.Timeout != 0 {
			t.Fatalf("local errors must not be timeouts: %+v", f.C)
		}
	}
	_ = ep
}

// C: five timeouts right after start → DOWN confirmed without waiting for 30.
func TestFastDown(t *testing.T) {
	p := linear(3, 10*time.Millisecond)
	p.loss = 1
	s := newSim(t, simpleCfg(), func(f *Flow, _ Mono) *simPath { return p })
	ep := s.add(64)
	s.run(6500 * time.Millisecond)
	for _, f := range monitored(ep) {
		if f.State() != FDown {
			t.Fatalf("flow %s %s after %d valid", f.Name(), f.State(), f.C.Valid())
		}
		if f.C.Valid() > 6 {
			t.Fatalf("too many samples %d", f.C.Valid())
		}
	}
	s.c.Flush()
	s.c.evalEndpoint(ep)
	if ep.state != EPDown || ep.scope != ScopeAll {
		t.Fatalf("endpoint %s/%s", ep.state, ep.scope)
	}
	if s.count(EvEndpointDown) != 1 || s.count(EvFlowDown) != 0 {
		t.Fatalf("events %v", evTypes(s.events))
	}
}

// D: 12 of 16 flows DOWN, 4 UNKNOWN → endpoint not DOWN.
func TestNoGlobalDownWithUnknown(t *testing.T) {
	p := linear(3, 10*time.Millisecond)
	p.loss = 1
	s := newSim(t, simpleCfg(), func(f *Flow, _ Mono) *simPath { return p })
	unknown := map[FlowID]bool{}
	s.sendErr = func(f *Flow) bool { return unknown[f.ID] }
	ep := s.add(64)
	for i, f := range monitored(ep) {
		if i < 4 {
			unknown[f.ID] = true
		}
	}
	s.run(20 * time.Second)
	s.c.evalEndpoint(ep)
	if ep.agg.Down != 12 || ep.agg.Unknown != 4 {
		t.Fatalf("agg %+v", ep.agg)
	}
	if ep.state == EPDown {
		t.Fatal("endpoint must not be DOWN with unknown flows")
	}
	if ep.state != EPLoss || ep.scope != ScopeUnknown {
		t.Fatalf("state %s/%s", ep.state, ep.scope)
	}
}

// E + O: recovery after DOWN; quality stays UNKNOWN until enough
// post-recovery data, and the DOWN period does not cause a LOSS.
func TestRecovery(t *testing.T) {
	p := linear(3, 10*time.Millisecond)
	p.loss = 1
	s := newSim(t, simpleCfg(), func(f *Flow, _ Mono) *simPath { return p })
	ep := s.add(64)
	s.run(60 * time.Second) // DOWN for a minute
	f := monitored(ep)[0]
	if f.State() != FDown {
		t.Fatal(f.State())
	}
	p.loss = 0
	s.run(6 * time.Second)
	if f.sm.avail != AvailUp {
		t.Fatalf("avail %s after %d positives", f.sm.avail, f.sm.consecPos)
	}
	if f.State() != FUnknown || f.sm.quality != QUnknown {
		t.Fatalf("quality must be UNKNOWN right after recovery, got %s", f.State())
	}
	snap := s.c.flowSnap(f, false)
	if !snap.Flags.Has(FlagQualityPending) {
		t.Fatalf("flags %v", snap.Flags)
	}
	s.run(60 * time.Second)
	if f.State() != FOK {
		t.Fatalf("after post-recovery warmup %s (reason %s)", f.State(), f.sm.reason)
	}
	s.c.Flush()
	if s.count(EvFlowLoss)+s.count(EvEndpointLoss)+s.count(EvPartialPathFailure) != 0 {
		t.Fatalf("false LOSS after recovery: %v", evTypes(s.events))
	}
	if s.count(EvEndpointRecovered) != 1 {
		t.Fatalf("events %v", evTypes(s.events))
	}
}

// F: all flows 10ms → all 100ms: absolute degradation via baseline.
func TestAbsoluteRTT(t *testing.T) {
	p := linear(3, 10*time.Millisecond)
	s := newSim(t, simpleCfg(), func(f *Flow, _ Mono) *simPath { return p })
	ep := s.add(64)
	s.run(4 * time.Minute)
	for _, f := range monitored(ep) {
		if !f.rtt.baseline.established {
			t.Fatalf("baseline not established for %s", f.Name())
		}
	}
	p.rtt = 100 * time.Millisecond
	s.run(45 * time.Second)
	for _, f := range monitored(ep) {
		if !f.sm.rttAbs {
			t.Fatalf("%s: absolute degradation not detected", f.Name())
		}
		if f.sm.rttRel {
			t.Fatalf("%s: must not be a relative outlier", f.Name())
		}
		if b := f.rtt.baseline.value(); b > 20000 {
			t.Fatalf("baseline drifted to %d us", b)
		}
	}
	s.c.Flush()
	if s.count(EvRTTDegradation) == 0 {
		t.Fatal("no RTT event")
	}
	// Persisting degradation must not become the new norm.
	s.run(10 * time.Minute)
	for _, f := range monitored(ep) {
		if !f.sm.rttAbs {
			t.Fatalf("%s: false recovery after prolonged degradation (baseline %d)", f.Name(), f.rtt.baseline.value())
		}
	}
	p.rtt = 10 * time.Millisecond
	s.run(60 * time.Second)
	for _, f := range monitored(ep) {
		if f.sm.rttAbs {
			t.Fatalf("%s: no RTT recovery", f.Name())
		}
	}
}

// G: one flow slower than the others → relative degradation.
func TestRelativeRTT(t *testing.T) {
	p := linear(3, 10*time.Millisecond)
	slow := linear(3, 60*time.Millisecond)
	var sf *Flow
	s := newSim(t, simpleCfg(), func(f *Flow, _ Mono) *simPath {
		if f == sf {
			return slow
		}
		return p
	})
	ep := s.add(64)
	sf = monitored(ep)[5]
	s.run(60 * time.Second)
	if !sf.sm.rttRel {
		t.Fatal("relative degradation not detected")
	}
	for _, f := range monitored(ep) {
		if f != sf && (f.sm.rttRel || f.sm.rttAbs) {
			t.Fatalf("%s falsely degraded", f.Name())
		}
	}
	s.c.evalHetero(ep, s.c.bucketNum(s.now)-1)
	if !contains(ep.hetero.RTTRelative, sf.Name()) {
		t.Fatal(ep.hetero)
	}
}

// J: capture drops do not create a false network DOWN.
func TestCaptureDrops(t *testing.T) {
	p := linear(3, 10*time.Millisecond)
	s := newSim(t, simpleCfg(), func(f *Flow, _ Mono) *simPath { return p })
	ep := s.add(64)
	s.run(40 * time.Second)
	// From now on every reply is "dropped" by the capture path and the
	// ring reports drops continuously.
	p.loss = 1
	s.dropsFn = func(Mono) uint64 { return 3 }
	s.run(30 * time.Second)
	for _, f := range monitored(ep) {
		if f.State() == FDown || f.State() == FLoss {
			t.Fatalf("%s %s with capture drops", f.Name(), f.State())
		}
		if f.C.Impaired == 0 {
			t.Fatal("timeouts during drops must be capture_impaired")
		}
	}
	s.c.Flush()
	if s.count(EvMonitoringImpaired) == 0 {
		t.Fatal("no MONITORING_IMPAIRED")
	}
	if s.count(EvEndpointDown)+s.count(EvFlowDown) != 0 {
		t.Fatal(evTypes(s.events))
	}
}

// K: an old SYN/ACK is not matched to a new probe; it is a late reply.
func TestLateSynAck(t *testing.T) {
	p := linear(3, 1500*time.Millisecond) // replies after the 1s deadline
	s := newSim(t, simpleCfg(), func(f *Flow, _ Mono) *simPath { return p })
	ep := s.add(64)
	s.run(20 * time.Second)
	for _, f := range monitored(ep) {
		if f.C.SynAck != 0 {
			t.Fatalf("late SYN/ACK credited to a newer probe: %+v", f.C)
		}
		if f.C.Late == 0 {
			t.Fatal("late replies not counted")
		}
	}
}

// L: two flows of one group degrade simultaneously → one main event.
func TestGroupEventDedup(t *testing.T) {
	a := linear(4, 10*time.Millisecond)
	b := linear(4, 10*time.Millisecond)
	b.hops[1].addr = a4("10.9.9.9")
	bad := map[FlowID]bool{}
	s := newSim(t, simpleCfg(), func(f *Flow, _ Mono) *simPath {
		var p simPath
		if f.SPort()%2 == 0 {
			p = *a
		} else {
			p = *b
		}
		if bad[f.ID] {
			p.loss = 1
		}
		return &p
	})
	cfg := simpleCfg()
	cfg.Discovery = true
	s.c.cfg.Discovery = true
	ep := s.add(64)
	s.run(3 * time.Minute)
	// Pick two monitored flows of the odd group.
	var odd []*Flow
	for _, f := range monitored(ep) {
		if f.SPort()%2 == 1 {
			odd = append(odd, f)
		}
	}
	if len(odd) < 3 || odd[0].group == nil || odd[0].level != LevelConfirmed {
		t.Fatalf("grouping not ready: %d odd flows, level %s", len(odd), odd[0].level)
	}
	before := len(s.events)
	bad[odd[0].ID], bad[odd[1].ID] = true, true
	s.run(15 * time.Second)
	s.c.Flush()
	var problem []Event
	for _, e := range s.events[before:] {
		switch e.Type {
		case EvFlowDown, EvGroupDown, EvGroupLoss, EvEndpointDown, EvEndpointLoss, EvPartialPathFailure:
			problem = append(problem, e)
		}
	}
	if len(problem) != 1 || len(problem[0].Flows) != 2 {
		t.Fatalf("want one main event listing 2 flows, got %v", problem)
	}
}

// M: E2E occupies the whole interval → hop probes are deferred, never
// collide with E2E and never become loss.
func TestHopDeferral(t *testing.T) {
	p := linear(4, 10*time.Millisecond)
	p.loss = 1 // every E2E waits the full 1s timeout = interval
	s := newSim(t, simpleCfg(), func(f *Flow, _ Mono) *simPath { return p })
	s.c.cfg.Discovery = true
	s.c.cfg.HopTimeout = 500 * time.Millisecond
	ep := s.add(16)
	s.run(60 * time.Second)
	if s.collision != 0 {
		t.Fatal("per-flow serialization violated")
	}
	if s.c.M.HopDeferWindow == 0 {
		t.Fatal("hop deferral not accounted")
	}
	for _, f := range monitored(ep) {
		for t2 := 1; t2 <= len(f.route.hops); t2++ {
			h := f.route.hopIf(TTL(t2))
			if h.Timeouts > 0 && h.Replies == 0 && h.Sent == h.Timeouts && f.route.distance == 0 && t2 < 5 {
				// hops 1..4 answer in this topology: a timeout here would be fabricated
				t.Fatalf("%s ttl %d: fabricated hop loss %+v", f.Name(), t2, h)
			}
		}
	}
	snap := s.c.Snapshot(SnapOpts{Hops: true, Only: AllEndpoints})
	for _, f := range snap.Endpoints[0].Flows {
		for _, h := range f.Hops {
			if h.TTL <= 4 && h.Loss != nil && *h.Loss > 0 && !h.Stale {
				t.Fatalf("hop %d reported 100%% loss instead of stale", h.TTL)
			}
		}
	}
}

// N: discovery stops and reports why.
func TestDiscoveryStop(t *testing.T) {
	t.Run("stability", func(t *testing.T) {
		p := linear(4, 5*time.Millisecond)
		s := newSim(t, simpleCfg(), func(f *Flow, _ Mono) *simPath { return p })
		s.c.cfg.Discovery = true
		s.c.cfg.ResponderPPS = 50
		ep := s.add(256)
		s.run(10 * time.Minute)
		if !ep.disc.stopped || ep.disc.reason != StopStability {
			t.Fatalf("reason %q stopped %v explored %d batches %d noNew %d", ep.disc.reason, ep.disc.stopped, ep.disc.explored, ep.disc.batches, ep.disc.noNew)
		}
		if ep.disc.explored < 32 || ep.disc.sinceNew < 32 || ep.disc.explored > 96 {
			t.Fatalf("%+v", ep.disc)
		}
	})
	t.Run("budget", func(t *testing.T) {
		s := newSim(t, simpleCfg(), func(f *Flow, _ Mono) *simPath {
			p := linear(3, 5*time.Millisecond)
			p.hops[1].addr = netip.AddrFrom4([4]byte{10, 1, byte(f.SPort()), 1}) // every port a new branch
			return p
		})
		s.c.cfg.Discovery = true
		s.c.cfg.ResponderPPS = 50
		ep := s.add(40)
		s.run(10 * time.Minute)
		if ep.disc.reason != StopBudget {
			t.Fatalf("reason %q", ep.disc.reason)
		}
	})
	t.Run("max_flows", func(t *testing.T) {
		s := newSim(t, simpleCfg(), func(f *Flow, _ Mono) *simPath {
			p := linear(3, 5*time.Millisecond)
			p.hops[1].addr = netip.AddrFrom4([4]byte{10, 1, byte(f.SPort()), 1})
			return p
		})
		s.c.cfg.Discovery = true
		s.c.cfg.ResponderPPS = 50
		s.c.cfg.MaxFlows = 48
		ep := s.add(256)
		s.run(10 * time.Minute)
		if ep.disc.reason != StopMaxFlows {
			t.Fatalf("reason %q candidates %d", ep.disc.reason, ep.disc.candidates)
		}
	})
	t.Run("deadline", func(t *testing.T) {
		p := linear(4, 5*time.Millisecond)
		s := newSim(t, simpleCfg(), func(f *Flow, _ Mono) *simPath { return p })
		s.c.cfg.Discovery = true
		s.c.cfg.ResponderPPS = 2 // slow enough to be cut by the deadline
		ep := s.add(256)
		s.run(5 * time.Second)
		s.c.StopDiscovery()
		if ep.disc.reason != StopDeadline {
			t.Fatalf("reason %q", ep.disc.reason)
		}
	})
	t.Run("insufficient", func(t *testing.T) {
		p := linear(4, 5*time.Millisecond)
		for i := range p.hops {
			p.hops[i].silent = true
		}
		p.noReply = true
		s := newSim(t, simpleCfg(), func(f *Flow, _ Mono) *simPath { return p })
		s.c.cfg.Discovery = true
		s.c.cfg.ResponderPPS = 100
		s.c.cfg.MaxTTL = 6
		ep := s.add(64)
		s.run(15 * time.Minute)
		if ep.disc.reason != StopInsufficientData {
			t.Fatalf("reason %q", ep.disc.reason)
		}
	})
}

// Discovery + grouping + localization over a 4-way ECMP with one bad arm.
func TestLocalizationSuspectedSegment(t *testing.T) {
	arms := make([]*simPath, 4)
	for i := range arms {
		arms[i] = &simPath{rtt: 10 * time.Millisecond, hops: []simHop{
			{addr: a4("10.0.0.1"), rtt: time.Millisecond},
			{addr: netip.AddrFrom4([4]byte{10, 1, byte(i), 1}), rtt: 3 * time.Millisecond},
			{addr: a4("10.3.0.1"), rtt: 6 * time.Millisecond},
		}}
	}
	arms[2].loss = 1
	armOf := func(sport wire.Port) int { return int((uint32(sport)*2654435761)>>7) % 4 }
	broken := false
	s := newSim(t, simpleCfg(), func(f *Flow, _ Mono) *simPath {
		a := armOf(f.SPort())
		if a == 2 && !broken {
			cp := *arms[2]
			cp.loss = 0
			return &cp
		}
		return arms[a]
	})
	s.c.cfg.Discovery = true
	s.c.cfg.ResponderPPS = 20
	ep := s.add(256)
	s.run(4 * time.Minute)
	if b := ep.branches(); b != 4 {
		t.Fatalf("branches %d groups %v", b, groupsDump(ep))
	}
	// every group represented by >= 2 monitored flows
	for _, g := range ep.groups {
		n := 0
		for _, f := range g.Members {
			if f.Role.Monitored() {
				n++
			}
		}
		if g.Level == LevelConfirmed && n < 2 {
			t.Fatalf("group %s has %d monitored representatives", g.ID, n)
		}
	}
	broken = true
	s.run(90 * time.Second)
	L := ep.loc
	if L.Level != LocSuspectedSegment {
		t.Fatalf("localization %+v", L)
	}
	want := []string{"10.0.0.1→10.1.2.1", "10.1.2.1→10.3.0.1"}
	for _, w := range want {
		if !contains(L.SuspectedSegments, w) {
			t.Fatalf("segments %v, want %v", L.SuspectedSegments, want)
		}
	}
	for _, seg := range L.SuspectedSegments {
		if strings.Contains(seg, "10.3.0.1→DST") || strings.HasPrefix(seg, "SRC") {
			t.Fatalf("shared segment blamed: %v", L.SuspectedSegments)
		}
	}
	snap := s.c.Snapshot(SnapOpts{Tree: true, Only: AllEndpoints})
	if len(snap.Endpoints[0].Tree) == 0 {
		t.Fatal("no tree")
	}
}

// With no healthy controls, localization must not name a segment.
func TestLocalizationNoControls(t *testing.T) {
	p := linear(3, 10*time.Millisecond)
	s := newSim(t, simpleCfg(), func(f *Flow, _ Mono) *simPath { return p })
	s.c.cfg.Discovery = true
	s.c.cfg.ResponderPPS = 20
	ep := s.add(64)
	s.run(2 * time.Minute)
	p.loss = 1
	s.run(20 * time.Second)
	if ep.loc.Level == LocSuspectedSegment || len(ep.loc.SuspectedSegments) > 0 {
		t.Fatalf("categorical localization without controls: %+v", ep.loc)
	}
}

// Route change: confirmed by two observations, recorded as a new route
// version, never as loss.
func TestRouteChange(t *testing.T) {
	p := linear(4, 10*time.Millisecond)
	s := newSim(t, simpleCfg(), func(f *Flow, _ Mono) *simPath { return p })
	s.c.cfg.Discovery = true
	s.c.cfg.ResponderPPS = 50
	ep := s.add(64)
	s.run(2 * time.Minute)
	f := monitored(ep)[0]
	ver := f.route.Ver
	p2 := *p
	p2.hops = append([]simHop(nil), p.hops...)
	p2.hops[1].addr = a4("10.77.0.1")
	*p = p2
	s.run(2 * time.Minute)
	s.c.Flush()
	if f.route.Ver == ver || len(f.routeHist) == 0 {
		t.Fatal("route version not changed")
	}
	if s.count(EvRouteChanged) == 0 {
		t.Fatal("no ROUTE_CHANGED")
	}
	if f.C.Timeout != 0 || f.State() == FLoss || f.State() == FDown {
		t.Fatal("route change interpreted as loss")
	}
	if old := f.routeHist[len(f.routeHist)-1]; old.E2EValid == 0 {
		t.Fatal("old route version lost its statistics")
	}
}

// A destination that never answers (a filtered port): every
// E2E probe runs into its timeout, which fills the whole interval. The
// measured flows' routes must still be refreshed — during an outage the
// trace is what localizes it — and a route change on them must be seen.
func TestDownFlowKeepsTracing(t *testing.T) {
	p := linear(6, 10*time.Millisecond)
	p.loss = 1
	s := newSim(t, simpleCfg(), func(f *Flow, _ Mono) *simPath { return p })
	s.c.cfg.Discovery = true
	s.c.cfg.ResponderPPS = 50
	ep := s.add(64)
	s.run(2 * time.Minute)
	mon := monitored(ep)
	if len(mon) == 0 {
		t.Fatal("no measured flows")
	}
	for _, f := range mon {
		if f.State() != FDown {
			t.Fatalf("%s %s, want DOWN", f.Name(), f.State())
		}
	}
	p2 := *p
	p2.hops = append([]simHop(nil), p.hops...)
	p2.hops[1].addr = a4("10.77.0.1")
	*p = p2
	s.run(90 * time.Second)
	s.c.Flush()
	if s.count(EvRouteChanged) == 0 {
		t.Fatal("route change on DOWN flows not seen")
	}
	for _, f := range monitored(ep) {
		for t2 := 1; t2 <= len(p.hops); t2++ {
			h := f.route.hopIf(TTL(t2))
			// 'stale' is 30 s; the refresh must stay well inside it.
			if h == nil || s.c.now-h.LastProbe > Mono(15*time.Second) {
				t.Errorf("%s hop %d not refreshed for 15 s: the route of a DOWN flow goes stale", f.Name(), t2)
			}
		}
		if f.State() != FDown {
			t.Errorf("%s %s, want DOWN", f.Name(), f.State())
		}
	}
}

// An upstream switch moves every port (the first-hop router moves all
// traffic to its other uplink). Ports that are only traced are
// never refreshed: their old traces must not keep the old route alive, and
// the traces must not be measured one by one as the "route" loses them.
func TestUpstreamSwitchRetraces(t *testing.T) {
	for _, tc := range []struct {
		name  string
		moved func(sport wire.Port) bool
	}{
		{"all ports", func(wire.Port) bool { return true }},
		{"half the ports (ECMP)", func(sp wire.Port) bool { return sp%2 == 0 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := linear(6, 10*time.Millisecond)
			p.loss = 1
			p2 := *p
			p2.hops = append([]simHop(nil), p.hops...)
			p2.hops[1].addr = a4("10.77.0.1")
			p2.hops[2].addr = a4("10.77.0.2")
			switched := false
			s := newSim(t, simpleCfg(), func(f *Flow, _ Mono) *simPath {
				if switched && tc.moved(f.SPort()) {
					return &p2
				}
				return p
			})
			s.c.cfg.Discovery = true
			s.c.cfg.ResponderPPS = 50
			s.c.cfg.Flows = 1
			ep := s.add(64)
			s.run(2 * time.Minute)
			if len(ep.groups) != 1 {
				t.Fatalf("%d routes before the switch, want 1", len(ep.groups))
			}
			switched = true
			s.run(90 * time.Second)
			if s.c.M.Retraced == 0 {
				t.Fatal("no port traced again after the route change")
			}
			want := 1
			if tc.moved(20001) != tc.moved(20000) {
				want = 2
			}
			if len(ep.groups) != want {
				for _, g := range ep.groups {
					t.Logf("%s %s %s", g.ID, g.Level, g.Sig.canon)
				}
				t.Fatalf("%d routes, want %d", len(ep.groups), want)
			}
			for _, g := range ep.groups {
				newPath := strings.Contains(g.Sig.canon, "10.77.0.1")
				for _, f := range append(append([]*Flow{}, g.Members...), g.Tentative...) {
					if tc.moved(f.SPort()) != newPath {
						t.Errorf("%s (sport %d) on route %s", f.Name(), f.SPort(), g.Sig.canon)
					}
				}
				if n := len(g.measured()); n != 1 {
					t.Errorf("route %s: %d measured ports, want 1", g.Sig.canon, n)
				}
			}
		})
	}
}

// Hop ICMP rate limiting: apparent loss on one hop that does not persist.
func TestICMPRateLimitFlag(t *testing.T) {
	p := linear(4, 10*time.Millisecond)
	p.hops[1].icmpLoss = 0.7
	s := newSim(t, simpleCfg(), func(f *Flow, _ Mono) *simPath { return p })
	s.c.cfg.Discovery = true
	s.c.cfg.ResponderPPS = 50
	ep := s.add(64)
	s.run(3 * time.Minute)
	f := monitored(ep)[0]
	if !possibleRateLimit(f.route, 2) {
		t.Fatalf("hop 2: %+v", f.route.hopIf(2))
	}
	if f.State() != FOK {
		t.Fatalf("E2E state %s", f.State())
	}
	if ep.loc.Level != LocNone {
		t.Fatalf("loc %+v", ep.loc)
	}
}

func evTypes(es []Event) []string {
	var out []string
	for _, e := range es {
		out = append(out, e.Type.String())
	}
	return out
}

func contains(s []string, x string) bool {
	for _, v := range s {
		if v == x {
			return true
		}
	}
	return false
}

func groupsDump(ep *Endpoint) string {
	var b strings.Builder
	for _, g := range ep.groups {
		fmt.Fprintf(&b, "%s %s n=%d sig=%s; ", g.ID, g.Level, len(g.Members), g.Sig.canon)
	}
	return b.String()
}

var _ = wire.SYN

// Random (independent) loss is not an outage: on paths that lose 10–30% of
// the probes runs of 5 failures happen many times a day; the DOWN threshold
// follows the flow's own background, so none of them is a FLOW_DOWN and the
// flows stay LOSS.
func TestRandomLossIsNotDown(t *testing.T) {
	for _, loss := range []float64{0.10, 0.18, 0.30} {
		p := linear(3, 10*time.Millisecond)
		p.loss = loss
		cfg := simpleCfg()
		cfg.Flows = 4
		s := newSim(t, cfg, func(f *Flow, _ Mono) *simPath { return p })
		ep := s.add(4)
		s.run(6 * time.Hour)
		s.c.Flush()
		// Up to one early false DOWN is tolerated: during the first 30
		// probes there is no background yet and the threshold is 5.
		if n := downEvents(s); n > 1 {
			t.Errorf("loss %.0f%%: %d FLOW_DOWN in 6 h of random loss", loss*100, n)
		}
		for _, f := range monitored(ep) {
			bp, bq := f.sm.bg.rates()
			t.Logf("loss %.0f%%: flow %s executed %d, background %.3f, fail-after-fail %.3f, DOWN threshold %d, max run %d",
				loss*100, f.Name(), f.Executed, bp, bq, s.c.downNeed(f), f.episode.max)
			if f.State() != FLoss {
				t.Errorf("loss %.0f%%: flow %s %s (%s)", loss*100, f.Name(), f.State(), f.sm.reason)
			}
			if need := s.c.downNeed(f); need <= s.c.cfg.DownAfter {
				t.Errorf("loss %.0f%%: DOWN threshold %d on a lossy flow", loss*100, need)
			}
		}
	}
}

// A real outage on a lossy flow is still DOWN, within the threshold, and
// the flow returns to LOSS after it.
func TestOutageOnLossyFlow(t *testing.T) {
	p := linear(3, 10*time.Millisecond)
	p.loss = 0.14
	cfg := simpleCfg()
	cfg.Flows = 2
	s := newSim(t, cfg, func(f *Flow, _ Mono) *simPath { return p })
	ep := s.add(2)
	s.run(10 * time.Minute)
	fs := monitored(ep)
	need := map[*Flow]int{}
	for _, f := range fs {
		need[f] = s.c.downNeed(f)
		if need[f] <= s.c.cfg.DownAfter || need[f] > 4*s.c.cfg.DownAfter {
			t.Fatalf("threshold %d at 14%% background", need[f])
		}
	}
	downs := downEvents(s)
	start := s.c.now
	p.loss = 1
	s.run(30 * time.Second)
	for _, f := range fs {
		if f.sm.avail != AvailDown {
			t.Fatalf("flow %s not DOWN after a 30 s outage (threshold %d)", f.Name(), need[f])
		}
		if d := f.sm.downSince - start; d <= 0 || d > Mono(time.Duration(need[f]+2)*time.Second) {
			t.Fatalf("flow %s DOWN %v after the outage began, threshold %d", f.Name(), time.Duration(d), need[f])
		}
	}
	p.loss = 0.14
	s.run(10 * time.Minute)
	s.c.Flush()
	if downEvents(s)-downs != 1 || s.count(EvFlowRecovered) < len(fs) {
		t.Fatalf("events %v", evTypes(s.events))
	}
	for _, f := range fs {
		if f.State() != FLoss {
			t.Fatalf("flow %s %s after the outage (%s)", f.Name(), f.State(), f.sm.reason)
		}
	}
}

// downEvents counts DOWN reports at every level (simultaneous flow DOWNs
// are aggregated into one group or endpoint event).
func downEvents(s *simNet) int {
	return s.count(EvFlowDown) + s.count(EvGroupDown) + s.count(EvEndpointDown)
}

// A port that becomes invalid in the middle of its discovery trace must not
// hold discovery open: the report would wait for it until the deadline.
func TestInvalidPortDoesNotBlockDiscovery(t *testing.T) {
	s := newSim(t, simpleCfg(), func(*Flow, Mono) *simPath { return linear(6, 10*time.Millisecond) })
	s.c.cfg.Discovery = true
	s.c.cfg.Flows = 1
	ep := s.add(16)
	var victims []*Flow
	for i := 0; i < 400 && len(victims) == 0; i++ {
		s.run(5 * time.Millisecond)
		for _, f := range ep.Flows {
			if f.sw != nil && f.sw.class == ClassDiscovery && !f.Role.Monitored() {
				victims = append(victims, f)
			}
		}
	}
	if len(victims) == 0 {
		t.Fatal("no port in a discovery trace")
	}
	victims = victims[:1]
	for _, f := range victims {
		s.c.invalidate(f, InvalidLocalNAT)
	}
	s.run(2 * time.Minute)
	if !s.c.DiscoveryDone() {
		t.Fatalf("discovery still open: %d ports in the batch, %d invalid", ep.disc.inBatch, len(victims))
	}
	for _, f := range victims {
		if f.sw != nil {
			t.Fatalf("%s still has a trace pending", f.Name())
		}
	}
}

// The verdicts need a number of probes, so the windows follow --interval: at
// 5 s and at 30 s per probe a lossy flow still becomes LOSS, the LOSS clears
// when the loss ends, and a slower path is still an RTT degradation.
func TestDetectorsAtSlowIntervals(t *testing.T) {
	for _, iv := range []time.Duration{5 * time.Second, 30 * time.Second} {
		p := linear(3, 10*time.Millisecond)
		cfg := simpleCfg()
		cfg.Interval, cfg.Flows = iv, 4
		s := newSim(t, cfg, func(f *Flow, _ Mono) *simPath { return p })
		ep := s.add(4)
		s.run(400 * iv)
		for _, f := range monitored(ep) {
			if f.State() != FOK || !f.rtt.baseline.established {
				t.Fatalf("interval %s: %s is %s (%s), baseline %v on a clean path", iv, f.Name(), f.State(), f.sm.reason, f.rtt.baseline.established)
			}
		}
		p.rtt = 100 * time.Millisecond
		s.run(60 * iv)
		for _, f := range monitored(ep) {
			if !f.sm.rttAbs {
				t.Errorf("interval %s: %s: RTT degradation not detected", iv, f.Name())
			}
		}
		p.rtt = 10 * time.Millisecond
		p.loss = 0.2
		s.run(300 * iv)
		for _, f := range monitored(ep) {
			if f.State() != FLoss {
				t.Errorf("interval %s: %s is %s (%s) at 20%% loss", iv, f.Name(), f.State(), f.sm.reason)
			}
		}
		p.loss = 0
		s.run(120 * iv)
		for _, f := range monitored(ep) {
			if f.State() != FOK {
				t.Errorf("interval %s: %s is %s (%s) after the loss ended", iv, f.Name(), f.State(), f.sm.reason)
			}
		}
	}
}

// A hop that keeps switching between two routers is flapping: after the
// third change in five minutes it is marked unstable instead of producing a
// route change (and a new route version) every time.
func TestFlappingHopIsUnstable(t *testing.T) {
	pa := linear(5, 10*time.Millisecond)
	pb := *pa
	pb.hops = append([]simHop(nil), pa.hops...)
	pb.hops[2].addr = a4("10.77.0.3")
	s := newSim(t, simpleCfg(), func(_ *Flow, now Mono) *simPath {
		if now > Mono(2*time.Minute) && (now/Mono(40*time.Second))%2 == 1 {
			return &pb
		}
		return pa
	})
	s.c.cfg.Discovery = true
	s.c.cfg.Flows = 2
	ep := s.add(16)
	s.run(12 * time.Minute)
	s.c.Flush()
	for _, f := range monitored(ep) {
		h := f.route.hopIf(3)
		if h == nil || !h.Unstable {
			t.Errorf("%s: hop 3 not marked unstable after %d route versions", f.Name(), len(f.routeHist)+1)
		}
		if f.nextRVer > 4 {
			t.Errorf("%s: %d route versions from one flapping hop", f.Name(), f.nextRVer)
		}
	}
}

// fanPath is an ECMP fan as seen in a data centre: 2 × 4 routers, then one
// router per pair in front of each of 4 next hops — 32 routes. A share of
// the probes sent with TTL 4 is answered by the address of TTL 5, for one
// and the same source port (a router that answers a probe and also forwards
// it).
func fanPath(sport wire.Port) *simPath {
	h := uint32(sport) * 2654435761
	a, b, c := int(h>>8)%2, int(h>>12)%4, int(h>>18)%4
	ad := func(x ...byte) netip.Addr { return netip.AddrFrom4([4]byte(x)) }
	return &simPath{rtt: 500 * time.Microsecond, hops: []simHop{
		{addr: ad(10, 0, 1, 1), rtt: 100 * time.Microsecond},
		{addr: ad(10, 0, 2, byte(1+a)), rtt: 200 * time.Microsecond},
		{addr: ad(10, 0, 3, byte(1+b+4*a)), rtt: 300 * time.Microsecond},
		{addr: ad(10, 0, byte(4+a), byte(1+4*b+c)), rtt: 350 * time.Microsecond},
		{addr: ad(10, 0, 9, byte(1+c)), rtt: 400 * time.Microsecond},
	}}
}

// A router that answers an expiring probe and lets it go on as well: one
// probe sent with TTL 3 is answered by the routers of TTL 3, 4 and 5, in any
// order. A router answers only probes sent with a TTL up to its position, so
// the largest TTL it answered is its place: every route keeps its own router
// at TTL 3 and 4, whoever answers first and whichever answers are lost.
func TestRouterPlaceIsLargestTTLAnswered(t *testing.T) {
	for _, tc := range []struct {
		name   string
		d3, d4 time.Duration
		loss   float64
	}{
		{"far first", 300 * time.Microsecond, 300 * time.Microsecond, 0},
		{"near first", time.Microsecond, time.Microsecond, 0},
		{"middle last", time.Microsecond, 300 * time.Microsecond, 0},
		{"answers lost 30%", 300 * time.Microsecond, 300 * time.Microsecond, 0.3},
		{"answers lost 60%", 300 * time.Microsecond, 300 * time.Microsecond, 0.6},
	} {
		cfg := simpleCfg()
		cfg.Flows, cfg.Discovery = 1, true
		s := newSim(t, cfg, func(f *Flow, _ Mono) *simPath {
			p := fanPath(f.SPort())
			p.hops[2].both, p.hops[3].both = tc.d3, tc.d4
			p.hops[2].icmpLoss, p.hops[3].icmpLoss, p.hops[4].icmpLoss = tc.loss, tc.loss, tc.loss
			return p
		})
		ep := s.add(256)
		s.run(5 * time.Minute)
		if s.c.M.MultiAnswer == 0 {
			t.Fatalf("%s: no probe seen answered by two routers", tc.name)
		}
		// No port places a router at a TTL where it is not, whatever was
		// lost; a hop may stay unknown.
		measured := 0
		for _, f := range ep.Flows {
			want := fanPath(f.SPort())
			for i, e := range f.sig.hops {
				if e.kind == eKnown && e.addr != want.hops[i].addr {
					t.Errorf("%s: %s places %s at TTL %d, the router there is %s", tc.name, f.Name(), e.addr, i+1, want.hops[i].addr)
				}
			}
			if !f.Role.Monitored() {
				continue
			}
			measured++
			for _, h := range s.c.flowHops(f) {
				if h.TTL <= 5 && h.Responder.IsValid() && h.Responder != want.hops[h.TTL-1].addr {
					t.Errorf("%s: %s TTL %d: shown %q (%s), the router there is %s", tc.name, f.Name(), h.TTL, h.Responder, h.Kind, want.hops[h.TTL-1].addr)
				}
				if h.TTL <= 5 && !h.Responder.IsValid() && tc.loss == 0 {
					t.Errorf("%s: %s TTL %d: no router shown (%s)", tc.name, f.Name(), h.TTL, h.Kind)
				}
				if h.Unstable {
					t.Errorf("%s: %s TTL %d shown as unstable", tc.name, f.Name(), h.TTL)
				}
			}
		}
		if ds := ep.discoveryStatus(true); !ds.Stopped {
			t.Errorf("%s: discovery not finished after %d ports, %d still in progress", tc.name, ds.Ports, ds.InProgress)
		}
		for _, g := range ep.groups {
			if n := len(g.measured()); n > 1 {
				t.Errorf("%s: route %s has %d measured ports", tc.name, g.Sig.canon, n)
			}
		}
		if tc.loss <= 0.3 && (len(ep.groups) != 32 || measured != 32) {
			t.Errorf("%s: %d routes, %d measured ports, want 32 and 32", tc.name, len(ep.groups), measured)
		}
		if len(ep.groups) > 32+2 {
			t.Errorf("%s: %d routes on a network that has 32", tc.name, len(ep.groups))
		}
		if n := s.count(EvRouteChanged); n != 0 {
			t.Errorf("%s: %d route changes on a network that did not change", tc.name, n)
		}
	}
}

// Focus: the port in focus has all its TTLs probed every interval instead
// of one TTL per interval, the hop refresh of the other ports waits, their
// TCP measurements go on, and everything returns when the focus is taken off.
func TestFocus(t *testing.T) {
	cfg := simpleCfg()
	cfg.Flows, cfg.Discovery = 1, true
	s := newSim(t, cfg, func(f *Flow, _ Mono) *simPath { return fanPath(f.SPort()) })
	ep := s.add(64)
	s.run(2 * time.Minute)
	var mon []*Flow
	for _, f := range ep.Flows {
		if f.Role.Monitored() {
			mon = append(mon, f)
		}
	}
	if len(mon) < 4 {
		t.Fatalf("%d measured ports", len(mon))
	}
	hopSent := func(f *Flow) (n uint32) {
		for i := 0; TTL(i+1) < f.route.distance; i++ {
			n += f.route.hops[i].Sent
		}
		return n
	}
	e2e := func(f *Flow) uint64 { return f.C.SynAck + f.C.Rst }
	const secs = 60
	iv := float64(cfg.Interval) / float64(time.Second)
	hops := uint32(mon[0].route.distance - 1)

	// before: about one hop probe per interval on every measured port
	b0, o0 := hopSent(mon[0]), hopSent(mon[1])
	s.run(secs * time.Second)
	base := hopSent(mon[0]) - b0
	if float64(base) > 1.3*secs/iv || hopSent(mon[1]) == o0 {
		t.Fatalf("without focus: %d hop probes on the port in %ds, other port %d", base, secs, hopSent(mon[1])-o0)
	}

	if !s.c.SetFocus(0, mon[0].SPort()) {
		t.Fatal("focus refused")
	}
	b0, o0 = hopSent(mon[0]), hopSent(mon[1])
	x0, y0 := e2e(mon[0]), e2e(mon[1])
	s.run(secs * time.Second)
	got := hopSent(mon[0]) - b0
	if want := float64(hops) * secs / iv; float64(got) < 0.8*want {
		t.Errorf("in focus: %d hop probes in %ds, want about %.0f (%d routers every interval); it was %d without focus", got, secs, want, hops, base)
	}
	if d := hopSent(mon[1]) - o0; d != 0 {
		t.Errorf("another port still refreshed its hops in focus mode: %d probes", d)
	}
	for i, d := range []uint64{e2e(mon[0]) - x0, e2e(mon[1]) - y0} {
		if float64(d) < 0.9*secs/iv {
			t.Errorf("port %d: %d TCP measurements in %ds while a port is in focus", i, d, secs)
		}
	}
	if snap := s.c.Snapshot(SnapOpts{Only: AllEndpoints}); len(snap.Endpoints) > 0 {
		n := 0
		for _, f := range snap.Endpoints[0].Flows {
			if f.Focus {
				n++
				if f.SPort != mon[0].SPort() {
					t.Errorf("focus shown on sport %d", f.SPort)
				}
			}
		}
		if n != 1 {
			t.Errorf("%d flows shown in focus", n)
		}
	}

	s.c.SetFocus(0, 0)
	b0, o0 = hopSent(mon[0]), hopSent(mon[1])
	s.run(secs * time.Second)
	if d := hopSent(mon[0]) - b0; float64(d) > 1.3*secs/iv {
		t.Errorf("after focus: still %d hop probes in %ds", d, secs)
	}
	if hopSent(mon[1]) == o0 {
		t.Error("after focus: the other port's hops are not refreshed again")
	}
	if n := s.count(EvRouteChanged); n != 0 {
		t.Errorf("%d route changes", n)
	}
}
