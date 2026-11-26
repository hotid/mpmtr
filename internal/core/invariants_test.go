package core

import (
	"math/rand/v2"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/hotid/mpmtr/internal/wire"
)

// --- grouping unit tests ---

func obsFlow(c *Core, ep *Endpoint, hops []string, dist int) *Flow {
	f, err := c.newFlow(ep, wire.Port(30000+len(ep.Flows)))
	if err != nil {
		panic(err)
	}
	r := f.route
	for i, h := range hops {
		hs := r.hop(TTL(i + 1))
		switch h {
		case "*":
			hs.Sent, hs.Timeouts = 3, 3
		case "?":
			hs.Sent, hs.Timeouts = 1, 1
		default:
			a := netip.MustParseAddr(h)
			hs.cur = a
			hs.resp[0] = respCount{addr: a, n: 2}
			hs.Sent, hs.Replies = 2, 2
			r.maxReplied = TTL(i + 1)
		}
	}
	if dist > 0 {
		r.distance = TTL(dist)
	}
	r.sweeps = 2
	return f
}

func groupingCore(t *testing.T) (*simNet, *Endpoint) {
	cfg := simpleCfg()
	cfg.Flows = 1
	s := newSim(t, cfg, func(*Flow, Mono) *simPath { return nil })
	ep := s.add(1)
	for _, f := range ep.Flows {
		f.invalid = InvalidLocalRoute // keep the monitored one out of grouping
	}
	return s, ep
}

// H: a hidden hop does not prevent recognizing two proven-different branches.
func TestHiddenHopDistinct(t *testing.T) {
	s, ep := groupingCore(t)
	// C knows TTL 3, so TTL 3 is not universally silent for A and B.
	a := obsFlow(s.c, ep, []string{"10.0.0.1", "10.1.0.1", "*", "10.3.0.1"}, 5)
	b := obsFlow(s.c, ep, []string{"10.0.0.1", "10.2.0.1", "*", "10.3.0.1"}, 5)
	obsFlow(s.c, ep, []string{"10.0.0.1", "10.5.0.1", "10.5.1.1", "10.3.0.1"}, 5)
	s.c.regroup(ep)
	if a.level != LevelPartialDistinct || b.level != LevelPartialDistinct || a.group == b.group {
		t.Fatalf("a %s b %s same=%v: %s", a.level, b.level, a.group == b.group, groupsDump(ep))
	}
	if ep.branches() != 3 {
		t.Fatalf("branches %d", ep.branches())
	}
	// Universally silent hop: both become confirmed (complete) and distinct.
	s2, ep2 := groupingCore(t)
	a2 := obsFlow(s2.c, ep2, []string{"10.0.0.1", "10.1.0.1", "*", "10.3.0.1"}, 5)
	b2 := obsFlow(s2.c, ep2, []string{"10.0.0.1", "10.2.0.1", "*", "10.3.0.1"}, 5)
	s2.c.regroup(ep2)
	if a2.level != LevelConfirmed || b2.level != LevelConfirmed || a2.group == b2.group {
		t.Fatalf("%s", groupsDump(ep2))
	}
}

// Compatible incomplete signatures are not merged transitively.
func TestWildcardNonTransitive(t *testing.T) {
	s, ep := groupingCore(t)
	A := obsFlow(s.c, ep, []string{"10.0.0.1", "*", "10.0.0.5"}, 4)
	B := obsFlow(s.c, ep, []string{"10.0.0.1", "10.0.0.2", "10.0.0.5"}, 4)
	C := obsFlow(s.c, ep, []string{"10.0.0.1", "10.0.0.3", "10.0.0.5"}, 4)
	s.c.regroup(ep)
	if B.level != LevelConfirmed || C.level != LevelConfirmed || B.group == C.group {
		t.Fatalf("B/C: %s", groupsDump(ep))
	}
	if A.level != LevelAmbiguous || A.group != nil {
		t.Fatalf("A must be ambiguous, got %s", A.level)
	}
	// Tentative: compatible with exactly one confirmed group.
	s2, ep2 := groupingCore(t)
	T := obsFlow(s2.c, ep2, []string{"10.0.0.1", "?", "10.0.0.5"}, 4)
	B2 := obsFlow(s2.c, ep2, []string{"10.0.0.1", "10.0.0.2", "10.0.0.5"}, 4)
	s2.c.regroup(ep2)
	if T.level != LevelTentative || T.group != B2.group || len(B2.group.Members) != 1 {
		t.Fatalf("tentative: %s %s", T.level, groupsDump(ep2))
	}
}

// Grouping is deterministic regardless of flow processing order.
func TestGroupingDeterministic(t *testing.T) {
	sigs := [][]string{
		{"10.0.0.1", "10.1.0.1", "10.3.0.1"}, {"10.0.0.1", "10.2.0.1", "10.3.0.1"},
		{"10.0.0.1", "*", "10.3.0.1"}, {"10.0.0.1", "10.1.0.1", "?"}, {"10.0.0.1", "10.4.0.1", "*"},
		{"10.0.0.1", "10.2.0.1", "10.3.0.1"}, {"10.0.0.1", "10.1.0.1", "10.3.0.1"},
	}
	var ref []string
	for trial := 0; trial < 20; trial++ {
		order := rand.Perm(len(sigs))
		s, ep := groupingCore(t)
		for _, i := range order {
			obsFlow(s.c, ep, sigs[i], 4)
		}
		s.c.regroup(ep)
		var got []string
		for _, g := range ep.groups {
			got = append(got, g.ID+g.Level.String()+itoa(len(g.Members))+itoa(len(g.Tentative)))
		}
		slices.Sort(got)
		if ref == nil {
			ref = got
		} else if !slices.Equal(ref, got) {
			t.Fatalf("order-dependent grouping:\n%v\n%v", ref, got)
		}
	}
}

func itoa(i int) string { return string(rune('0' + i)) }

// --- correlation invariants ---

func manualCore(t *testing.T) (*simNet, *Flow) {
	cfg := simpleCfg()
	cfg.Flows = 1
	s := newSim(t, cfg, func(*Flow, Mono) *simPath { return nil }) // network silent; packets injected manually
	ep := s.add(1)
	return s, ep.Flows[0]
}

func (s *simNet) runUntilActive(f *Flow) *Probe {
	for i := 0; i < 300 && f.active == nil; i++ {
		s.run(10 * time.Millisecond)
	}
	if f.active == nil {
		s.t.Fatal("no active probe")
	}
	return f.active
}

func synack(f *Flow, ack uint32, flags uint8) *wire.Packet {
	return &wire.Packet{Kind: wire.KindTCP, Src: f.Tmpl.Dst, Dst: f.Tmpl.Src, SPort: f.Tmpl.DPort, DPort: f.Tmpl.SPort, Ack: ack, Flags: flags, TS: 1, TSKernel: true}
}

// Weak match never becomes strict success; RST without ACK is unexpected.
func TestWeakMatchNotSuccess(t *testing.T) {
	s, f := manualCore(t)
	p := s.runUntilActive(f)
	pkt := synack(f, p.seq+12345, wire.SYN|wire.ACK)
	pkt.TS = s.rtBase + int64(s.now)
	s.c.OnPacket(pkt)
	if f.active != nil {
		t.Fatal("weak reply must complete the probe")
	}
	s.run(300 * time.Millisecond)
	if f.C.SynAck != 0 || f.C.Weak != 1 || f.C.Valid() != 0 {
		t.Fatalf("%+v", f.C)
	}
	if f.rtt.n != 0 {
		t.Fatal("weak reply used for RTT")
	}
	// Next probe: a RST without ACK is unexpected, not a success.
	p = s.runUntilActive(f)
	s.c.OnPacket(synack(f, 0, wire.RST))
	s.run(1100 * time.Millisecond)
	if f.C.Rst != 0 || f.C.Unexpected == 0 {
		t.Fatalf("%+v", f.C)
	}
	_ = p
}

// Duplicates and late replies are never counted twice or credited.
func TestDuplicateAndLate(t *testing.T) {
	s, f := manualCore(t)
	p := s.runUntilActive(f)
	seq := p.seq
	s.c.OnPacket(&wire.Packet{Kind: wire.KindTCP, Outgoing: true, Src: f.Tmpl.Src, Dst: f.Tmpl.Dst, SPort: f.Tmpl.SPort, DPort: f.Tmpl.DPort, Seq: seq, Flags: wire.SYN, TS: int64(p.sentRT), TSKernel: true})
	r := synack(f, seq+1, wire.SYN|wire.ACK)
	r.TS = int64(p.sentRT) + 5e6
	s.c.OnPacket(r)
	s.c.OnPacket(r) // duplicate
	s.run(500 * time.Millisecond)
	if f.C.SynAck != 1 || f.C.Duplicate != 1 {
		t.Fatalf("%+v", f.C)
	}
	if f.rtt.last < 4900 || f.rtt.last > 5100 {
		t.Fatalf("kernel RTT %d us", f.rtt.last)
	}
	if f.C.RstMissing != 1 {
		t.Fatalf("missing RST not detected: %+v", f.C)
	}
	// Next probe times out; its late SYN/ACK arrives during the following one.
	p2 := s.runUntilActive(f)
	seq2 := p2.seq
	for f.active != nil && f.active.seq == seq2 {
		s.run(50 * time.Millisecond)
	}
	p3 := s.runUntilActive(f)
	s.c.OnPacket(synack(f, seq2+1, wire.SYN|wire.ACK))
	if f.active != p3 {
		t.Fatal("late reply completed the new probe")
	}
	if f.C.Late != 1 {
		t.Fatalf("%+v", f.C)
	}
}

// ICMP quote fallback: seq mismatch accepted only with a single candidate
// and matching IP ID, flagged low-confidence; disabled by --no-quote-fallback.
func TestQuoteFallback(t *testing.T) {
	for _, enabled := range []bool{true, false} {
		s, f := manualCore(t)
		s.c.cfg.QuoteFallback = enabled
		s.c.cfg.Discovery = true
		f.Role = RoleCandidate
		f.e2eGen++
		s.c.startSweep(f, ClassDiscovery, 1)
		s.run(5 * time.Millisecond)
		p := f.active
		if p == nil || p.class != ClassDiscovery {
			t.Fatal("no hop probe")
		}
		s.c.OnPacket(&wire.Packet{Kind: wire.KindTCP, Outgoing: true, Src: f.Tmpl.Src, Dst: f.Tmpl.Dst, SPort: f.Tmpl.SPort, DPort: f.Tmpl.DPort, Seq: p.seq, Flags: wire.SYN, TS: int64(p.sentRT), TSKernel: true})
		ic := &wire.Packet{Kind: wire.KindICMP, Src: netip.MustParseAddr("10.0.0.1"), ICMPType: 11,
			InnerSrc: f.Tmpl.Src, InnerDst: f.Tmpl.Dst, InnerSPort: f.Tmpl.SPort, InnerDPort: f.Tmpl.DPort,
			InnerSeq: p.seq ^ 0xffff, HasInnerSeq: true, InnerIPID: p.ipid ^ 1, TS: int64(p.sentRT) + 1e6, TSKernel: true}
		s.c.OnPacket(ic) // IP ID mismatch: never matched
		if f.active != p {
			t.Fatal("matched on insufficient identifiers")
		}
		ic.InnerIPID = p.ipid
		s.c.OnPacket(ic)
		if enabled {
			if f.active == p || s.c.M.QuoteSeqMismatch != 1 {
				t.Fatal("fallback not applied")
			}
			s.run(300 * time.Millisecond)
			if h := f.route.hopIf(1); h.LowConf != 1 || h.Replies != 1 {
				t.Fatalf("%+v", h)
			}
		} else if f.active != p {
			t.Fatal("fallback applied although disabled")
		}
	}
}

// Local SNAT of our SYN invalidates the flow; its timeouts are not loss.
func TestLocalNATInvalid(t *testing.T) {
	s, f := manualCore(t)
	p := s.runUntilActive(f)
	s.c.OnPacket(&wire.Packet{Kind: wire.KindTCP, Outgoing: true, Src: netip.MustParseAddr("203.0.113.9"), Dst: f.Tmpl.Dst, SPort: 40000, DPort: f.Tmpl.DPort, Seq: p.seq, Flags: wire.SYN, TS: 1, TSKernel: true})
	s.run(20 * time.Second)
	if f.invalid != InvalidLocalNAT || f.State() != FInvalid {
		t.Fatalf("invalid=%v state=%v", f.invalid, f.State())
	}
	if f.C.Timeout != 0 || f.sm.avail == AvailDown {
		t.Fatalf("NATed flow produced network loss: %+v", f.C)
	}
}

// A SYN never seen leaving is a local error, not a timeout.
func TestTxNotObservedIsLocal(t *testing.T) {
	p := linear(3, 10*time.Millisecond)
	p.loss = 1
	s := newSim(t, simpleCfg(), func(*Flow, Mono) *simPath { return p })
	s.noTxCap = func(*Flow) bool { return true }
	ep := s.add(16)
	s.run(15 * time.Second)
	for _, f := range monitored(ep) {
		if f.C.Timeout != 0 || f.State() == FDown {
			t.Fatalf("%+v", f.C)
		}
		if f.C.LocalErr == 0 {
			t.Fatal("not counted as local error")
		}
	}
}

// Scheduler starvation is skipped, never timeout; no catch-up burst.
func TestSkippedNotLoss(t *testing.T) {
	p := linear(3, 10*time.Millisecond)
	cfg := simpleCfg()
	cfg.PPS = 5 // 16 flows at 1/s cannot fit
	s := newSim(t, cfg, func(*Flow, Mono) *simPath { return p })
	ep := s.add(16)
	s.run(60 * time.Second)
	var skipped, valid, timeout uint64
	for _, f := range monitored(ep) {
		skipped += f.C.Skipped
		valid += f.C.Valid()
		timeout += f.C.Timeout
	}
	if skipped == 0 || timeout != 0 {
		t.Fatalf("skipped %d timeout %d", skipped, timeout)
	}
	// No burst: sends are within the configured rate (plus small burst).
	if float64(s.sentE2E) > 60*5*1.1+10 {
		t.Fatalf("burst: %d sends in 60s at 5 pps", s.sentE2E)
	}
	for _, f := range monitored(ep) {
		if f.State() == FDown || f.State() == FLoss {
			t.Fatal("starvation became a network failure")
		}
	}
}

// Hop budget shortage makes hops STALE, never 100% loss.
func TestHopBudgetStale(t *testing.T) {
	p := linear(6, 10*time.Millisecond)
	s := newSim(t, simpleCfg(), func(*Flow, Mono) *simPath { return p })
	s.c.cfg.Discovery = true
	s.c.cfg.ResponderPPS = 0.02 // one probe per 50 s per responder
	ep := s.add(64)
	s.run(90 * time.Second)
	snap := s.c.Snapshot(SnapOpts{Hops: true, Only: AllEndpoints})
	for _, f := range snap.Endpoints[0].Flows {
		for _, h := range f.Hops {
			if h.Loss != nil && *h.Loss > 0 {
				t.Fatalf("budget shortage produced hop loss: %+v", h)
			}
		}
	}
	if s.c.M.HopDeferResp == 0 {
		t.Fatal("responder limiting not accounted")
	}
	_ = ep
}

// Wilson must not make LOSS recovery unreachable: after the loss stops,
// the flow returns to OK within minutes.
func TestLossRecoveryReachable(t *testing.T) {
	p := linear(3, 10*time.Millisecond)
	s := newSim(t, simpleCfg(), func(*Flow, Mono) *simPath { return p })
	ep := s.add(16)
	s.run(30 * time.Second)
	p.loss = 0.2
	s.run(2 * time.Minute)
	nLoss := 0
	for _, f := range monitored(ep) {
		if f.State() == FLoss {
			nLoss++
		}
	}
	if nLoss < 12 {
		t.Fatalf("only %d flows in LOSS at 20%% loss", nLoss)
	}
	p.loss = 0
	s.run(80 * time.Second)
	for _, f := range monitored(ep) {
		if f.State() != FOK {
			t.Fatalf("%s did not recover: %s consecPos=%d", f.Name(), f.State(), f.sm.consecPos)
		}
	}
	s.c.Flush()
	if s.count(EvFlowLossCleared)+s.count(EvEndpointRecovered)+s.count(EvGroupRecovered) == 0 {
		t.Fatal(evTypes(s.events))
	}
}

// Same source port reused by different endpoints is independent.
func TestSamePortDifferentEndpoints(t *testing.T) {
	p := linear(3, 10*time.Millisecond)
	dead := linear(3, 10*time.Millisecond)
	dead.loss = 1
	s := newSim(t, simpleCfg(), func(f *Flow, _ Mono) *simPath {
		if f.EP.ID == 1 {
			return dead
		}
		return p
	})
	ep0 := s.add(16)
	ep1, err := s.c.AddEndpoint("sim2", netip.MustParseAddr("198.51.100.11"), 443, ep0.ports)
	if err != nil {
		t.Fatal(err)
	}
	s.run(60 * time.Second)
	if ep0.Flows[0].SPort() != ep1.Flows[0].SPort() {
		t.Fatal("ports differ")
	}
	if ep0.Flows[0].State() != FOK || ep1.Flows[0].State() != FDown {
		t.Fatalf("%s %s", ep0.Flows[0].State(), ep1.Flows[0].State())
	}
}

// Statistics reset starts a fresh warmup without events.
func TestResetStats(t *testing.T) {
	p := linear(3, 10*time.Millisecond)
	s := newSim(t, simpleCfg(), func(*Flow, Mono) *simPath { return p })
	ep := s.add(16)
	s.run(60 * time.Second)
	n := len(s.events)
	s.c.ResetStats()
	for _, f := range monitored(ep) {
		if f.State() != FUnknown || f.C.Sent != 0 {
			t.Fatal("not reset")
		}
	}
	s.run(45 * time.Second)
	s.c.Flush()
	if len(s.events) != n {
		t.Fatalf("reset produced events: %v", evTypes(s.events[n:]))
	}
	for _, f := range monitored(ep) {
		if f.State() != FOK {
			t.Fatal(f.State())
		}
	}
}

// ICMP unreachable is a separate network failure, not a timeout.
func TestUnreachable(t *testing.T) {
	p := linear(3, 10*time.Millisecond)
	p.unreach = true
	s := newSim(t, simpleCfg(), func(*Flow, Mono) *simPath { return p })
	ep := s.add(16)
	s.run(20 * time.Second)
	f := monitored(ep)[0]
	if f.C.Unreach == 0 || f.C.Timeout != 0 || f.State() != FDown {
		t.Fatalf("%+v %s", f.C, f.State())
	}
}

// Recovery is never suppressed by aggregation: the endpoint recovery and
// every flow recovery are reported.
func TestRecoveryNotSuppressed(t *testing.T) {
	p := linear(3, 10*time.Millisecond)
	p.loss = 1
	s := newSim(t, simpleCfg(), func(*Flow, Mono) *simPath { return p })
	s.add(64)
	s.run(20 * time.Second)
	p.loss = 0
	s.run(20 * time.Second)
	s.c.Flush()
	if s.count(EvEndpointDown) != 1 || s.count(EvFlowDown) != 0 {
		t.Fatalf("problem events %v", evTypes(s.events))
	}
	if s.count(EvEndpointRecovered) != 1 || s.count(EvFlowRecovered) != 16 {
		t.Fatalf("recovery events %v", evTypes(s.events))
	}
	// A new episode after recovery is reported again (not deduplicated).
	p.loss = 1
	s.run(15 * time.Second)
	s.c.Flush()
	if s.count(EvEndpointDown) != 2 {
		t.Fatalf("second episode suppressed: %v", evTypes(s.events))
	}
}

// LOCALIZATION_RESULT is published only on level / segment-set changes.
func TestLocalizationResultRules(t *testing.T) {
	s, ep := groupingCore(t)
	c := s.c
	n := func() int { return s.count(EvLocalization) }
	c.setLoc(ep, Localization{Level: LocNone})
	if n() != 0 {
		t.Fatal("initial NONE must not be an event")
	}
	c.setLoc(ep, Localization{Level: LocSuspectedSegment, SuspectedSegments: []string{"a→b"}, Supporting: []string{"x"}})
	c.setLoc(ep, Localization{Level: LocSuspectedSegment, SuspectedSegments: []string{"a→b"}, Supporting: []string{"y"}})
	if n() != 1 {
		t.Fatalf("supporting-only change produced an event: %d", n())
	}
	c.setLoc(ep, Localization{Level: LocSuspectedSegment, SuspectedSegments: []string{"a→b", "b→c"}})
	if n() != 2 {
		t.Fatal("segment set change not reported")
	}
	c.setLoc(ep, Localization{Level: LocInconclusive})
	if n() != 3 {
		t.Fatal("losing a confirmed localization must be reported")
	}
	c.setLoc(ep, Localization{Level: LocInconclusive, BadGroups: []string{"G1"}})
	if n() != 3 {
		t.Fatal("INCONCLUSIVE → INCONCLUSIVE is noise")
	}
	c.setLoc(ep, Localization{Level: LocNone})
	if n() != 4 {
		t.Fatal("improvement to NONE must be reported")
	}
	last := s.events[len(s.events)-1]
	if d, ok := last.Details.(*LocalizationDetails); !ok || d.OldLevel != LocInconclusive || d.NewLevel != LocNone {
		t.Fatalf("%+v", last.Details)
	}
}

// RTT degradation detection must not depend on the sample ring covering
// three periods: at 100 ms intervals the ring holds about 13 s.
func TestRelativeRTTFastInterval(t *testing.T) {
	p := linear(3, time.Millisecond)
	slow := linear(3, 30*time.Millisecond)
	var sf *Flow
	cfg := simpleCfg()
	cfg.Interval, cfg.Timeout = 100*time.Millisecond, 100*time.Millisecond
	cfg.EndpointPPS = 2000
	s := newSim(t, cfg, func(f *Flow, _ Mono) *simPath {
		if f == sf {
			return slow
		}
		return p
	})
	ep := s.add(64)
	sf = monitored(ep)[2]
	s.run(45 * time.Second)
	if !sf.sm.rttRel {
		t.Fatal("relative degradation not detected at 100ms interval")
	}
}

// Sequence numbers of one flow always move forward (RFC 793 "after"):
// stateful middleboxes drop a re-sent SYN on a 4-tuple in SYN_SENT whose
// seq is before the previous one.
func TestSeqMonotonicPerFlow(t *testing.T) {
	p := linear(4, 5*time.Millisecond)
	s := newSim(t, simpleCfg(), func(*Flow, Mono) *simPath { return p })
	s.c.cfg.Discovery = true
	last := map[FlowID]uint32{}
	bad := 0
	orig := s.path
	s.path = func(f *Flow, now Mono) *simPath {
		if f.active == nil { // called from Send before activation
			seq := f.lastSeq
			if prev, ok := last[f.ID]; ok && int32(seq-prev) <= 0 {
				bad++
			}
			last[f.ID] = seq
		}
		return orig(f, now)
	}
	s.add(64)
	s.run(60 * time.Second)
	if bad != 0 || len(last) == 0 {
		t.Fatalf("%d non-increasing seqs over %d flows", bad, len(last))
	}
}

// ... and across restarts of mpmtr (stale SYN_SENT entries of a previous run
// on a middlebox): the ISN clock component keeps moving forward.
func TestSeqMonotonicAcrossRestart(t *testing.T) {
	first := func(delay time.Duration) uint32 {
		p := linear(2, time.Millisecond)
		s := newSim(t, simpleCfg(), func(*Flow, Mono) *simPath { return p })
		s.rtBase += int64(delay)
		s.c.nowRT = Wall(s.rtBase)
		ep := s.add(1)
		s.run(1500 * time.Millisecond)
		return ep.Flows[0].lastSeq
	}
	a := first(0)
	b := first(2 * time.Second)
	if int32(b-a) <= 0 {
		t.Fatalf("ISN went backwards across restart: %d then %d", a, b)
	}
}

// Flow set model: the first port is measured at once; discovery walks the
// ports in order; every route found gets cfg.Flows measured ports; a
// measured port is never replaced; discovery stops when new ports keep
// landing on known routes.
func TestFlowSetModel(t *testing.T) {
	arms := make([]*simPath, 4)
	for i := range arms {
		arms[i] = linear(4, 20*time.Millisecond)
		arms[i].hops[1].addr = netip.AddrFrom4([4]byte{10, 9, byte(i), 1})
	}
	armOf := func(sport wire.Port) int { return int((uint32(sport)*2654435761)>>7) % 4 }
	cfg := simpleCfg()
	cfg.Flows = 1
	cfg.Discovery = true
	cfg.ResponderPPS = 100
	s := newSim(t, cfg, func(f *Flow, _ Mono) *simPath { return arms[armOf(f.SPort())] })
	ep := s.add(256)
	if m := monitored(ep); len(m) != 1 || m[0].SPort() != 20000 {
		t.Fatalf("at start: %d measured", len(m))
	}
	seen := map[*Flow]bool{}
	for step := 0; step < 24; step++ {
		s.run(5 * time.Second)
		for f := range seen {
			if !f.Role.Monitored() {
				t.Fatalf("measured port %d was replaced", f.SPort())
			}
		}
		for _, f := range monitored(ep) {
			seen[f] = true
		}
	}
	if !ep.disc.stopped || ep.disc.reason != StopStability {
		t.Fatalf("discovery %+v", ep.discoveryStatus(true))
	}
	if ep.disc.explored >= 256 {
		t.Fatalf("explored all %d ports: stop rule did not fire", ep.disc.explored)
	}
	if b := ep.branches(); b != 4 {
		t.Fatalf("routes %d: %v", b, groupsDump(ep))
	}
	if n := len(monitored(ep)); n != 4 {
		t.Fatalf("measured %d ports for 4 routes", n)
	}
	for _, g := range ep.groups {
		n := 0
		for _, f := range g.Members {
			if f.Role.Monitored() {
				n++
			}
		}
		if n != 1 {
			t.Fatalf("route %s: %d measured", g.ID, n)
		}
	}
	prev := wire.Port(0)
	for _, f := range ep.Flows {
		if f.SPort() < prev {
			t.Fatalf("ports not explored in order: %d after %d", f.SPort(), prev)
		}
		prev = f.SPort()
	}
	if ep.state != EPOK {
		t.Fatalf("endpoint %s", ep.state)
	}
}

type routeSim struct {
	*simNet
	src netip.Addr
}

func (r *routeSim) Route(dst netip.Addr, sport, dport wire.Port) (Route, error) {
	return Route{Src: r.src, IfIndex: 2}, nil
}

// A local route/source change retires the old flow identity (with its
// statistics) and continues on a new flow; nothing is mixed or lost.
func TestLocalRouteChange(t *testing.T) {
	p := linear(3, 5*time.Millisecond)
	s := newSim(t, simpleCfg(), func(*Flow, Mono) *simPath { return p })
	rs := &routeSim{simNet: s, src: simSrc}
	s.c.env = rs
	ep := s.add(64)
	s.run(40 * time.Second)
	old := monitored(ep)
	rs.src = netip.MustParseAddr("192.0.2.77")
	if n := s.c.RevalidateRoutes(); n != 16 {
		t.Fatalf("revalidated %d", n)
	}
	s.run(40 * time.Second)
	for _, f := range old {
		if f.invalid != InvalidLocalRoute || f.Role.Monitored() || f.C.Timeout != 0 {
			t.Fatalf("old flow %s: %v %s %+v", f.Name(), f.invalid, f.Role, f.C)
		}
	}
	nw := monitored(ep)
	if len(nw) != 16 {
		t.Fatalf("monitored after change: %d", len(nw))
	}
	for _, f := range nw {
		if f.Tmpl.Src != rs.src || f.C.SynAck == 0 || f.C.Timeout != 0 {
			t.Fatalf("new flow %s src %s %+v", f.Name(), f.Tmpl.Src, f.C)
		}
	}
}

// Drops are counted at the statistics read, while the watermark
// lags behind it. A probe sent after the reported watermark whose reply was
// dropped before that read must still become capture_impaired, not timeout.
func TestDropPeriodNotBoundedByWatermark(t *testing.T) {
	s, f := manualCore(t)
	p := s.runUntilActive(f)
	s.c.OnPacket(&wire.Packet{Kind: wire.KindTCP, Outgoing: true, IfIndex: int32(f.IfIndex), Src: f.Tmpl.Src, Dst: f.Tmpl.Dst,
		SPort: f.Tmpl.SPort, DPort: f.Tmpl.DPort, Seq: p.seq, Flags: wire.SYN, TS: int64(p.sentRT), TSKernel: true})
	// Statistics read 2 ms after the send reports one drop; the watermark of
	// that read is 8 ms behind it (before the probe was sent).
	read := p.sentRT.Add(2 * time.Millisecond)
	s.c.OnWatermarkDrops(read.Add(-10*time.Millisecond), 1, 0, read.Add(-5*time.Millisecond), read)
	s.dropsFn = nil
	seq := p.seq
	s.run(1500 * time.Millisecond)
	if f.C.Impaired != 1 || f.C.Timeout != 0 {
		t.Fatalf("probe %d: %+v", seq, f.C)
	}
}

// SharedHops: after discovery, a hop that all measured flows share (TTL 1)
// is refreshed by one flow only; without the option every flow refreshes it.
func TestSharedHops(t *testing.T) {
	run := func(shared bool) (probers map[FlowID]int, treeSent int) {
		arms := make([]*simPath, 4)
		for i := range arms {
			arms[i] = linear(4, 20*time.Millisecond)
			arms[i].hops[1].addr = netip.AddrFrom4([4]byte{10, 9, byte(i), 1})
		}
		armOf := func(sport wire.Port) int { return int((uint32(sport)*2654435761)>>7) % 4 }
		cfg := simpleCfg()
		cfg.Flows = 2
		cfg.Discovery = true
		cfg.SharedHops = shared
		s := newSim(t, cfg, func(f *Flow, _ Mono) *simPath { return arms[armOf(f.SPort())] })
		ep := s.add(256)
		s.run(2 * time.Minute) // discovery done, owners built
		if !ep.disc.stopped {
			t.Fatal("discovery still running")
		}
		probers = map[FlowID]int{}
		s.onSend = func(f *Flow, ttl uint8) {
			if ttl == 1 {
				probers[f.ID]++
			}
		}
		s.run(time.Minute)
		s.onSend = nil
		for _, r := range s.c.buildTree(ep) {
			if !r.E2E && r.Hop.TTL == 1 {
				treeSent = int(r.Hop.Sent)
			}
		}
		return
	}
	off, _ := run(false)
	on, sent := run(true)
	if len(off) < 4 {
		t.Fatalf("without --shared-hops only %d flows refreshed hop 1", len(off))
	}
	if len(on) != 1 {
		t.Fatalf("with --shared-hops %d flows refreshed hop 1: %v", len(on), on)
	}
	if sent == 0 {
		t.Fatal("shared hop has no statistics in the tree")
	}
}

// Behind a heavily ICMP-rate-limited first hop: incomplete traces that do
// not contradict each other are one route, not one route each; a
// trace fitting two different routes waits; one reply identifies a hop.
func TestPartialTracesCluster(t *testing.T) {
	s, ep := groupingCore(t)
	p3 := obsFlow(s.c, ep, []string{"10.0.0.1", "10.9.0.1", "10.2.0.1"}, 0)
	p1 := obsFlow(s.c, ep, []string{"10.0.0.1", "10.1.0.1", "?"}, 0)
	p2 := obsFlow(s.c, ep, []string{"10.0.0.1", "?", "10.2.0.1"}, 0)
	p4 := obsFlow(s.c, ep, []string{"?", "10.1.0.1", "10.4.0.1"}, 0)
	p5 := obsFlow(s.c, ep, []string{"10.0.0.1", "?", "?", "10.7.0.1"}, 0)
	s.c.regroup(ep)
	if ep.branches() != 2 {
		t.Fatalf("routes %d, want 2: %s", ep.branches(), groupsDump(ep))
	}
	if p4.group == nil || p4.group != p1.group {
		t.Fatalf("p4 must join p1's route: %s", groupsDump(ep))
	}
	if p3.group == p1.group {
		t.Fatal("p3 and p1 differ at TTL 2")
	}
	// p2 fits p1's route only until p4 shows that route goes via 10.4.0.1.
	if p2.group == nil || p2.group != p3.group {
		t.Fatalf("p2 must end on p3's route: %s", groupsDump(ep))
	}
	if p5.level != LevelAmbiguous || len(p5.fits) != 2 {
		t.Fatalf("p5 fits both routes, got %s fits %d: %s", p5.level, len(p5.fits), groupsDump(ep))
	}
	// A single reply from the only responder identifies the hop.
	s2, ep2 := groupingCore(t)
	a := obsFlow(s2.c, ep2, []string{"10.0.0.1", "10.1.0.1"}, 3)
	b := obsFlow(s2.c, ep2, []string{"10.0.0.1", "10.1.0.1"}, 3)
	h := b.route.hop(1)
	h.cur = netip.Addr{}
	h.resp[0].n, h.Replies, h.Sent = 1, 1, 5
	s2.c.regroup(ep2)
	if a.group == nil || a.group != b.group || a.group.Level != LevelConfirmed {
		t.Fatalf("one reply must identify the hop: %s", groupsDump(ep2))
	}
}

// Tree: a first hop that answered for some routes and was rate-limited for
// others is one node, not one node per answer status.
func TestTreeFillsSharedHop(t *testing.T) {
	s, ep := groupingCore(t)
	obsFlow(s.c, ep, []string{"10.0.0.1", "10.1.0.1", "10.3.0.1"}, 4)
	obsFlow(s.c, ep, []string{"?", "10.2.0.1", "10.3.0.1"}, 4)
	obsFlow(s.c, ep, []string{"*", "10.5.0.1", "10.3.0.1"}, 4)
	s.c.regroup(ep)
	roots := 0
	for _, r := range s.c.buildTree(ep) {
		if !r.E2E && r.Hop.TTL == 1 {
			roots++
		}
	}
	if roots != 1 {
		t.Fatalf("hop 1 drawn %d times: %s", roots, groupsDump(ep))
	}
}

// Two measured routes that turn out to be one: the higher-numbered measured
// port stops (and is reported), the lowest one keeps measuring.
func TestMergedRouteStopsDuplicate(t *testing.T) {
	s, ep := groupingCore(t)
	s.c.cfg.Discovery = true
	a := obsFlow(s.c, ep, []string{"10.0.0.1", "10.1.0.1", "10.3.0.1"}, 4)
	b := obsFlow(s.c, ep, []string{"10.0.0.1", "10.2.0.1", "10.3.0.1"}, 4)
	s.c.regroup(ep)
	s.c.assignMonitors(ep)
	if !a.Role.Monitored() || !b.Role.Monitored() {
		t.Fatalf("two routes must be measured: a %s b %s", a.Role, b.Role)
	}
	h := b.route.hop(2) // b's TTL 2 turns out to be 10.1.0.1
	h.cur = netip.MustParseAddr("10.1.0.1")
	h.resp[0] = respCount{addr: h.cur, n: 2}
	s.c.regroup(ep)
	s.c.assignMonitors(ep)
	if !a.Role.Monitored() || b.Role.Monitored() {
		t.Fatalf("after merge: a %s b %s", a.Role, b.Role)
	}
	if len(ep.stopped) != 1 || ep.stopped[0].Flow != b.Name() {
		t.Fatalf("stopped %+v", ep.stopped)
	}
}

// --shared-hops in discovery: once >= 8 ports saw the same single router at
// TTL 1, later ports start after it (every 8th still from TTL 1); the routes
// found are the same.
func TestSharedPrefixDiscovery(t *testing.T) {
	run := func(shared bool) (ttl1 int, routes int, confirmed bool) {
		arms := make([]*simPath, 16)
		for i := range arms {
			arms[i] = linear(4, 20*time.Millisecond)
			arms[i].hops[1].addr = netip.AddrFrom4([4]byte{10, 9, byte(i), 1})
		}
		armOf := func(sport wire.Port) int { return int((uint32(sport)*2654435761)>>7) % 16 }
		cfg := simpleCfg()
		cfg.Flows = 1
		cfg.Discovery = true
		cfg.DiscoverOnly = true
		cfg.SharedHops = shared
		s := newSim(t, cfg, func(f *Flow, _ Mono) *simPath { return arms[armOf(f.SPort())] })
		s.onSend = func(f *Flow, ttl uint8) {
			if ttl == 1 {
				ttl1++
			}
		}
		ep := s.add(256)
		s.run(3 * time.Minute)
		confirmed = true
		for _, g := range ep.groups {
			if g.Level != LevelConfirmed {
				confirmed = false
			}
		}
		return ttl1, ep.branches(), confirmed
	}
	off, rOff, _ := run(false)
	on, rOn, conf := run(true)
	if rOff != 16 || rOn != 16 || !conf {
		t.Fatalf("routes %d / %d (confirmed %v)", rOff, rOn, conf)
	}
	if on*3 > off {
		t.Fatalf("TTL 1 probes: %d with --shared-hops vs %d without", on, off)
	}
	t.Logf("TTL 1 probes in discovery: %d → %d", off, on)
}

// Rate-limited first hop: ports whose TTL-1 probe was not
// answered are taken to pass the router every answering port saw there, so
// their routes are complete (confirmed), not "partly".
func TestRateLimitedSharedHopCompletes(t *testing.T) {
	s, ep := groupingCore(t)
	for i := 0; i < 3; i++ {
		obsFlow(s.c, ep, []string{"10.0.0.1", "10.1.0.1", "10.3.0.1"}, 4)
	}
	x := obsFlow(s.c, ep, []string{"*", "10.2.0.1", "10.3.0.1"}, 4)
	y := obsFlow(s.c, ep, []string{"?", "10.1.0.1", "10.3.0.1"}, 4)
	s.c.regroup(ep)
	if x.level != LevelConfirmed || y.level != LevelConfirmed {
		t.Fatalf("x %s y %s: %s", x.level, y.level, groupsDump(ep))
	}
	if ep.branches() != 2 {
		t.Fatalf("routes %d: %s", ep.branches(), groupsDump(ep))
	}
}

// Parallel TTLs: with silent hops (common in practice) discovery of a
// 4-route endpoint finishes in a few seconds and finds every route.
func TestDiscoveryParallelTTL(t *testing.T) {
	arms := make([]*simPath, 4)
	for i := range arms {
		arms[i] = linear(9, 100*time.Millisecond)
		arms[i].hops[1].addr = netip.AddrFrom4([4]byte{10, 9, byte(i), 1})
		for h := 3; h <= 6; h++ {
			arms[i].hops[h].silent = true
		}
	}
	armOf := func(sport wire.Port) int { return int((uint32(sport)*2654435761)>>7) % 4 }
	cfg := simpleCfg()
	cfg.Flows = 1
	cfg.Discovery = true
	cfg.DiscoverOnly = true
	s := newSim(t, cfg, func(f *Flow, _ Mono) *simPath { return arms[armOf(f.SPort())] })
	ep := s.add(256)
	var took time.Duration
	for step := 0; step < 600 && !ep.disc.stopped; step++ {
		s.run(100 * time.Millisecond)
		took += 100 * time.Millisecond
	}
	if !ep.disc.stopped || ep.branches() != 4 {
		t.Fatalf("stopped %v routes %d after %v: %s", ep.disc.stopped, ep.branches(), took, groupsDump(ep))
	}
	for _, g := range ep.groups {
		if g.Level != LevelConfirmed {
			t.Fatalf("route %s %s", g.ID, g.Level)
		}
	}
	if took > 6*time.Second {
		t.Fatalf("discovery of %d ports took %v", ep.disc.explored, took)
	}
	t.Logf("discovery: %d ports, 4 routes in %v (sim time)", ep.disc.explored, took)
}

// The routes an ambiguous port fits are recomputed on every regroup: a
// port that has become resolved is no longer listed as "unresolved".
func TestFitsResetOnRegroup(t *testing.T) {
	s, ep := groupingCore(t)
	obsFlow(s.c, ep, []string{"10.0.0.1", "10.0.0.2", "10.0.0.5"}, 4)
	obsFlow(s.c, ep, []string{"10.0.0.1", "10.0.0.3", "10.0.0.5"}, 4)
	a := obsFlow(s.c, ep, []string{"10.0.0.1", "*", "10.0.0.5"}, 4)
	for i := 0; i < 3; i++ {
		s.c.regroup(ep)
	}
	if len(a.fits) != 2 {
		t.Fatalf("fits %d after 3 regroups", len(a.fits))
	}
	h := a.route.hop(2)
	h.Timeouts, h.Replies = 0, 2
	h.cur = netip.MustParseAddr("10.0.0.2")
	h.resp[0] = respCount{addr: h.cur, n: 2}
	s.c.regroup(ep)
	if a.fits != nil || a.group == nil {
		t.Fatalf("resolved port still lists %d fits", len(a.fits))
	}
}

// The route's loss is the loss to its last hop: the DST row of the tree
// shows the measured port's end-to-end probes, so both are one number.
func TestDSTRowIsRouteLoss(t *testing.T) {
	p := linear(4, 20*time.Millisecond)
	p.loss = 0.2
	cfg := simpleCfg()
	cfg.Flows = 1
	cfg.Discovery = true
	s := newSim(t, cfg, func(*Flow, Mono) *simPath { return p })
	ep := s.add(64)
	s.run(3 * time.Minute)
	// A not-measured port of the same route had a much faster TTL-limited
	// probe to the destination: it must not leak into the route's DST row.
	for _, f := range ep.Flows {
		if !f.Role.Monitored() && f.route.distance > 0 {
			h := f.route.hop(f.route.distance)
			h.rtt.Add(1)
			h.rtt.Add(999999)
			break
		}
	}
	var dst *TreeRow
	rows := s.c.buildTree(ep)
	for i := range rows {
		if rows[i].Group != nil {
			dst = &rows[i]
		}
	}
	if dst == nil || dst.Hop.Kind != KindDst || dst.Hop.Loss == nil {
		t.Fatalf("no DST row with loss: %+v", rows)
	}
	var valid, fail uint64
	for _, f := range ep.Flows {
		if f.Role.Monitored() {
			valid += f.C.Valid()
			fail += f.C.Failures()
		}
	}
	want := float64(fail) / float64(valid)
	var mn, mx uint32
	for _, f := range ep.Flows {
		if f.Role.Monitored() {
			mn, mx = f.rtt.min, f.rtt.max
		}
	}
	if dst.Hop.Min != mn || dst.Hop.Max != mx {
		t.Fatalf("DST best/worst %d/%d, E2E %d/%d (mixed with TTL probes)", dst.Hop.Min, dst.Hop.Max, mn, mx)
	}
	if *dst.Hop.Loss != want || uint64(dst.Hop.Sent) != valid {
		t.Fatalf("DST loss %.3f sent %d, route E2E %.3f of %d", *dst.Hop.Loss, dst.Hop.Sent, want, valid)
	}
	if want < 0.1 {
		t.Fatalf("simulated loss not visible: %.3f", want)
	}
	// Same in the flow's own hop table.
	for _, f := range ep.Flows {
		if !f.Role.Monitored() {
			continue
		}
		hs := s.c.flowHops(f)
		last := hs[len(hs)-1]
		fw := float64(f.C.Failures()) / float64(f.C.Valid())
		if last.Kind != KindDst || last.Loss == nil || *last.Loss != fw {
			t.Fatalf("flow %s DST row %+v, flow loss %.3f", f.Name(), last, fw)
		}
	}
	for _, r := range rows {
		if r.E2E {
			t.Fatal("a route has a row of its own: its numbers belong on its DST row")
		}
	}
}

// A hop losing ~20% of its ICMP replies while every later hop answers is
// flagged as ICMP rate limiting in the tree even when each port alone has
// too few probes there for the per-flow rule.
func TestTreeRateLimitPooled(t *testing.T) {
	rows := []TreeRow{
		{Path: ">a", Parent: -1, Hop: HopSnap{TTL: 1, Kind: KindHop, Sent: 140, Replies: 111}},
		{Path: ">a>b", Parent: 0, Hop: HopSnap{TTL: 2, Kind: KindHop, Sent: 110, Replies: 110}},
		{Path: ">c", Parent: -1, Hop: HopSnap{TTL: 1, Kind: KindHop, Sent: 140, Replies: 111}},
		{Path: ">c>d", Parent: 2, Hop: HopSnap{TTL: 2, Kind: KindHop, Sent: 110, Replies: 80}},
	}
	markRateLimited(rows)
	if !rows[0].Hop.RateLimit {
		t.Fatal("hop with clean downstream not flagged")
	}
	if rows[2].Hop.RateLimit {
		t.Fatal("loss that persists downstream flagged as rate limiting")
	}
}

// A later hop that is merely "not provably lossy" does not clear a lossy
// hop: 1 timeout in 5 there says little against 50% here. The flag needs
// the loss to drop significantly.
func TestRateLimitNeedsSignificantDrop(t *testing.T) {
	if lossDropsAfter(20, 40, 1, 5) {
		t.Fatal("50% of 40 cleared by 1 of 5 lost downstream")
	}
	if !lossDropsAfter(20, 40, 0, 30) {
		t.Fatal("50% of 40 with 0 of 30 lost downstream not flagged")
	}
	if !lossDropsAfter(101, 115, 0, 5) {
		t.Fatal("88% of 115 with 0 of 5 lost downstream not flagged")
	}
	if lossDropsAfter(3, 200, 0, 200) {
		t.Fatal("insignificant loss flagged")
	}
	rows := []TreeRow{
		{Path: ">a", Parent: -1, Hop: HopSnap{TTL: 1, Kind: KindHop, Sent: 40, Replies: 20}},
		{Path: ">a>b", Parent: 0, Hop: HopSnap{TTL: 2, Kind: KindHop, Sent: 5, Replies: 4}},
	}
	markRateLimited(rows)
	if rows[0].Hop.RateLimit {
		t.Fatal("tree: 50% loss cleared by a 5-probe downstream hop with a timeout")
	}
}

// Anycast: N servers behind the address with their own TS clocks (mixed
// rates, SYN-cookie quantization), the balancer picks a server per source
// port. The census finds exactly N servers, maps the ports to them, stops
// before exhausting the range, and every server gets a measured port.
func TestAnycastCensus(t *testing.T) {
	const n = 23
	type srv struct {
		hz  float64
		off uint32
	}
	servers := make([]srv, n)
	for i := range servers {
		hz := 1000.0
		if i%3 == 0 {
			hz = 250
		}
		servers[i] = srv{hz: hz, off: uint32(i)*97_000_003 + 12345}
	}
	srvOf := func(sport wire.Port) int { return int((uint32(sport)*2654435761)>>9) % n }
	p := linear(4, 30*time.Millisecond)
	cfg := simpleCfg()
	cfg.Flows = 1
	cfg.Discovery = true
	cfg.Anycast = true
	cfg.EndpointPPS = 500
	s := newSim(t, cfg, func(*Flow, Mono) *simPath { return p })
	s.serverTS = func(f *Flow, rt int64) uint32 {
		sv := servers[srvOf(f.SPort())]
		ts := sv.off + uint32(int64(float64(rt)*sv.hz/1e9))
		return ts&^63 | 23 // SYN cookie: low 6 bits encode options
	}
	ep := s.add(1024)
	s.run(2 * time.Minute)
	a := ep.ac
	if a.status != ACDone || len(a.servers) != n {
		t.Fatalf("status %s servers %d (explored %d, answers %d)", a.status, len(a.servers), a.explored, len(a.answers))
	}
	if a.explored >= 1000 {
		t.Fatalf("census did not stop early: %d", a.explored)
	}
	// Each server maps to exactly one simulated server, consistently.
	for _, sv := range a.servers {
		want := -1
		for _, port := range sv.ports {
			if want < 0 {
				want = srvOf(port)
			} else if srvOf(port) != want {
				t.Fatalf("server %s mixes ports of two machines", sv.Name())
			}
		}
	}
	measured := map[*Server]bool{}
	for _, f := range ep.Flows {
		if f.Role.Monitored() {
			if sv := a.portSrv[f.SPort()]; sv != nil {
				measured[sv] = true
			}
		}
	}
	if len(measured) != n {
		for _, sv := range a.servers {
			if !measured[sv] {
				for _, port := range sv.ports {
					f := ep.byPort[port]
					t.Logf("unmeasured %s port %d role %s invalid %v portSrv %v group %v", sv.Name(), port, f.Role, f.invalid, a.portSrv[port] == sv, f.group != nil)
				}
			}
		}
		t.Fatalf("%d of %d servers measured", len(measured), n)
	}
	if a.moved != 0 {
		t.Fatalf("measured ports reported moving: %d", a.moved)
	}
	// A flow's route ends at its server: the DST hop says which one.
	labelled := 0
	for _, fs := range s.c.Snapshot(SnapOpts{Hops: true, Only: AllEndpoints}).Endpoints[0].Flows {
		for _, h := range fs.Hops {
			if h.Kind == KindDst && fs.ACServer != "" {
				if !strings.HasPrefix(h.Name, fs.ACServer+" (") {
					t.Fatalf("%s on %s: DST hop name %q", fs.Name, fs.ACServer, h.Name)
				}
				labelled++
			}
		}
	}
	if labelled == 0 {
		t.Fatal("no DST hop names a server")
	}
	t.Logf("census: %d ports, %d servers", a.explored, len(a.servers))

	// Anti-phantom: a census server that no measured answer confirms and
	// whose measured port answers on a real server's clock is dropped; the
	// port follows the real server (and stops — that server is measured).
	real := a.servers[0]
	var port wire.Port
	for _, p := range real.ports {
		if f := ep.byPort[p]; f != nil && f.Role == RoleCandidate && f.invalid == ValidFlow {
			port = p
			break
		}
	}
	ph := &Server{ID: 999, Hz: 1000, Offset: real.Offset + 1<<30, ports: []wire.Port{port}}
	a.servers = append(a.servers, ph)
	a.portSrv[port] = ph
	pf := ep.byPort[port]
	s.c.activate(pf, RoleActive)
	s.run(10 * time.Second)
	if slices.Contains(a.servers, ph) || a.portSrv[port] != real || a.phantoms != 1 {
		t.Fatalf("phantom kept: servers %d portSrv %v phantoms %d", len(a.servers), a.portSrv[port] == real, a.phantoms)
	}
	if pf.Role.Monitored() {
		t.Fatal("duplicate measured port of the real server not stopped")
	}
}

// Per-connection clocks (modern Linux tcp_timestamps=1): servers cannot be
// told apart and the census says so instead of inventing servers.
func TestAnycastUnidentifiable(t *testing.T) {
	p := linear(4, 30*time.Millisecond)
	cfg := simpleCfg()
	cfg.Flows = 1
	cfg.Anycast = true
	s := newSim(t, cfg, func(*Flow, Mono) *simPath { return p })
	s.serverTS = func(f *Flow, rt int64) uint32 {
		return uint32(f.SPort())*2654435761 + uint32(rt/1e6)
	}
	ep := s.add(512)
	s.run(time.Minute)
	if ep.ac.status != ACUnidentifiable || len(ep.ac.servers) > 2 {
		t.Fatalf("status %s servers %d", ep.ac.status, len(ep.ac.servers))
	}
}

// Application checks: every AppInterval on each measured port, counted
// apart from the TCP probes. A server whose checks all fail while TCP
// answers is DOWN (app_down) with no TCP failure at all; slots during a
// check are skipped, never lost; a local problem (plugin) is neither.
func TestAppChecks(t *testing.T) {
	p := linear(3, 20*time.Millisecond)
	cfg := simpleCfg()
	cfg.Flows = 4
	cfg.App, cfg.AppInterval, cfg.AppTimeout = true, 5*time.Second, 2*time.Second
	cfg.Discovery = true // hop probes on the measured ports too
	s := newSim(t, cfg, func(*Flow, Mono) *simPath { return p })
	var bad *Flow
	s.appFn = func(f *Flow) (AppResult, time.Duration) {
		if f == bad {
			return AppResult{Outcome: AppFailed, ConnectRTT: 20 * time.Millisecond, Stage: "handshake", Err: "eof"}, 1500 * time.Millisecond
		}
		return AppResult{Outcome: AppPassed, ConnectRTT: 20 * time.Millisecond}, 1500 * time.Millisecond
	}
	ep := s.add(16)
	s.run(15 * time.Second) // discovery: the route and its measured ports
	if len(monitored(ep)) != 4 {
		t.Fatalf("measured %d", len(monitored(ep)))
	}
	bad = monitored(ep)[1]
	// Every check must start on a clean 4-tuple: the flow's latest raw
	// probe an answered E2E (no half-open state left on a NAT).
	checked := 0
	s.appFn0 = func(f *Flow) {
		checked++
		if !f.tupleClean || f.burst > 0 {
			t.Fatalf("flow %s: application check on a 4-tuple a hop probe left half-open", f.Name())
		}
	}
	s.run(5 * time.Minute)
	for _, f := range monitored(ep) {
		if f.invalid != ValidFlow || f.C.EgressMismatch != 0 {
			t.Fatalf("flow %s: application checks made it invalid (%s, egress mismatch %d)", f.Name(), f.invalid, f.C.EgressMismatch)
		}
		if f.C.AppSent < 45 || f.C.AppSent > 70 {
			t.Fatalf("flow %s: %d app checks in 5 min at 5 s", f.Name(), f.C.AppSent)
		}
		if f.C.SkipBy[SkipApp] == 0 {
			t.Fatalf("flow %s: no slot skipped while checks ran", f.Name())
		}
		if f.C.Timeout != 0 {
			t.Fatalf("flow %s: %d timeouts — checks disturbed the raw probes", f.Name(), f.C.Timeout)
		}
		// -c counts TCP probes only, and an application failure is neither
		// a TCP timeout nor missing from the totals.
		if tcp := f.C.SynAck + f.C.Rst + f.C.Unreach + f.C.Timeout; uint64(f.Executed) != tcp {
			t.Fatalf("flow %s: executed %d, TCP probes with a result %d (app checks %d)", f.Name(), f.Executed, tcp, f.C.AppSent)
		}
		w := f.win.sum(s.c.bucketNum(s.c.now), WindowLong)
		// TCP answered every time: no TCP failure on any flow, the bad one
		// included, and the checks are in the window with their own count.
		if w.Timeout != 0 || w.Failures() != 0 || f.C.Failures() != 0 || w.App == 0 || (f == bad) != (w.AppFail > 0) {
			t.Fatalf("flow %s: window timeouts %d, TCP failures %d, app %d of %d failed, lifetime TCP failures %d", f.Name(), w.Timeout, w.Failures(), w.AppFail, w.App, f.C.Failures())
		}
		if f == bad {
			if w.AppFail != w.App || f.State() != FDown || f.sm.reason != ReasonAppDown || f.sm.tcpDown || f.appStage != "handshake" {
				t.Fatalf("failing server: %d of %d checks failed, state %s (%s), TCP down %v, stage %q", w.AppFail, w.App, f.State(), f.sm.reason, f.sm.tcpDown, f.appStage)
			}
		} else if f.C.AppOK == 0 || f.State() != FOK {
			t.Fatalf("flow %s: ok %d state %s", f.Name(), f.C.AppOK, f.State())
		}
	}
}

// The application's state follows its own checks: three failed in a row make
// the flow DOWN although every TCP probe in between is answered, two passed
// in a row bring it back with a recovery event; a check failing now and then
// is LOSS, and the TCP failure rate stays zero throughout.
func TestAppStateIsItsOwn(t *testing.T) {
	p := linear(3, 20*time.Millisecond)
	cfg := simpleCfg()
	cfg.Flows = 1
	cfg.App, cfg.AppInterval, cfg.AppTimeout = true, 5*time.Second, 2*time.Second
	s := newSim(t, cfg, func(*Flow, Mono) *simPath { return p })
	mode, n := "ok", 0
	s.appFn = func(f *Flow) (AppResult, time.Duration) {
		n++
		if mode == "dead" || (mode == "flaky" && n%4 == 0) {
			return AppResult{Outcome: AppFailed, ConnectRTT: 20 * time.Millisecond, Stage: "answer", Err: "eof"}, 200 * time.Millisecond
		}
		return AppResult{Outcome: AppPassed, ConnectRTT: 20 * time.Millisecond}, 200 * time.Millisecond
	}
	ep := s.add(1)
	f := ep.Flows[0]
	s.run(90 * time.Second)
	if f.State() != FOK {
		t.Fatalf("healthy: %s (%s)", f.State(), f.sm.reason)
	}
	mode = "dead"
	s.run(4 * cfg.AppInterval)
	if f.State() != FDown || f.sm.reason != ReasonAppDown || f.sm.tcpDown || f.C.Failures() != 0 {
		t.Fatalf("application dead: %s (%s), TCP down %v, TCP failures %d, checks failed in a row %d", f.State(), f.sm.reason, f.sm.tcpDown, f.C.Failures(), f.sm.appFails)
	}
	// Told at the highest level that describes it (here the endpoint), with
	// the flow's own transition.
	trans := func(k EventKind) (n int) {
		for _, e := range s.events {
			for _, fr := range e.Flows {
				if fr.Transition == k || (fr.Transition == EvNone && e.Type == k) {
					n++
				}
			}
		}
		return n
	}
	// Nothing is wrong with the path: no extra traces, and the localization
	// says the application fails, it names no segment.
	if ep.loc.Level != LocApplication || len(ep.loc.SuspectedSegments) != 0 || ep.incident != nil || f.C.SkipBy[SkipIncident] != 0 {
		t.Fatalf("application dead: localization %s %v, incident %v, slots given to incident traces %d", ep.loc.Level, ep.loc.SuspectedSegments, ep.incident != nil, f.C.SkipBy[SkipIncident])
	}
	downs, recs := trans(EvFlowDown), s.count(EvFlowRecovered)
	if downs != 1 || recs != 0 {
		t.Fatalf("FLOW_DOWN %d, FLOW_RECOVERED %d after the application died", downs, recs)
	}
	mode = "ok"
	s.run(3 * cfg.AppInterval)
	// (a flow's recovery is always told on its own too)
	if f.State() == FDown || s.count(EvFlowRecovered) != 1 {
		t.Fatalf("application back: %s (%s), FLOW_RECOVERED %d", f.State(), f.sm.reason, s.count(EvFlowRecovered))
	}
	mode, n = "flaky", 0
	s.run(5 * time.Minute)
	w := f.win.sum(s.c.bucketNum(s.c.now), WindowLong)
	if f.State() != FLoss || w.Failures() != 0 || w.AppFail == 0 || w.AppFail == w.App {
		t.Fatalf("one check in four failing: %s (%s), TCP failures %d, app %d of %d", f.State(), f.sm.reason, w.Failures(), w.AppFail, w.App)
	}
	if snap := winSnap(w); snap.FailureRate == nil || *snap.FailureRate != 0 || snap.AppFailRate == nil || *snap.AppFailRate < 0.15 || *snap.AppFailRate > 0.35 {
		t.Fatalf("rates: TCP %v, application %v", snap.FailureRate, snap.AppFailRate)
	}
}

// Servers the balancer gives few ports to (about 1 port in 400) are found:
// the census goes on while answers on clocks nobody has keep coming. And
// no application check runs while the census floods the address.
func TestAnycastLightServers(t *testing.T) {
	const heavy = 20
	type srv struct {
		hz  float64
		off uint32
	}
	servers := make([]srv, heavy+2)
	for i := range servers {
		hz := 1000.0
		if i%3 == 0 {
			hz = 250
		}
		servers[i] = srv{hz: hz, off: uint32(i)*97_000_003 + 12345}
	}
	srvOf := func(sport wire.Port) int {
		h := (uint32(sport) * 2654435761) >> 7
		switch h % 1000 {
		case 0, 1, 2:
			return heavy
		case 3, 4, 5:
			return heavy + 1
		}
		return int(h/1000) % heavy
	}
	p := linear(4, 30*time.Millisecond)
	cfg := simpleCfg()
	cfg.Flows = 1
	cfg.Discovery = true
	cfg.Anycast = true
	cfg.EndpointPPS = 500
	cfg.App, cfg.AppInterval, cfg.AppTimeout = true, 5*time.Second, 2*time.Second
	s := newSim(t, cfg, func(*Flow, Mono) *simPath { return p })
	s.serverTS = func(f *Flow, rt int64) uint32 {
		sv := servers[srvOf(f.SPort())]
		return (sv.off+uint32(int64(float64(rt)*sv.hz/1e9)))&^63 | 23
	}
	ep := s.add(2048)
	for i := 0; i < 1200 && ep.ac.status == ACRunning; i++ {
		s.run(100 * time.Millisecond)
		if s.appCalls > 0 {
			t.Fatalf("application check during the census (explored %d)", ep.ac.explored)
		}
	}
	s.run(time.Minute)
	a := ep.ac
	if a.status != ACDone || len(a.servers) != heavy+2 {
		t.Fatalf("status %s servers %d of %d (explored %d)", a.status, len(a.servers), heavy+2, a.explored)
	}
	if s.appCalls == 0 {
		t.Fatal("no application checks after the census")
	}
}

// A server reached through two routes appears under both, and each row
// shows only the ports of its own route (not the server's total).
func TestAnycastServerPerRoute(t *testing.T) {
	const n = 3
	arms := make([]*simPath, 2)
	for i := range arms {
		arms[i] = &simPath{rtt: time.Duration(20+20*i) * time.Millisecond, hops: []simHop{
			{addr: a4("10.0.0.1"), rtt: time.Millisecond},
			{addr: netip.AddrFrom4([4]byte{10, 1, byte(i), 1}), rtt: 3 * time.Millisecond},
			{addr: a4("10.3.0.1"), rtt: 6 * time.Millisecond},
		}}
	}
	armOf := func(sport wire.Port) int { return int((uint32(sport)*2654435761)>>7) % 2 }
	// One heavy server takes most ports, so both routes' first ports reach it.
	srvOf := func(sport wire.Port) int { return max(0, int((uint32(sport)*40503)>>5)%10-7) }
	cfg := simpleCfg()
	cfg.Flows = 1
	cfg.Discovery = true
	cfg.Anycast = true
	cfg.EndpointPPS = 500
	s := newSim(t, cfg, func(f *Flow, _ Mono) *simPath { return arms[armOf(f.SPort())] })
	s.serverTS = func(f *Flow, rt int64) uint32 {
		return uint32(srvOf(f.SPort()))*97_000_003 + 12345 + uint32(rt/1e6)
	}
	ep := s.add(512)
	s.run(2 * time.Minute)
	if got := len(ep.ac.servers); got != n {
		t.Fatalf("%d servers", got)
	}
	var route string
	under := map[string]int{}
	for _, r := range s.c.Snapshot(SnapOpts{Tree: true, Only: AllEndpoints}).Endpoints[0].Tree {
		if r.Group != nil {
			route = r.Group.ID
			continue
		}
		if r.Hop.Kind != KindServer {
			continue
		}
		under[r.Hop.Server]++
		if len(r.SPorts) == 0 {
			t.Fatalf("server row %s under %s has no port", r.Hop.Server, route)
		}
		var sent uint32
		for _, sp := range r.SPorts {
			f := flowBySport(ep, sp)
			if f.group == nil || f.group.ID != route {
				t.Fatalf("server row %s under route %s shows sport %d of another route", r.Hop.Responder, route, sp)
			}
			sent += uint32(f.C.Sent)
		}
		if r.Hop.Sent > sent {
			t.Fatalf("server row %s under %s: %d probes, its ports sent %d", r.Hop.Responder, route, r.Hop.Sent, sent)
		}
	}
	two := 0
	for _, k := range under {
		if k > 1 {
			two++
		}
	}
	if two == 0 {
		for _, f := range ep.Flows {
			if f.Role.Monitored() {
				g := ""
				if f.group != nil {
					g = f.group.ID
				}
				t.Logf("%s sport %d group %s server %v arm %d", f.Name(), f.SPort(), g, ep.ServerOf(f.SPort()), armOf(f.SPort()))
			}
		}
		t.Fatalf("no server under two routes: %v (groups %d)", under, len(ep.groups))
	}
}

// A census SYN that never gets its turn (here: its port turns invalid while
// the SYN is due) is given up by the watchdog, so the census still ends.
func TestAnycastCensusWatchdog(t *testing.T) {
	p := linear(3, 20*time.Millisecond)
	cfg := simpleCfg()
	cfg.Flows = 1
	cfg.Discovery = true
	cfg.Anycast = true
	cfg.EndpointPPS = 500
	s := newSim(t, cfg, func(*Flow, Mono) *simPath { return p })
	s.serverTS = func(f *Flow, rt int64) uint32 { return uint32(f.SPort()%2)*97_000_003 + uint32(rt/1e6) }
	ep := s.add(1024)
	var lost *Flow
	for i := 0; i < 600 && lost == nil; i++ {
		s.run(50 * time.Millisecond)
		for _, f := range ep.Flows {
			if f.census && f.active == nil && !f.Role.Monitored() {
				f.invalid = InvalidLocalRoute // hopClass refuses it from now on
				lost = f
				break
			}
		}
	}
	if lost == nil {
		t.Fatal("no census SYN was ever due")
	}
	s.run(3 * time.Minute)
	if ep.ac.status == ACRunning {
		t.Fatalf("census still running: inflight %d, %s still due %v", ep.ac.inflight, lost.Name(), lost.census)
	}
	if ep.ac.stuck == 0 || ep.ac.inflight != 0 {
		t.Fatalf("stuck %d inflight %d", ep.ac.stuck, ep.ac.inflight)
	}
}

// A route whose measured port is only a tentative member (a hop of its
// trace went quiet) keeps its verdict and still counts as measured.
func TestTentativeMeasuredKeepsRoute(t *testing.T) {
	arms := make([]*simPath, 2)
	for i := range arms {
		arms[i] = &simPath{rtt: 20 * time.Millisecond, hops: []simHop{
			{addr: a4("10.0.0.1"), rtt: time.Millisecond},
			{addr: netip.AddrFrom4([4]byte{10, 1, byte(i), 1}), rtt: 3 * time.Millisecond},
			{addr: a4("10.3.0.1"), rtt: 6 * time.Millisecond},
		}}
	}
	armOf := func(sport wire.Port) int { return int((uint32(sport)*2654435761)>>7) % 2 }
	cfg := simpleCfg()
	cfg.Flows = 1
	cfg.Discovery = true
	s := newSim(t, cfg, func(f *Flow, _ Mono) *simPath { return arms[armOf(f.SPort())] })
	ep := s.add(256)
	s.run(2 * time.Minute)
	var g *Group
	for _, x := range ep.groups {
		if x.Level == LevelConfirmed && x.State == GOK && len(x.measured()) == 1 {
			g = x
			break
		}
	}
	if g == nil || ep.coverage.Incomplete {
		t.Fatalf("setup: no measured OK route (coverage %+v)", ep.coverage)
	}
	f := g.measured()[0]
	g.Members = slices.DeleteFunc(g.Members, func(x *Flow) bool { return x == f })
	g.Tentative = append(g.Tentative, f)
	f.level = LevelTentative
	c := s.c
	c.evalGroups(ep)
	c.evalEndpoint(ep)
	if g.State != GOK {
		t.Fatalf("route state %s with its measured port tentative", g.State)
	}
	if ep.coverage.Incomplete {
		t.Fatalf("coverage %+v", ep.coverage)
	}
}

// Routes that differ only after a run of silent routers: a port measured
// for its server (never traced by discovery) must still trace through the
// silent run to the destination and join its route.
func TestCensusPortTracesPastSilentHops(t *testing.T) {
	const n = 40
	arms := make([]*simPath, 2)
	for i := range arms {
		p := &simPath{rtt: 30 * time.Millisecond}
		p.hops = append(p.hops, simHop{addr: a4("10.0.0.1"), rtt: time.Millisecond}, simHop{addr: a4("10.0.1.1"), rtt: 2 * time.Millisecond})
		for k := 0; k < 4; k++ {
			p.hops = append(p.hops, simHop{addr: netip.AddrFrom4([4]byte{10, 9, byte(k), 1}), silent: true, rtt: 5 * time.Millisecond})
		}
		p.hops = append(p.hops, simHop{addr: netip.AddrFrom4([4]byte{10, 7, byte(i), 1}), rtt: 20 * time.Millisecond})
		arms[i] = p
	}
	armOf := func(sport wire.Port) int { return int((uint32(sport)*2654435761)>>7) % 2 }
	srvOf := func(sport wire.Port) int { return int((uint32(sport)*40503)>>5) % n }
	cfg := simpleCfg()
	cfg.Flows = 1
	cfg.Discovery = true
	cfg.Anycast = true
	cfg.EndpointPPS = 500
	s := newSim(t, cfg, func(f *Flow, _ Mono) *simPath { return arms[armOf(f.SPort())] })
	s.serverTS = func(f *Flow, rt int64) uint32 { return uint32(srvOf(f.SPort()))*97_000_003 + uint32(rt/1e6) }
	ep := s.add(1024)
	s.run(4 * time.Minute)
	if ep.ac.status != ACDone || len(ep.ac.servers) != n {
		t.Fatalf("census %s, %d servers", ep.ac.status, len(ep.ac.servers))
	}
	late := 0
	for _, f := range ep.Flows {
		if !f.Role.Monitored() {
			continue
		}
		if int(f.SPort()-ep.ports[0]) > ep.disc.explored+8 {
			late++ // measured for its server, never traced by discovery
		}
		if f.route.distance != TTL(len(arms[0].hops)+1) || f.group == nil {
			t.Fatalf("%s (sport %d): distance %d, group %v", f.Name(), f.SPort(), f.route.distance, f.group != nil)
		}
	}
	if late == 0 {
		t.Fatal("setup: every measured port was traced by discovery")
	}
}

// Discovery candidates left half-traced when discovery stopped are not
// listed as "not yet assigned": nothing probes them any more. Measured
// ports still are.
func TestUnresolvedOnlyWhileProbed(t *testing.T) {
	s, ep := groupingCore(t)
	obsFlow(s.c, ep, []string{"10.0.0.1", "10.0.0.2", "10.0.0.5"}, 4)
	obsFlow(s.c, ep, []string{"10.0.0.1", "10.0.0.3", "10.0.0.5"}, 4)
	left := obsFlow(s.c, ep, []string{"10.0.0.1", "*", "10.0.0.5"}, 4)
	meas := obsFlow(s.c, ep, []string{"10.0.0.1", "*", "10.0.0.5"}, 4)
	left.Role, meas.Role = RoleCandidate, RoleActive
	s.c.regroup(ep)
	e := s.c.epSnap(ep, false, false)
	if len(e.Unresolved) != 1 || e.Unresolved[0].Flow != meas.Name() {
		t.Fatalf("unresolved %+v, want only the measured %s", e.Unresolved, meas.Name())
	}
}

// Routes of different lengths: parallel TTLs are sent below the shortest
// length known so far, and a port whose own path is shorter still gets its
// destination's answers to several of them at once. Its length is the
// lowest TTL the destination answered at, and nothing about the port is
// spoiled by the extra answers.
func TestParallelTTLOnShorterRoute(t *testing.T) {
	long := linear(12, 2*time.Millisecond)
	short := []*simPath{linear(5, 150*time.Millisecond), linear(5, 150*time.Millisecond)}
	short[1].hops[1].addr = netip.MustParseAddr("10.9.1.1")
	long.hops[1].addr = netip.MustParseAddr("10.9.2.1")
	// The first port takes the long route, and that route answers fastest:
	// its length is the one known when the others are traced.
	pathOf := func(f *Flow, _ Mono) *simPath {
		if f.ID%3 == 0 {
			return long
		}
		return short[f.ID%2]
	}
	cfg := simpleCfg()
	cfg.Flows = 1
	cfg.Discovery = true
	s := newSim(t, cfg, pathOf)
	ep := s.add(64)
	for step := 0; step < 600 && !ep.disc.stopped; step++ {
		s.run(100 * time.Millisecond)
	}
	if !ep.disc.stopped || ep.branches() != 3 {
		t.Fatalf("stopped %v, routes %d: %s", ep.disc.stopped, ep.branches(), groupsDump(ep))
	}
	reached := 0
	for _, f := range ep.Flows {
		if f.route.distance == 0 {
			continue
		}
		want := TTL(len(pathOf(f, 0).hops) + 1)
		if f.route.distance != want {
			t.Fatalf("%s: distance %d, its path has %d", f.Name(), f.route.distance, want)
		}
		if f.invalid != ValidFlow {
			t.Fatalf("%s invalid: %s", f.Name(), f.invalid)
		}
		reached++
	}
	if reached < 10 {
		t.Fatalf("only %d ports traced to the destination", reached)
	}
	s.run(time.Minute)
	for _, f := range monitored(ep) {
		if f.State() != FOK || f.C.Unexpected != 0 || f.C.Weak != 0 {
			t.Fatalf("%s: %s (%s), unexpected %d, weak %d", f.Name(), f.State(), f.sm.reason, f.C.Unexpected, f.C.Weak)
		}
	}
}

// A hop a port got no answer at, filled with the router the other ports
// saw there, is marked: the port did not see that router itself.
func TestAssumedHopsAreMarked(t *testing.T) {
	s, ep := groupingCore(t)
	var seen []*Flow
	for i := 0; i < 3; i++ {
		seen = append(seen, obsFlow(s.c, ep, []string{"10.0.0.1", "10.1.0.1", "10.3.0.1"}, 4))
	}
	y := obsFlow(s.c, ep, []string{"?", "10.1.0.1", "10.3.0.1"}, 4)
	s.c.regroup(ep)
	if y.level != LevelConfirmed || !slices.Equal(y.sig.assumed, []TTL{1}) {
		t.Fatalf("level %s, assumed %v", y.level, y.sig.assumed)
	}
	for _, f := range seen {
		if len(f.sig.assumed) != 0 {
			t.Fatalf("%s saw every hop itself, assumed %v", f.Name(), f.sig.assumed)
		}
	}
	if fs := s.c.flowSnap(y, false); !slices.Equal(fs.AssumedHops, []TTL{1}) {
		t.Fatalf("snapshot: assumed_hops %v", fs.AssumedHops)
	}
}

// A server the census found and that then stops answering is a server
// that is DOWN. It is not taken off the list: no answer says it was never
// there.
func TestAnycastServerDiesAfterCensus(t *testing.T) {
	const n = 5
	srvOf := func(sport wire.Port) int { return int((uint32(sport)*2654435761)>>9) % n }
	p, gone := linear(4, 30*time.Millisecond), linear(4, 30*time.Millisecond)
	gone.loss = 1
	dead := -1
	cfg := simpleCfg()
	cfg.Flows = 1
	cfg.Discovery = true
	cfg.Anycast = true
	cfg.EndpointPPS = 500
	s := newSim(t, cfg, func(f *Flow, _ Mono) *simPath {
		if srvOf(f.SPort()) == dead {
			return gone
		}
		return p
	})
	s.serverTS = func(f *Flow, rt int64) uint32 {
		return uint32(srvOf(f.SPort()))*97_000_003 + 12345 + uint32(rt/1e6)
	}
	ep := s.add(512)
	for step := 0; step < 600 && ep.ac.status != ACDone; step++ {
		s.run(100 * time.Millisecond)
	}
	a := ep.ac
	if a.status != ACDone || len(a.servers) != n {
		t.Fatalf("census: %s, %d servers", a.status, len(a.servers))
	}
	// It dies before its measured port got one answer in the measuring phase.
	var victim *Server
	for _, sv := range a.servers {
		if !sv.confirmed {
			victim = sv
			break
		}
	}
	if victim == nil {
		victim = a.servers[n-1]
	}
	dead = srvOf(victim.ports[0])
	s.run(time.Minute)
	if !slices.Contains(a.servers, victim) || a.phantoms != 0 {
		t.Fatalf("the dead server left the list (dropped as artefacts: %d)", a.phantoms)
	}
	fs := s.c.measuredOf(ep, victim)
	if len(fs) == 0 {
		t.Fatalf("the dead server has no measured port")
	}
	for _, f := range fs {
		if f.State() != FDown {
			t.Fatalf("%s of the dead server: %s (%s)", f.Name(), f.State(), f.sm.reason)
		}
	}
}

// TCP and the application each come back on their own: TCP answering again
// does not end a DOWN the application still holds, and the application
// passing again leaves the TCP loss to be judged as loss.
func TestAppAndTCPRecoverApart(t *testing.T) {
	p := linear(3, 20*time.Millisecond)
	cfg := simpleCfg()
	cfg.Flows = 1
	cfg.App, cfg.AppInterval, cfg.AppTimeout = true, 5*time.Second, 2*time.Second
	s := newSim(t, cfg, func(*Flow, Mono) *simPath { return p })
	appDead := false
	s.appFn = func(f *Flow) (AppResult, time.Duration) {
		if appDead {
			return AppResult{Outcome: AppFailed, ConnectRTT: 20 * time.Millisecond, Stage: "answer", Err: "eof"}, 200 * time.Millisecond
		}
		return AppResult{Outcome: AppPassed, ConnectRTT: 20 * time.Millisecond}, 200 * time.Millisecond
	}
	ep := s.add(1)
	f := ep.Flows[0]
	s.run(90 * time.Second)
	appDead = true
	s.run(4 * cfg.AppInterval)
	if f.State() != FDown || f.sm.reason != ReasonAppDown {
		t.Fatalf("application dead: %s (%s)", f.State(), f.sm.reason)
	}
	p.loss = 1
	s.run(30 * time.Second)
	if f.State() != FDown || !f.sm.tcpDown || f.sm.reason == ReasonAppDown {
		t.Fatalf("TCP dead too: %s (%s), TCP down %v", f.State(), f.sm.reason, f.sm.tcpDown)
	}
	p.loss = 0
	s.run(30 * time.Second)
	if f.State() != FDown || f.sm.tcpDown || f.sm.reason != ReasonAppDown || s.count(EvFlowRecovered) != 0 {
		t.Fatalf("TCP back, application still dead: %s (%s), TCP down %v, FLOW_RECOVERED %d", f.State(), f.sm.reason, f.sm.tcpDown, s.count(EvFlowRecovered))
	}
	// The application comes back onto a path that loses a fifth of the SYNs.
	p.loss = 0.2
	appDead = false
	s.run(6 * time.Minute)
	w := f.win.sum(s.c.bucketNum(s.c.now), WindowLong)
	if f.State() != FLoss || f.sm.appDown || f.sm.lossByApp || w.AppFail != 0 {
		t.Fatalf("application back, TCP losing: %s (%s), app down %v, loss by app %v, checks failed %d of %d", f.State(), f.sm.reason, f.sm.appDown, f.sm.lossByApp, w.AppFail, w.App)
	}
}

// anycastSim runs a census over n simulated servers; owner says which of
// them a port reaches (and may change during the test).
func anycastSim(t *testing.T, n, ports int, owner func(wire.Port) int) (*simNet, *Endpoint) {
	p := linear(4, 30*time.Millisecond)
	cfg := simpleCfg()
	cfg.Flows = 1
	cfg.Discovery = true
	cfg.Anycast = true
	cfg.EndpointPPS = 500
	s := newSim(t, cfg, func(*Flow, Mono) *simPath { return p })
	s.serverTS = func(f *Flow, rt int64) uint32 {
		return uint32(owner(f.SPort()))*97_000_003 + 12345 + uint32(rt/1e6)
	}
	ep := s.add(ports)
	for step := 0; step < 600 && ep.ac.status != ACDone; step++ {
		s.run(100 * time.Millisecond)
	}
	if ep.ac.status != ACDone || len(ep.ac.servers) != n {
		t.Fatalf("census: %s, %d servers", ep.ac.status, len(ep.ac.servers))
	}
	s.run(5 * time.Second) // every server confirmed by its measured port
	return s, ep
}

// spare returns up to k ports of sv that are traced and not measured.
func spare(ep *Endpoint, sv *Server, k int) (out []wire.Port) {
	for _, p := range sv.ports {
		if f := ep.byPort[p]; f != nil && f.Role == RoleCandidate && f.invalid == ValidFlow && len(out) < k {
			out = append(out, p)
		}
	}
	return out
}

// give makes the census's record say that the ports belong to sv.
func give(a *anycastState, sv *Server, ports ...wire.Port) {
	for _, p := range ports {
		if old := a.portSrv[p]; old != nil {
			old.ports = slices.DeleteFunc(old.ports, func(q wire.Port) bool { return q == p })
		}
		a.portSrv[p] = sv
		sv.ports = append(sv.ports, p)
	}
	slices.Sort(sv.ports)
}

// A clock the census made up out of two servers' answers: its ports are
// measured one after another, each goes to the server it really reaches,
// and with the last of them the made-up server is gone.
func TestAnycastMadeUpServerDissolves(t *testing.T) {
	const n = 4
	srvOf := func(p wire.Port) int { return int((uint32(p)*2654435761)>>9) % n }
	s, ep := anycastSim(t, n, 256, srvOf)
	a := ep.ac
	x, y := a.servers[0], a.servers[1]
	px, py := spare(ep, x, 2), spare(ep, y, 1)
	if len(px) < 2 || len(py) < 1 {
		t.Fatalf("spare ports: %d and %d", len(px), len(py))
	}
	ph := &Server{ID: 999, Hz: 1000, Offset: x.Offset + 1<<30}
	a.servers = append(a.servers, ph)
	give(a, ph, px[0], py[0], px[1])
	s.c.acAssign(ep)
	s.run(4 * time.Second)
	if !slices.Contains(a.servers, ph) || len(ph.ports) != 2 {
		t.Fatalf("after its first port left: listed %v, ports %v", slices.Contains(a.servers, ph), ph.ports)
	}
	s.run(15 * time.Second)
	if slices.Contains(a.servers, ph) || a.phantoms != 1 || len(a.servers) != n {
		t.Fatalf("made-up server kept: listed %v, dropped %d, servers %d", slices.Contains(a.servers, ph), a.phantoms, len(a.servers))
	}
	if a.portSrv[px[0]] != x || a.portSrv[px[1]] != x || a.portSrv[py[0]] != y {
		t.Fatalf("its ports did not go to the servers they reach")
	}
}

// A real server whose lowest port is not its own (the census put it there,
// or the balancer moved it since): the port goes where it belongs, and the
// server is measured through its next port and stays.
func TestAnycastServerSurvivesOneForeignPort(t *testing.T) {
	const n = 4
	srvOf := func(p wire.Port) int { return int((uint32(p)*2654435761)>>9) % n }
	s, ep := anycastSim(t, n, 256, srvOf)
	a := ep.ac
	r, q := a.servers[0], a.servers[1]
	// r as it is before anything confirmed it, with a port of q as its lowest.
	for _, f := range s.c.measuredOf(ep, r) {
		s.c.deactivate(f)
		r.ports = slices.DeleteFunc(r.ports, func(p wire.Port) bool { return p == f.SPort() })
		delete(a.portSrv, f.SPort())
	}
	r.confirmed = false
	var foreign wire.Port
	for _, p := range spare(ep, q, 64) {
		if own := spare(ep, r, 1); len(own) == 1 && p < own[0] {
			foreign = p
			break
		}
	}
	if foreign == 0 {
		t.Skip("no port of the other server below this server's ports")
	}
	give(a, r, foreign)
	s.c.acAssign(ep)
	if fs := s.c.measuredOf(ep, r); len(fs) != 1 || fs[0].SPort() != foreign {
		t.Fatalf("the foreign port is not the one measured for the server")
	}
	s.run(10 * time.Second)
	if !slices.Contains(a.servers, r) || a.phantoms != 0 {
		t.Fatalf("a real server was dropped over one foreign port (dropped %d)", a.phantoms)
	}
	fs := s.c.measuredOf(ep, r)
	if a.portSrv[foreign] != q || !r.confirmed || len(fs) != 1 || srvOf(fs[0].SPort()) != srvOf(r.ports[0]) {
		t.Fatalf("foreign port moved %v, server confirmed %v, measured ports %d", a.portSrv[foreign] == q, r.confirmed, len(fs))
	}
}

// A server leaves the balancer's pool before it was measured and its ports
// go to the others: it is dropped when the last of its ports has shown
// that, not sooner.
func TestAnycastServerLeavesPool(t *testing.T) {
	const n = 4
	gone := -1
	srvOf := func(p wire.Port) int {
		k := int((uint32(p)*2654435761)>>9) % n
		if k == gone {
			k = (k + 1 + int(p)%(n-1)) % n
		}
		return k
	}
	s, ep := anycastSim(t, n, 64, srvOf)
	a := ep.ac
	v := a.servers[n-1]
	left := len(spare(ep, v, 64))
	if left < 2 {
		t.Fatalf("the server has %d spare ports", left)
	}
	v.confirmed = false
	gone = int((uint32(v.ports[0])*2654435761)>>9) % n
	s.run(4 * time.Second)
	if !slices.Contains(a.servers, v) {
		t.Fatalf("dropped after its first port, with %d more to ask", left)
	}
	s.run(time.Duration(left+2) * 4 * time.Second)
	if slices.Contains(a.servers, v) || a.phantoms != 1 || len(a.servers) != n-1 {
		t.Fatalf("still listed %v after every port answered as another server (ports left %v, dropped %d)", slices.Contains(a.servers, v), v.ports, a.phantoms)
	}
}
