package core

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/hotid/mpmtr/internal/wire"
)

// The route tree, whatever the network looks like: every row hangs under a
// row before it (or at the top), every route found ends in exactly one DST
// row, no two rows have the same name, and a row's name extends its
// parent's — the tree is built from the routes' typed elements, and its
// names still read as paths.
func TestTreeStructure(t *testing.T) {
	ad := func(x ...byte) netip.Addr { return netip.AddrFrom4([4]byte(x)) }
	silent := func(sport wire.Port) *simPath {
		p := fanPath(sport)
		p.hops[1].silent, p.hops[2].silent = true, true // two hops in a row never answer
		return p
	}
	direct := func(wire.Port) *simPath { return &simPath{rtt: 300 * time.Microsecond} } // the destination is the first hop
	oneSilent := func(sport wire.Port) *simPath {
		return &simPath{rtt: 500 * time.Microsecond, hops: []simHop{
			{addr: ad(10, 0, 0, 1), rtt: 100 * time.Microsecond},
			{addr: ad(10, 0, 1, byte(1+sport%2)), rtt: 200 * time.Microsecond, silent: sport%2 == 0},
		}}
	}
	for _, tc := range []struct {
		name   string
		path   func(wire.Port) *simPath
		routes int // 0: not checked
	}{
		{"a fan of 32 routes", fanPath, 32},
		{"two silent hops in a row", silent, 0},
		{"destination directly connected", direct, 1},
		{"one arm with a silent hop", oneSilent, 0},
	} {
		cfg := simpleCfg()
		cfg.Flows, cfg.Discovery = 1, true
		s := newSim(t, cfg, func(f *Flow, _ Mono) *simPath { return tc.path(f.SPort()) })
		ep := s.add(256)
		s.run(4 * time.Minute)
		rows := s.c.Snapshot(SnapOpts{Tree: true, Only: AllEndpoints}).Endpoints[0].Tree
		if len(rows) == 0 {
			t.Fatalf("%s: no tree", tc.name)
		}
		seen := map[string]bool{}
		dst := map[string]int{}
		for i, r := range rows {
			if r.Parent < -1 || r.Parent >= i {
				t.Fatalf("%s: row %d (%s) hangs under row %d", tc.name, i, r.Path, r.Parent)
			}
			if seen[r.Path] {
				t.Errorf("%s: two rows are named %s", tc.name, r.Path)
			}
			seen[r.Path] = true
			if r.Parent >= 0 && !strings.HasPrefix(r.Path, rows[r.Parent].Path+">") {
				t.Errorf("%s: row %s hangs under %s, whose name it does not extend", tc.name, r.Path, rows[r.Parent].Path)
			}
			if r.Parent == -1 && strings.Count(r.Path, ">") != 1 && r.Hop.Kind != KindDst && r.Hop.Replies > 0 {
				t.Errorf("%s: an answering top row is named %s", tc.name, r.Path)
			}
			if r.Hop.Kind == KindDst {
				if r.Group == nil {
					t.Fatalf("%s: a DST row without its route", tc.name)
				}
				dst[r.Group.ID]++
			} else if r.Group != nil {
				t.Errorf("%s: row %s is not a DST row but carries a route", tc.name, r.Path)
			}
			// Below agrees with the parents.
			if r.Parent >= 0 && !Below(rows, i, r.Parent) {
				t.Errorf("%s: row %d is not below its parent %d", tc.name, i, r.Parent)
			}
			if Below(rows, i, i) {
				t.Errorf("%s: row %d is below itself", tc.name, i)
			}
		}
		shown := 0
		for _, g := range ep.groups {
			if len(g.Sig.hops) == 0 && !g.Sig.distKnown {
				continue // nothing known of it yet: not in the tree
			}
			shown++
			if dst[g.ID] != 1 {
				t.Errorf("%s: route %s (%s) has %d DST rows", tc.name, g.ID, g.Sig.canon, dst[g.ID])
			}
		}
		if len(dst) != shown {
			t.Errorf("%s: %d DST rows for %d routes", tc.name, len(dst), shown)
		}
		if tc.routes > 0 && shown != tc.routes {
			t.Errorf("%s: %d routes in the tree, want %d", tc.name, shown, tc.routes)
		}
		// A directly connected destination has no hop row above its DST.
		if tc.name == "destination directly connected" && (len(rows) != 1 || rows[0].Hop.Kind != KindDst || rows[0].Hop.TTL != 1) {
			t.Errorf("%s: rows %+v", tc.name, rows)
		}
	}
}

// Loss and slow answers on a hop are marked only when they go on to the
// destination, on every branch under the hop.
func TestMarkDownstream(t *testing.T) {
	hop := func(sent, replies uint32, up bool) *HopSnap {
		return &HopSnap{Kind: KindHop, Sent: sent, Replies: replies, rttKnown: true, rttUp: up}
	}
	dst := func(loss, up bool) *HopSnap {
		return &HopSnap{Kind: KindDst, Sent: 100, Replies: 100, LossPersists: loss, RTTShift: up}
	}
	// One path: 1 fine, 2 loses and is slow, 3 too (silent 4 between), DST too.
	rows := []*HopSnap{hop(100, 100, false), hop(100, 60, true), hop(100, 70, true), {Kind: KindSilent, Sent: 20}, dst(true, true)}
	markDownstream(rows, []int{-1, 0, 1, 2, 3})
	for i, want := range []bool{false, true, true, false} {
		if rows[i].LossPersists != want || rows[i].RTTShift != want {
			t.Errorf("path hop %d: loss %v rtt %v, want %v", i+1, rows[i].LossPersists, rows[i].RTTShift, want)
		}
	}
	// A hop that loses while the next one does not: its router answers
	// poorly, nothing is marked, also when the destination loses.
	rows = []*HopSnap{hop(100, 50, true), hop(100, 100, false), dst(true, true)}
	markDownstream(rows, []int{-1, 0, 1})
	if rows[0].LossPersists || rows[0].RTTShift {
		t.Errorf("rate-limiting hop marked: %+v", *rows[0])
	}
	// The destination is fine: nothing above it is marked.
	rows = []*HopSnap{hop(100, 50, true), hop(100, 50, true), dst(false, false)}
	markDownstream(rows, []int{-1, 0, 1})
	if rows[0].LossPersists || rows[1].LossPersists || rows[1].RTTShift {
		t.Errorf("marked above a healthy destination")
	}
	// A hop with two branches, only one of them losing to its destination:
	// the fault is on that branch, not on the shared hop.
	rows = []*HopSnap{hop(100, 60, true), hop(100, 60, true), dst(true, true), hop(100, 100, false), dst(false, false)}
	markDownstream(rows, []int{-1, 0, 1, 0, 3})
	if rows[0].LossPersists || rows[0].RTTShift || !rows[1].LossPersists || !rows[1].RTTShift {
		t.Errorf("branches: shared %v/%v, losing branch %v/%v", rows[0].LossPersists, rows[0].RTTShift, rows[1].LossPersists, rows[1].RTTShift)
	}
	// Too few probes on a hop: it neither confirms nor breaks the chain.
	rows = []*HopSnap{hop(100, 60, true), {Kind: KindHop, Sent: 3, Replies: 1}, dst(true, true)}
	markDownstream(rows, []int{-1, 0, 1})
	if !rows[0].LossPersists || rows[1].LossPersists {
		t.Errorf("thin hop: %v %v", rows[0].LossPersists, rows[1].LossPersists)
	}
}

// End to end on the simulated network: a hop that becomes slow, with the
// hops after it and the destination, marks those rows as slower than they
// were; a hop that only answers its own ICMP slowly marks nothing.
func TestTreeMarksSlowSegment(t *testing.T) {
	cfg := simpleCfg()
	cfg.Discovery = true
	cfg.Flows = 1
	p := linear(4, 10*time.Millisecond)
	for i := range p.hops {
		p.hops[i].rtt = time.Duration(i+1) * 2 * time.Millisecond
	}
	s := newSim(t, cfg, func(*Flow, Mono) *simPath { return p })
	s.add(4)
	rowsOf := func() []TreeRow { return s.c.Snapshot(SnapOpts{Tree: true, Only: AllEndpoints}).Endpoints[0].Tree }
	s.run(3 * time.Minute)
	for _, r := range rowsOf() {
		if r.Hop.RTTShift || r.Hop.RTTSpike || r.Hop.LossPersists {
			t.Fatalf("marked on a steady path: %+v", r.Hop)
		}
	}
	// From hop 3 on everything takes 40 ms longer.
	p.hops[2].rtt += 40 * time.Millisecond
	p.hops[3].rtt += 40 * time.Millisecond
	p.rtt += 40 * time.Millisecond
	s.run(15 * time.Second)
	marked := map[TTL]bool{}
	for _, r := range rowsOf() {
		if r.Hop.Kind == KindHop || r.Hop.Kind == KindDst {
			marked[r.Hop.TTL] = r.Hop.RTTShift
		}
	}
	if marked[1] || marked[2] || !marked[3] || !marked[4] || !marked[5] {
		t.Fatalf("rows marked slower: %v, want TTL 3, 4 and the destination (5)", marked)
	}

	// On a second endpoint, hop 2 alone answers 40 ms later (its own ICMP is
	// slow), traffic through it is not: nothing is marked.
	q := linear(4, 10*time.Millisecond)
	s2 := newSim(t, cfg, func(*Flow, Mono) *simPath { return q })
	s2.add(4)
	s2.run(3 * time.Minute)
	q.hops[1].rtt += 40 * time.Millisecond
	s2.run(15 * time.Second)
	for _, r := range s2.c.Snapshot(SnapOpts{Tree: true, Only: AllEndpoints}).Endpoints[0].Tree {
		if r.Hop.RTTShift {
			t.Fatalf("slow ICMP of one hop marked TTL %d", r.Hop.TTL)
		}
	}
	// Without the later hops: the hop itself would be up.
	var up bool
	for _, r := range s2.c.Snapshot(SnapOpts{Tree: true, Only: AllEndpoints}).Endpoints[0].Tree {
		if r.Hop.TTL == 2 && r.Hop.Kind == KindHop {
			up = r.Hop.rttUp
		}
	}
	if !up {
		t.Fatal("hop 2 not seen as slower than before: the test proves nothing")
	}
}
