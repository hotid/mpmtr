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
