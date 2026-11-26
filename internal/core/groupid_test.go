package core

import (
	"net/netip"
	"testing"
	"time"
)

// Two different routes whose short identifiers are the same stay two
// routes. The identifier is 20 bits of a hash of the signature: with a few
// hundred routes some pair shares it every now and then (276 routes: 3.5%
// of runs). This pair was found by search; the routes differ in two hops.
func TestRoutesWithTheSameShortIDStayApart(t *testing.T) {
	sigA := "10.0.0.1>10.1.15.1>10.2.158.1>DST"
	sigB := "10.0.0.1>10.1.23.1>10.2.124.1>DST"
	if groupID(LevelConfirmed, sigA) != groupID(LevelConfirmed, sigB) {
		t.Fatal("the pair no longer shares a short identifier: find another one")
	}
	ad := func(x ...byte) netip.Addr { return netip.AddrFrom4([4]byte(x)) }
	path := func(b2, b3 byte) *simPath {
		return &simPath{rtt: 500 * time.Microsecond, hops: []simHop{
			{addr: ad(10, 0, 0, 1), rtt: 100 * time.Microsecond},
			{addr: ad(10, 1, b2, 1), rtt: 200 * time.Microsecond},
			{addr: ad(10, 2, b3, 1), rtt: 300 * time.Microsecond},
		}}
	}
	cfg := simpleCfg()
	cfg.Flows, cfg.Discovery = 1, true
	s := newSim(t, cfg, func(f *Flow, _ Mono) *simPath {
		if f.SPort()%2 == 0 {
			return path(15, 158)
		}
		return path(23, 124)
	})
	ep := s.add(64)
	s.run(3 * time.Minute)
	var confirmed []*Group
	for _, g := range ep.groups {
		if g.Level == LevelConfirmed {
			confirmed = append(confirmed, g)
		}
	}
	if len(confirmed) != 2 {
		t.Fatalf("%d confirmed routes, want 2 (two different routes were taken for one)", len(confirmed))
	}
	a, b := confirmed[0], confirmed[1]
	if a.ID == b.ID {
		t.Errorf("both routes are called %s", a.ID)
	}
	if a.Sig.canon == b.Sig.canon {
		t.Errorf("both routes have the signature %s", a.Sig.canon)
	}
	// No port of one route is a member of the other.
	for _, g := range confirmed {
		for _, f := range g.Members {
			want := sigA
			if f.SPort()%2 != 0 {
				want = sigB
			}
			if g.Sig.canon != want {
				t.Errorf("port %d (route %s) is in the route %s", f.SPort(), want, g.Sig.canon)
			}
		}
	}
	// The names stay the same from one regrouping to the next, and a route
	// that goes and comes back is called what it was called.
	names := map[string]string{a.Sig.canon: a.ID, b.Sig.canon: b.ID}
	s.run(time.Minute)
	for _, g := range ep.groups {
		if want, ok := names[g.Sig.canon]; ok && g.Level == LevelConfirmed && g.ID != want {
			t.Errorf("route %s was renamed from %s to %s", g.Sig.canon, want, g.ID)
		}
	}
	for canon, want := range names {
		if got := uniqueGroupID(groupKey{LevelConfirmed, canon}, ep.groupIDs); got != want {
			t.Errorf("route %s asked again is %s, was %s", canon, got, want)
		}
	}
}
