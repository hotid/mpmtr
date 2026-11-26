package core

import (
	"slices"
	"testing"
	"time"

	"github.com/hotid/mpmtr/internal/wire"
)

// A hop row that sums up several ports shows the label stack once, not
// once per port: four ports that were all given label 20016 are "20016",
// not a stack of four. Ports given different stacks show each stack once.
func TestHopRowMPLSStacks(t *testing.T) {
	c := newSim(t, simpleCfg(), func(*Flow, Mono) *simPath { return linear(3, 10*time.Millisecond) }).c
	hop := func(labels ...uint32) *HopStat {
		h := &HopStat{Sent: 3, Replies: 3}
		for i, l := range labels {
			h.MPLS[i] = wire.MPLSEntry{Label: l}
		}
		h.NMPLS = len(labels)
		return h
	}
	for _, tc := range []struct {
		name   string
		hops   []*HopStat
		first  []uint32
		stacks [][]uint32
	}{
		{"no labels", []*HopStat{hop(), hop()}, nil, nil},
		{"four ports, one label", []*HopStat{hop(20016), hop(20016), hop(20016), hop(20016)}, []uint32{20016}, nil},
		{"one port without a label", []*HopStat{hop(20016), hop(), hop(20016)}, []uint32{20016}, nil},
		{"a real stack of two", []*HopStat{hop(16001, 24005), hop(16001, 24005)}, []uint32{16001, 24005}, nil},
		{"two labels among the ports", []*HopStat{hop(20015), hop(20015), hop(20015), hop(20016)}, []uint32{20015},
			[][]uint32{{20015}, {20016}}},
		{"a stack and its shorter form", []*HopStat{hop(16001, 24005), hop(16001)}, []uint32{16001, 24005},
			[][]uint32{{16001, 24005}, {16001}}},
		{"more different stacks than are kept", []*HopStat{hop(1), hop(2), hop(3), hop(4), hop(5), hop(1)}, []uint32{1},
			[][]uint32{{1}, {2}, {3}, {4}}},
	} {
		s := c.aggHops(tc.hops, 3)
		if !slices.Equal(s.MPLS, tc.first) {
			t.Errorf("%s: labels %v, want %v", tc.name, s.MPLS, tc.first)
		}
		if !slices.EqualFunc(s.MPLSStacks, tc.stacks, func(a, b []uint32) bool { return slices.Equal(a, b) }) {
			t.Errorf("%s: stacks %v, want %v", tc.name, s.MPLSStacks, tc.stacks)
		}
	}
}
