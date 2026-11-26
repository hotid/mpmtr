package report

import (
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/hotid/mpmtr/internal/wire"

	"github.com/hotid/mpmtr/internal/core"
)

// Tree rows keep the numeric columns aligned at any depth, and a route's
// result starts under the Loss% header.
func TestTreeAlignment(t *testing.T) {
	loss := 0.0
	full := 1.0
	lossAt := strings.Index(HopHeader, "Loss%")
	jitEnd := strings.Index(HopHeader, "Jttr") + len("Jttr")
	for _, prefix := range []string{"", "├─", "│ │ │ └─", "│ │ │ │ │ │ "} {
		for _, h := range []core.HopSnap{
			{TTL: 3, Kind: core.KindHop, Responder: netip.MustParseAddr("203.0.113.74"), Sent: 31, Replies: 31, Loss: &loss, Last: 124100, AgeMs: 644},
			{TTL: 6, TTLTo: 9, Kind: core.KindSilent, Sent: 185, Loss: &full, AgeMs: 8000},
		} {
			l := []rune(HopLineTree(h, nil, prefix))
			if got := strings.TrimRight(string(l[:min(jitEnd, len(l))]), " "); h.Replies > 0 && len([]rune(got)) != jitEnd {
				t.Errorf("prefix %q kind %s: Jttr column ends at %d, want %d\n%s\n%s", prefix, h.Kind, len([]rune(got)), jitEnd, HopHeader, string(l))
			}
			if l[lossAt+4] != '%' { // "Loss%" and " 0.0%" / "100.0%" end together
				t.Errorf("prefix %q kind %s: Loss%% misaligned\n%s\n%s", prefix, h.Kind, HopHeader, string(l))
			}
		}
		for _, g := range []core.GroupSnap{
			{ID: "G1", State: core.GOK, Flows: []string{"F1"}, Ports: []wire.Port{20001}, Monitored: 1, W5: core.WinSnap{Valid: 583}},
			{ID: "G2", State: core.GUnknown, Flows: []string{"F2"}, Ports: []wire.Port{20002}},
		} {
			l := []rune(RouteLineTree(g, "A", prefix+"└═"))
			if l[lossAt-1] != ' ' || l[lossAt] == ' ' {
				t.Errorf("prefix %q: route result not under Loss%%\n%s\n%s", prefix, HopHeader, string(l))
			}
		}
	}
}

func TestDstServerName(t *testing.T) {
	h := core.HopSnap{TTL: 10, Kind: core.KindDst, Responder: netip.MustParseAddr("198.51.100.99"), Name: "S20 (1000 Hz)", Replies: 1, Sent: 1}
	if l := HopLine(h, nil); !strings.Contains(l, "DST 198.51.100.99 → S20 (1000 Hz) ") {
		t.Fatalf("%q", l)
	}
	h.Responder = netip.MustParseAddr("2001:db8:1234:5678::a")
	if l := HopLine(h, nil); !strings.Contains(l, "DST 2001:db8:1234:5678::a → S20 ") {
		t.Fatalf("%q", l)
	}
}

type fakeNames map[string]string

func (f fakeNames) Name(netip.Addr) string    { return "" }
func (f fakeNames) Note(ip netip.Addr) string { return f[ip.String()] }

// Annotations show where they change along a branch; silent rows inherit
// the one above them, so the hop after a gap does not repeat it.
func TestTreeNotesOnChange(t *testing.T) {
	n := fakeNames{"1.1.1.1": "AS1 ONE", "1.1.1.2": "AS1 ONE", "2.2.2.1": "AS2 TWO", "2.2.2.2": "AS2 TWO", "3.3.3.3": "AS1 ONE"}
	rows := []core.TreeRow{
		{Path: ">1.1.1.1", Parent: -1, Hop: core.HopSnap{Kind: core.KindHop, Responder: netip.MustParseAddr("1.1.1.1")}},
		{Path: ">1.1.1.1>*", Parent: 0, Hop: core.HopSnap{Kind: core.KindSilent}},
		{Path: ">1.1.1.1>*>1.1.1.2", Parent: 1, Hop: core.HopSnap{Kind: core.KindHop, Responder: netip.MustParseAddr("1.1.1.2")}},
		{Path: ">1.1.1.1>*>1.1.1.2>2.2.2.1", Parent: 2, Hop: core.HopSnap{Kind: core.KindHop, Responder: netip.MustParseAddr("2.2.2.1")}},
		{Path: ">1.1.1.1>*>1.1.1.2>2.2.2.1>2.2.2.2", Parent: 3, Hop: core.HopSnap{Kind: core.KindDst, Responder: netip.MustParseAddr("2.2.2.2")}},
		{Path: ">1.1.1.1>*>1.1.1.2>3.3.3.3", Parent: 2, Hop: core.HopSnap{Kind: core.KindHop, Responder: netip.MustParseAddr("3.3.3.3")}},
	}
	got := TreeNotes(rows, n)
	want := []string{"AS1 ONE", "", "", "AS2 TWO", "", ""}
	if !slices.Equal(got, want) {
		t.Fatalf("notes %q, want %q", got, want)
	}
	if l := HopLineNote(rows[3].Hop, n, "", got[3]); !strings.HasSuffix(strings.TrimSpace(l), "AS2 TWO") {
		t.Fatalf("line %q", l)
	}
	hops := []core.HopSnap{rows[0].Hop, rows[2].Hop, rows[3].Hop, {Kind: core.KindHop, Responder: netip.MustParseAddr("3.3.3.3")}}
	if got := PathNotes(hops, n); !slices.Equal(got, []string{"AS1 ONE", "", "AS2 TWO", "AS1 ONE"}) {
		t.Fatalf("path notes %q", got)
	}
}

// The mpls flag: one stack is a/b, different stacks of different ports are
// separated by commas, and a label is never repeated per port.
func TestMPLSFlag(t *testing.T) {
	for _, tc := range []struct {
		h    core.HopSnap
		want string
	}{
		{core.HopSnap{MPLS: []uint32{20016}}, "mpls:20016"},
		{core.HopSnap{MPLS: []uint32{16001, 24005}}, "mpls:16001/24005"},
		{core.HopSnap{MPLS: []uint32{20015}, MPLSStacks: [][]uint32{{20015}, {20016}}}, "mpls:20015,20016"},
		{core.HopSnap{MPLS: []uint32{16001, 24005}, MPLSStacks: [][]uint32{{16001, 24005}, {16001}}}, "mpls:16001/24005,16001"},
	} {
		tc.h.TTL, tc.h.Responder, tc.h.Kind = 3, netip.MustParseAddr("192.0.2.1"), core.KindHop
		line := HopLineTree(tc.h, nil, "")
		if !strings.HasSuffix(strings.TrimSpace(line), tc.want) {
			t.Errorf("want %q at the end of %q", tc.want, line)
		}
	}
}
