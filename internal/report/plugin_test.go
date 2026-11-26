package report

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/hotid/mpmtr/internal/core"
)

type pluginNames struct {
	notes map[string]string
	width int
}

func (pluginNames) Name(netip.Addr) string            { return "" }
func (pluginNames) Note(netip.Addr) string            { return "AS64500 EXAMPLE" }
func (f pluginNames) PluginNote(ip netip.Addr) string { return f.notes[ip.String()] }
func (f pluginNames) PluginWidth() int                { return f.width }

// What the hop-information plugins say has its own column, between the
// numbers and FLAGS, present only when plugins run; every row keeps FLAGS
// in one place, a long text is cut to the column.
func TestPluginColumn(t *testing.T) {
	n := pluginNames{notes: map[string]string{"192.0.2.1": "Ethernet1/2", "192.0.2.2": "port-channel1012345"}, width: 12}
	hdr := HopHeaderFor(n)
	col, flagsAt := strings.Index(hdr, "PLUGIN"), strings.Index(hdr, "FLAGS")
	if col < 0 || flagsAt != col+n.width+1 || !strings.HasPrefix(hdr, strings.TrimSuffix(HopHeader, "FLAGS")) {
		t.Fatalf("header %q", hdr)
	}
	hop := func(ip string, replies uint32) string {
		return HopLineNote(core.HopSnap{TTL: 3, Kind: core.KindHop, Responder: netip.MustParseAddr(ip), Sent: 5, Replies: replies, Stale: true}, n, "", "AS64500 EXAMPLE")
	}
	for ip, want := range map[string]string{"192.0.2.1": "Ethernet1/2  stale AS64500 EXAMPLE", "192.0.2.2": "port-channe… stale AS64500 EXAMPLE",
		"192.0.2.3": "             stale AS64500 EXAMPLE"} {
		for _, replies := range []uint32{0, 5} {
			l := []rune(hop(ip, replies))
			if got := string(l[col:]); got != want {
				t.Errorf("%s (replies %d): %q, want %q", ip, replies, got, want)
			}
		}
	}
	// a silent row has no responder to ask about
	if l := HopLineNote(core.HopSnap{TTL: 4, Kind: core.KindSilent, Responder: netip.MustParseAddr("192.0.2.1"), Sent: 5}, n, "", ""); strings.Contains(l, "Ethernet") {
		t.Errorf("silent row %q", l)
	}
	// a row without a note and without flags is still padded: the route
	// that a DST row gets appended lands under FLAGS, not under PLUGIN
	dst := HopLineNote(core.HopSnap{TTL: 8, Kind: core.KindDst, Responder: netip.MustParseAddr("192.0.2.9"), Sent: 5, Replies: 5}, n, "", "") + "  route B OK"
	if at := strings.Index(dst, "route B"); at != flagsAt+2 { // the same two spaces as without plugins
		t.Errorf("route of a DST row at column %d, FLAGS at %d: %q", at, flagsAt, dst)
	}
	// without plugins nothing changes
	plain := pluginNames{}
	if HopHeaderFor(plain) != HopHeader || HopHeaderFor(nil) != HopHeader {
		t.Error("header changed without plugins")
	}
	if l := HopLineNote(core.HopSnap{TTL: 3, Kind: core.KindHop, Responder: netip.MustParseAddr("192.0.2.1"), Sent: 5, Replies: 5, Stale: true}, plain, "", ""); !strings.HasSuffix(l, " stale") {
		t.Errorf("row without plugins %q", l)
	}
}

// The server list has the PLUGIN column too: what the application plugin
// notes about a server stands under it, before the state.
func TestServerLinePluginColumn(t *testing.T) {
	names := pluginNames{width: 6}
	s := core.ServerSnap{Name: "S4", Hz: 1000, Ports: 3}
	s.E2E.AppNote = "200"
	head := ServerHeaderFor(names)
	line := ServerLine(s, nil, names, CellStyle{})
	col := strings.Index(head, "PLUGIN")
	if col < 0 || !strings.Contains(head, "SERVER") {
		t.Fatalf("header: %q", head)
	}
	if got := []rune(line); len(got) < col+3 || string(got[col:col+3]) != "200" {
		t.Fatalf("note not under PLUGIN (column %d):\n%s\n%s", col, head, line)
	}
	if strings.Contains(ServerHeaderFor(nil), "PLUGIN") || strings.Contains(ServerLine(s, nil, nil, CellStyle{}), "200") {
		t.Fatalf("PLUGIN column without plugins")
	}
}
