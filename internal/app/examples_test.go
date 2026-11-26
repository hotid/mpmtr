package app

import (
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/hotid/mpmtr/internal/core"
	"github.com/hotid/mpmtr/internal/wire"

	"golang.org/x/sys/unix"

	"github.com/hotid/mpmtr/internal/sys"
)

func needPython(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not found")
	}
}

// The example plugins of docs/WRITING_PLUGINS.md, written without the SDK,
// work against the real host side.
func TestExampleHopPlugin(t *testing.T) {
	needPython(t)
	inv := filepath.Join(t.TempDir(), "inventory.txt")
	if err := os.WriteFile(inv, []byte("192.0.2.1  core1  rack 12, row B  # comment\n192.0.2.2  edge7\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	h, err := StartHopInfo([]HopPluginSpec{{Path: "../../examples/mpmtr-hop-static", Args: []string{inv}}}, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	for _, a := range []string{"192.0.2.1", "192.0.2.2", "192.0.2.9"} {
		h.Name(netip.MustParseAddr(a))
	}
	settle(t, h)
	if n, note := h.Name(netip.MustParseAddr("192.0.2.1")), h.Note(netip.MustParseAddr("192.0.2.1")); n != "core1" || note != "rack 12, row B" {
		t.Errorf("192.0.2.1: %q %q", n, note)
	}
	if n, note := h.Name(netip.MustParseAddr("192.0.2.2")), h.Note(netip.MustParseAddr("192.0.2.2")); n != "edge7" || note != "" {
		t.Errorf("192.0.2.2: %q %q", n, note)
	}
	if n := h.Name(netip.MustParseAddr("192.0.2.9")); n != "" {
		t.Errorf("unknown address: %q", n)
	}
	if all := h.All(); all[netip.MustParseAddr("192.0.2.1")]["static"].Name != "core1" {
		t.Errorf("hello name: %v", all)
	}
}

func TestExampleAppPlugin(t *testing.T) {
	needPython(t)
	serve := func(greeting string) net.Listener {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { l.Close() })
		go func() {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				go func() {
					if greeting != "" {
						c.Write([]byte(greeting + "\r\n"))
					}
					time.Sleep(2 * time.Second)
					c.Close()
				}()
			}
		}()
		return l
	}
	good, wrong, mute := serve("SSH-2.0-test"), serve("220 mail ready"), serve("")
	p, err := StartPlugin("../../examples/mpmtr-app-banner", []string{"SSH-2.0"})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if p.Name != "banner" {
		t.Fatalf("hello: %q", p.Name)
	}
	lo := netip.MustParseAddr("127.0.0.1")
	res := sys.NewReserver()
	defer res.Close()
	const sport = 23412
	if err := res.Reserve(lo, sport); err != nil {
		t.Fatal(err)
	}
	check := func(id uint64, l net.Listener) (bool, string, bool) {
		dport := wire.Port(l.Addr().(*net.TCPAddr).Port)
		fd, _, _, err := sys.DialFrom(lo, sport, lo, dport, sys.DialOpts{}, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer unix.Close(fd)
		out, stage, _, _, _ := p.Check(id, fd, pluginMsg{Dst: "127.0.0.1", DPort: uint16(dport)}, 500*time.Millisecond)
		return out == core.AppPassed, stage, out.Local()
	}
	if ok, stage, local := check(1, good); !ok || local {
		t.Errorf("right greeting: ok %v stage %q local %v", ok, stage, local)
	}
	if ok, stage, local := check(2, wrong); ok || local || stage != "banner" {
		t.Errorf("wrong greeting: ok %v stage %q local %v", ok, stage, local)
	}
	if ok, stage, local := check(3, mute); ok || local || stage != "banner" {
		t.Errorf("no greeting: ok %v stage %q local %v", ok, stage, local)
	}
}
