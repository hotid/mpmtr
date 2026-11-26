package app

import (
	"net"
	"net/http"
	"net/http/httptest"
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

// End to end: the example plugin gets a real connection opened from a
// reserved port; a healthy server passes, a mute one fails at the protocol
// stage (the server's fault), a dead plugin is a local error.
func TestPluginEndToEnd(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "mpmtr-app-http")
	if out, err := exec.Command("go", "build", "-o", bin, "../../cmd/mpmtr-app-http").CombinedOutput(); err != nil {
		t.Fatalf("build plugin: %v %s", err, out)
	}
	good, _ := net.Listen("tcp", "127.0.0.1:0")
	defer good.Close()
	go http.Serve(good, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	mute, _ := net.Listen("tcp", "127.0.0.1:0")
	defer mute.Close()
	go func() {
		for {
			c, err := mute.Accept()
			if err != nil {
				return
			}
			go func() { time.Sleep(3 * time.Second); c.Close() }()
		}
	}()
	p, err := StartPlugin(bin, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if p.Name != "http" {
		t.Fatalf("hello: %q", p.Name)
	}
	lo := netip.MustParseAddr("127.0.0.1")
	res := sys.NewReserver()
	defer res.Close()
	const sport = 23411
	if err := res.Reserve(lo, sport); err != nil {
		t.Fatal(err)
	}
	lastNote := ""
	check := func(id uint64, l net.Listener, timeout time.Duration) (bool, string, bool) {
		dport := wire.Port(l.Addr().(*net.TCPAddr).Port)
		fd, _, _, err := sys.DialFrom(lo, sport, lo, dport, sys.DialOpts{}, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer unix.Close(fd)
		out, stage, _, note, _ := p.Check(id, fd, pluginMsg{Dst: "127.0.0.1", DPort: uint16(dport)}, timeout)
		lastNote = note
		return out == core.AppPassed, stage, out.Local()
	}
	if ok, stage, local := check(1, good, 2*time.Second); !ok || local {
		t.Fatalf("healthy server: ok %v stage %s local %v", ok, stage, local)
	}
	// The plugin's note (the HTTP status) comes with the verdict and sets
	// the width of its column.
	if lastNote != "200" || p.NoteWidth() != 3 {
		t.Fatalf("note %q, width %d; want 200 and 3", lastNote, p.NoteWidth())
	}
	if ok, stage, local := check(2, mute, 500*time.Millisecond); ok || local || stage != "answer" {
		t.Fatalf("mute server: ok %v stage %s local %v", ok, stage, local)
	}
	p.cmd.Process.Kill()
	time.Sleep(100 * time.Millisecond)
	if ok, _, local := check(3, good, time.Second); ok || !local {
		t.Fatalf("dead plugin: ok %v local %v", ok, local)
	}
}

// A plugin that takes the sockets and never answers is stopped after three
// checks in a row: its copies of the connections close with it, and the
// checks after that are local errors at once.
func TestSilentPluginIsStopped(t *testing.T) {
	defer func(d time.Duration) { pluginGrace = d }(pluginGrace)
	pluginGrace = 50 * time.Millisecond
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	defer l.Close()
	closed := make(chan struct{}, 8)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				c.Read(make([]byte, 1)) // returns when the last copy of the peer's socket closes
				c.Close()
				closed <- struct{}{}
			}()
		}
	}()
	p, err := StartPlugin("/usr/bin/env", []string{"MPMTR_TEST_HOP_PLUGIN=app-hang", os.Args[0]})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	lo := netip.MustParseAddr("127.0.0.1")
	dport := wire.Port(l.Addr().(*net.TCPAddr).Port)
	check := func(id uint64) (core.AppOutcome, time.Duration) {
		fd, _, _, err := sys.DialFrom(lo, wire.Port(23420+id), lo, dport, sys.DialOpts{}, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer unix.Close(fd)
		start := time.Now()
		out, _, _, _, _ := p.Check(id, fd, pluginMsg{Dst: "127.0.0.1", DPort: uint16(dport)}, 50*time.Millisecond)
		return out, time.Since(start)
	}
	for id := uint64(1); id <= pluginSilentMax; id++ {
		if out, _ := check(id); out != core.AppPluginFailed {
			t.Fatalf("check %d: %v", id, out)
		}
		if id < pluginSilentMax && p.Dead() != nil {
			t.Fatalf("stopped after %d unanswered checks: %v", id, p.Dead())
		}
	}
	if p.Dead() == nil {
		t.Fatalf("still running after %d unanswered checks", pluginSilentMax)
	}
	for i := 0; i < pluginSilentMax; i++ {
		select {
		case <-closed:
		case <-time.After(3 * time.Second):
			t.Fatalf("the stopped plugin still holds %d of the connections", pluginSilentMax-i)
		}
	}
	if out, took := check(9); out != core.AppPluginFailed || took > 40*time.Millisecond {
		t.Fatalf("check after the stop: %v in %v", out, took)
	}
}

// The http plugin speaks TLS when told to and puts the target's name, as
// mpmtr hands it over, into the TLS server name and the Host header.
func TestHTTPPluginTLSAndHost(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "mpmtr-app-http")
	if out, err := exec.Command("go", "build", "-o", bin, "../../cmd/mpmtr-app-http").CombinedOutput(); err != nil {
		t.Fatalf("build plugin: %v %s", err, out)
	}
	type seen struct{ host, sni, method, path string }
	got := make(chan seen, 4)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s := seen{host: r.Host, method: r.Method, path: r.URL.Path}
		if r.TLS != nil {
			s.sni = r.TLS.ServerName
		}
		got <- s
		w.WriteHeader(http.StatusTeapot)
	}))
	srv.StartTLS()
	defer srv.Close()
	plain := httptest.NewServer(srv.Config.Handler)
	defer plain.Close()
	lo := netip.MustParseAddr("127.0.0.1")
	res := sys.NewReserver()
	defer res.Close()
	const sport = 23412
	if err := res.Reserve(lo, sport); err != nil {
		t.Fatal(err)
	}
	run := func(args []string, l net.Listener, host string) (core.AppOutcome, string, string) {
		p, err := StartPlugin(bin, args)
		if err != nil {
			t.Fatal(err)
		}
		defer p.Close()
		dport := wire.Port(l.Addr().(*net.TCPAddr).Port)
		fd, _, _, err := sys.DialFrom(lo, sport, lo, dport, sys.DialOpts{}, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer unix.Close(fd)
		out, stage, _, note, _ := p.Check(1, fd, pluginMsg{Dst: "127.0.0.1", DPort: uint16(dport), Host: host}, 2*time.Second)
		return out, stage, note
	}
	if out, stage, note := run([]string{"--tls"}, srv.Listener, "name.example"); out != core.AppPassed || note != "418" {
		t.Fatalf("TLS: %v stage %s note %q", out, stage, note)
	}
	if s := <-got; s.host != "name.example" || s.sni != "name.example" || s.method != "HEAD" {
		t.Fatalf("TLS: the server saw Host %q, server name %q, method %s", s.host, s.sni, s.method)
	}
	// The test certificate is not for that name: with --verify the check fails at TLS.
	if out, stage, _ := run([]string{"--tls", "--verify"}, srv.Listener, "name.example"); out != core.AppFailed || stage != "tls" {
		t.Fatalf("TLS with --verify: %v stage %s", out, stage)
	}
	// Not port 443 and no --tls: plain HTTP.
	// --get asks with GET, for the URL's path under the URL's host.
	if out, stage, note := run([]string{"--get", "other.example/index.php"}, plain.Listener, ""); out != core.AppPassed || note != "418" {
		t.Fatalf("plain: %v stage %s note %q", out, stage, note)
	}
	if s := <-got; s.host != "other.example" || s.sni != "" || s.method != "GET" || s.path != "/index.php" {
		t.Fatalf("plain: the server saw Host %q, server name %q, method %s", s.host, s.sni, s.method)
	}
}

// A plugin closed while its read loop runs must not leave that loop reading
// the descriptor number, which the next plugin's socket may get: it would
// take that plugin's hello.
func TestPluginRestart(t *testing.T) {
	for i := 0; i < 60; i++ {
		p, err := StartPlugin("/usr/bin/env", []string{"MPMTR_TEST_HOP_PLUGIN=app-hang", os.Args[0]})
		if err != nil {
			t.Fatalf("start %d: %v", i, err)
		}
		p.Close()
	}
}
