package cli

import (
	"io"
	"net"
	"runtime/debug"
	"slices"
	"testing"
	"time"

	"github.com/hotid/mpmtr/internal/core"
	"github.com/hotid/mpmtr/internal/wire"
)

func TestParseTarget(t *testing.T) {
	cases := []struct {
		in   string
		host string
		port wire.Port
		err  bool
	}{
		{"example.com", "example.com", 443, false},
		{"example.com:80", "example.com", 80, false},
		{"1.1.1.1", "1.1.1.1", 443, false},
		{"[2001:db8::1]:8443", "2001:db8::1", 8443, false},
		{"[2001:db8::1]", "2001:db8::1", 443, false},
		{"2001:db8::1", "2001:db8::1", 443, false},
		{"host:0", "", 0, true},
		{"host:99999", "", 0, true},
		{"[::1", "", 0, true},
		{":80", "", 0, true},
	}
	for _, c := range cases {
		h, p, err := ParseTarget(c.in)
		if (err != nil) != c.err || (!c.err && (h != c.host || p != c.port)) {
			t.Errorf("%q → %q %d %v", c.in, h, p, err)
		}
	}
}

// Ports are used in order (repeatable without any seed): the first port is
// the start of the range. The range lies below the kernel's ephemeral range
// (default 32768-60999): a port in it may be taken by any outgoing
// connection of the machine at that moment, and preflight rightly skips it.
func TestPortsSequential(t *testing.T) {
	f, targets, err := parseArgs([]string{"-r", "--sport-range", "29100-29115", "127.0.0.1"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	o, err := Build(f, targets, io.Discard, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if o.PortLock != nil {
		defer o.PortLock.Release()
	}
	want, _ := parseRange("29100-29115")
	if !slices.Equal(o.Ports, want) {
		t.Fatalf("ports %v", o.Ports)
	}
	if o.Core.Flows != 1 || o.Core.MaxFlows != 16 {
		t.Fatalf("flows per route %d, discovery limit %d", o.Core.Flows, o.Core.MaxFlows)
	}
}

func TestParsePorts(t *testing.T) {
	if _, err := parseRange("300-200"); err == nil {
		t.Fatal("reversed range accepted")
	}
	if _, err := parseList("20001,20001"); err == nil {
		t.Fatal("duplicate accepted")
	}
	if l, err := parseList("20001, 20007,20023"); err != nil || len(l) != 3 {
		t.Fatal(l, err)
	}
}

func TestBuildValidation(t *testing.T) {
	bad := [][]string{
		{"-4", "-6", "1.1.1.1"},
		{"--timeout", "2s", "1.1.1.1"},
		{"--json", "1.1.1.1"},
		{"--flows", "0", "1.1.1.1"},
		{"--flow-label", "2000000", "1.1.1.1"},
		{"--tos", "300", "1.1.1.1"},
		{"--discover", "--no-discovery", "1.1.1.1"},
		{"-6", "1.1.1.1"},
		{"--pps", "NaN", "1.1.1.1"},
		{"--endpoint-pps", "+Inf", "1.1.1.1"},
		{"--fwmark", "4294967296", "1.1.1.1"},
		{"--hop-info-interval", "30s", "1.1.1.1"},                              // no plugin to refresh
		{"--hop-info", "/bin/true", "--hop-info-interval", "500ms", "1.1.1.1"}, // below 1s
		{"--hop-info", "/bin/true", "--hop-info-interval", "-5s", "1.1.1.1"},
		{"-r", "--events", "-", "1.1.1.1"},
		{"--discover", "--events", "-", "1.1.1.1"},
	}
	for _, args := range bad {
		f, targets, err := parseArgs(args, nil)
		if err != nil {
			continue
		}
		if _, err := Build(f, targets, nil, nil); err == nil {
			t.Errorf("%v accepted", args)
		}
	}
}

// A short --interval without --timeout must work (timeout follows it);
// an explicit --timeout above --interval is still an error.
func TestTimeoutFollowsInterval(t *testing.T) {
	f, targets, err := parseArgs([]string{"-r", "-i", "200ms", "127.0.0.1"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	o, err := Build(f, targets, io.Discard, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if o.Core.Timeout != 200*time.Millisecond {
		t.Fatalf("timeout %v", o.Core.Timeout)
	}
	f, targets, _ = parseArgs([]string{"-i", "200ms", "--timeout", "1s", "127.0.0.1"}, nil)
	if _, err := Build(f, targets, io.Discard, io.Discard); err == nil {
		t.Fatal("explicit --timeout > --interval accepted")
	}
}

func TestDurationFlags(t *testing.T) {
	for in, want := range map[string]time.Duration{
		"0.2": 200 * time.Millisecond, "5": 5 * time.Second, "0,5": 500 * time.Millisecond,
		"200ms": 200 * time.Millisecond, "1m30s": 90 * time.Second, ".05": 50 * time.Millisecond,
	} {
		f, _, err := parseArgs([]string{"-i", in, "--timeout", in, "--report-timeout", in, "127.0.0.1"}, nil)
		if err != nil {
			t.Fatalf("%s: %v", in, err)
		}
		if f.interval != want || f.timeout != want || f.reportTimeout != want {
			t.Fatalf("%s: %v %v %v", in, f.interval, f.timeout, f.reportTimeout)
		}
	}
	for _, in := range []string{"abc", "-1", "1x"} {
		if _, _, err := parseArgs([]string{"-i", in, "127.0.0.1"}, nil); err == nil {
			t.Fatalf("%q accepted", in)
		}
	}
	f, _, _ := parseArgs([]string{"127.0.0.1"}, nil)
	if f.interval != time.Second {
		t.Fatalf("default interval %v", f.interval)
	}
}

// Ports used by other local sockets are skipped, not an error.
func TestPreflightSkipsBusyPorts(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	busy := wire.Port(l.Addr().(*net.TCPAddr).Port)
	ports := []wire.Port{busy, busy + 1, busy + 2}
	free, w, err := preflightPorts(ports, false, 1)
	if err != nil || len(w) != 0 || slices.Contains(free, busy) || len(free) != 2 {
		t.Fatalf("free %v warnings %v err %v", free, w, err)
	}
	if _, _, err := preflightPorts([]wire.Port{busy}, true, 1); err == nil {
		t.Fatal("no free explicit port must be an error")
	}
}

func TestModuleVersion(t *testing.T) {
	bi := func(v string, settings ...string) *debug.BuildInfo {
		b := &debug.BuildInfo{Main: debug.Module{Version: v}}
		for i := 0; i+1 < len(settings); i += 2 {
			b.Settings = append(b.Settings, debug.BuildSetting{Key: settings[i], Value: settings[i+1]})
		}
		return b
	}
	for _, c := range []struct {
		bi   *debug.BuildInfo
		ok   bool
		want string
	}{
		{bi("v0.2.0"), true, "v0.2.0"},
		{bi("v0.2.0+dirty", "vcs.revision", "abcdef0123456789", "vcs.modified", "true"), true, "v0.2.0+dirty"},
		{bi("v0.0.0-20261127120255-a9681d3c0d53", "vcs.revision", "a9681d3c0d539de4", "vcs.modified", "false"), true, "a9681d3"},
		{bi("v0.2.1-0.20261124000000-abcdef012345+dirty"), true, "abcdef0-dirty"},
		{bi("(devel)", "vcs.revision", "0123456789abcdef", "vcs.modified", "true"), true, "0123456-dirty"},
		{bi("(devel)"), true, "devel"},
		{bi(""), true, "devel"},
		{nil, false, "devel"},
	} {
		if got := moduleVersion(c.bi, c.ok); got != c.want {
			t.Errorf("moduleVersion(%v) = %q, want %q", c.bi, got, c.want)
		}
	}
}

// The exit code: DOWN wins, then missing data (an UNKNOWN endpoint, an
// incomplete report, too many ports without a verdict or unmeasurable), then
// LOSS.
func TestExitCode(t *testing.T) {
	ep := func(state core.EPState, total, unknown, invalid int) core.EPSnap {
		return core.EPSnap{State: state, Agg: core.EndpointAgg{Total: total, Unknown: unknown, Invalid: invalid}}
	}
	for _, tc := range []struct {
		name       string
		eps        []core.EPSnap
		incomplete bool
		want       int
	}{
		{"ok", []core.EPSnap{ep(core.EPOK, 4, 0, 0)}, false, ExitOK},
		{"ok, one port in four without a verdict", []core.EPSnap{ep(core.EPOK, 4, 1, 0)}, false, ExitOK},
		{"ok, one invalid port in five", []core.EPSnap{ep(core.EPOK, 5, 0, 1)}, false, ExitOK},
		{"ok, two invalid ports in five", []core.EPSnap{ep(core.EPOK, 5, 0, 2)}, false, ExitUnknown},
		{"ok, unknown and invalid together above a quarter", []core.EPSnap{ep(core.EPOK, 6, 1, 1)}, false, ExitUnknown},
		{"ok but incomplete", []core.EPSnap{ep(core.EPOK, 4, 0, 0)}, true, ExitUnknown},
		{"loss", []core.EPSnap{ep(core.EPLoss, 4, 0, 0)}, false, ExitLoss},
		{"loss but incomplete", []core.EPSnap{ep(core.EPLoss, 4, 0, 0)}, true, ExitUnknown},
		{"loss and an unknown endpoint", []core.EPSnap{ep(core.EPLoss, 4, 0, 0), ep(core.EPUnknown, 4, 4, 0)}, false, ExitUnknown},
		{"down, incomplete", []core.EPSnap{ep(core.EPDown, 4, 0, 0), ep(core.EPOK, 4, 0, 0)}, true, ExitDown},
	} {
		if got := exitCode(&core.Snapshot{Endpoints: tc.eps}, tc.incomplete); got != tc.want {
			t.Errorf("%s: exit %d, want %d", tc.name, got, tc.want)
		}
	}
}

func TestSplitArgs(t *testing.T) {
	for in, want := range map[string][]string{
		"":                                  nil,
		"http":                              {"http"},
		"  http   --get  /x ":               {"http", "--get", "/x"},
		`http --user-agent 'A B (C; D)' -g`: {"http", "--user-agent", "A B (C; D)", "-g"},
		`snmp --x "a 'b' c" ''`:             {"snmp", "--x", "a 'b' c", ""},
	} {
		if got := splitArgs(in); !slices.Equal(got, want) {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
}
