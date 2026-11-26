//go:build integration

// Privileged Linux integration tests on a network-namespace ECMP topology
// (see topo.sh). Run as root:
//
//	make integration
//
// Each test checks mpmtr's result AND the actual traffic (tcpdump on the
// routers) where the claim is about the wire.
package integration

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/hotid/mpmtr/internal/core"
	"github.com/hotid/mpmtr/internal/report"
)

var bin string

func TestMain(m *testing.M) {
	if os.Geteuid() != 0 {
		// Not a skip: a green result without a single test run would lie.
		fmt.Println("integration tests need root (network namespaces): run `make integration`")
		os.Exit(1)
	}
	bin = os.Getenv("MPMTR_BIN")
	if bin == "" {
		bin = filepath.Join(os.TempDir(), "mpmtr-it")
		if out, err := exec.Command("go", "build", "-o", bin, "..").CombinedOutput(); err != nil {
			fmt.Printf("build: %v\n%s", err, out)
			os.Exit(1)
		}
	}
	if out, err := exec.Command("./topo.sh", "up").CombinedOutput(); err != nil {
		fmt.Printf("topology: %v\n%s", err, out)
		os.Exit(1)
	}
	srv := exec.Command("ip", "netns", "exec", "mpdst", "python3", "-m", "http.server", "--bind", "::", "443")
	srv.Start()
	time.Sleep(time.Second)
	code := m.Run()
	srv.Process.Kill()
	if os.Getenv("MPMTR_KEEP") == "" {
		exec.Command("./topo.sh", "down").Run()
	}
	os.Exit(code)
}

func sh(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

func nsx(t *testing.T, ns string, args ...string) string {
	return sh(t, append([]string{"ip", "netns", "exec", ns}, args...)...)
}

// netem applies a qdisc and registers its removal.
func netem(t *testing.T, ns, dev string, args ...string) {
	nsx(t, ns, append([]string{"tc", "qdisc", "replace", "dev", dev, "root", "netem"}, args...)...)
	t.Cleanup(func() { exec.Command("ip", "netns", "exec", ns, "tc", "qdisc", "del", "dev", dev, "root").Run() })
}

func sysctl(t *testing.T, ns, kv string) {
	k, _, _ := strings.Cut(kv, "=")
	old := strings.TrimSpace(nsx(t, ns, "sysctl", "-n", k))
	nsx(t, ns, "sysctl", "-qw", kv)
	t.Cleanup(func() { exec.Command("ip", "netns", "exec", ns, "sysctl", "-qw", k+"="+old).Run() })
}

type result struct {
	R      report.JSONReport
	Code   int
	Stdout string
	Stderr string
}

// fast are probing parameters that keep tests short in the lab (RTT << 1ms).
var fast = []string{"-i", "100ms", "--timeout", "100ms", "--responder-pps", "200", "--endpoint-pps", "2000"}

func mpmtr(t *testing.T, args ...string) result {
	t.Helper()
	all := append([]string{"netns", "exec", "mpsrc", bin}, args...)
	cmd := exec.Command("ip", all...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	r := result{Stdout: out.String(), Stderr: errb.String()}
	if ee, ok := err.(*exec.ExitError); ok {
		r.Code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(args, " "), "--json") {
		if e := json.Unmarshal(out.Bytes(), &r.R); e != nil {
			t.Fatalf("json: %v\nstdout: %.2000s\nstderr: %s", e, out.String(), errb.String())
		}
	}
	return r
}

func ep0(t *testing.T, r result) core.EPSnap {
	t.Helper()
	if r.R.Snapshot == nil || len(r.R.Snapshot.Endpoints) == 0 {
		t.Fatalf("no endpoint in result; code %d stderr %s", r.Code, r.Stderr)
	}
	return r.R.Snapshot.Endpoints[0]
}

// What a script relies on, in real runs: the process status equals the
// report's exit_code, a report that was cut short says so and why, and the
// text report carries the same status.
func TestReportStatusAndJSON(t *testing.T) {
	// Complete and healthy.
	r := mpmtr(t, append([]string{"-r", "-c", "40", "--json", "10.20.0.2:443"}, fast...)...)
	if r.Code != 0 || r.R.ExitCode != 0 || !r.R.Complete || len(r.R.Incomplete) != 0 {
		t.Errorf("healthy: status %d exit_code %d complete %v reasons %v", r.Code, r.R.ExitCode, r.R.Complete, r.R.Incomplete)
	}
	if r.R.Tool != "mpmtr" || r.R.Version == "" || r.R.Params.Mode != "report" || r.R.Params.PcapFilter == "" {
		t.Errorf("healthy: tool %q version %q parameters %v", r.R.Tool, r.R.Version, r.R.Params)
	}
	if !r.R.Finished.After(r.R.Started) {
		t.Errorf("healthy: started %v finished %v", r.R.Started, r.R.Finished)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(r.Stdout), &raw); err != nil || !strings.HasPrefix(string(raw["events"]), "[") {
		t.Errorf("healthy: events must be a list, got %.40s (err %v)", raw["events"], err)
	}

	// Complete, but too few probes for a verdict: UNKNOWN, status 3.
	r = mpmtr(t, append([]string{"-r", "-c", "5", "--json", "10.20.0.2:443"}, fast...)...)
	if r.Code != 3 || r.R.ExitCode != 3 || !r.R.Complete {
		t.Errorf("-c 5: status %d exit_code %d complete %v", r.Code, r.R.ExitCode, r.R.Complete)
	}
	if !strings.Contains(r.Stderr, "-c 5") {
		t.Errorf("-c 5: no note about the count on standard error: %q", r.Stderr)
	}

	// Cut short by the deadline: incomplete, status 3, with real counts.
	r = mpmtr(t, append([]string{"-r", "-c", "900", "--report-timeout", "5s", "--json", "10.20.0.2:443"}, fast...)...)
	reasons := strings.Join(r.R.Incomplete, "; ")
	if r.Code != 3 || r.R.ExitCode != 3 || r.R.Complete || !strings.Contains(reasons, "report-timeout reached") || !strings.Contains(reasons, "of 3600 E2E probes") {
		t.Errorf("deadline: status %d exit_code %d complete %v reasons %q", r.Code, r.R.ExitCode, r.R.Complete, reasons)
	}
	if e := ep0(t, r); len(e.Flows) == 0 || e.Flows[0].C.Sent == 0 {
		t.Errorf("deadline: the partial report has no counts")
	}

	// Interrupted: the report is still one whole JSON document, marked.
	cmd := exec.Command("ip", append([]string{"netns", "exec", "mpsrc", bin, "-r", "-c", "900", "--json", "10.20.0.2:443"}, fast...)...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Second)
	cmd.Process.Signal(syscall.SIGINT)
	err := cmd.Wait()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	}
	var ir report.JSONReport
	if e := json.Unmarshal(out.Bytes(), &ir); e != nil {
		t.Fatalf("interrupted: not JSON: %v\n%.500s\n%s", e, out.String(), errb.String())
	}
	if code != 3 || ir.ExitCode != 3 || ir.Complete || !strings.Contains(strings.Join(ir.Incomplete, "; "), "interrupted") {
		t.Errorf("interrupted: status %d exit_code %d complete %v reasons %v", code, ir.ExitCode, ir.Complete, ir.Incomplete)
	}

	// The text report says the same status in its first line.
	r = mpmtr(t, append([]string{"-r", "-c", "40", "10.20.0.2:443"}, fast...)...)
	if first, _, _ := strings.Cut(r.Stdout, "\n"); r.Code != 0 || !strings.HasSuffix(first, "exit 0") {
		t.Errorf("text: status %d, first line %q", r.Code, first)
	}
	r = mpmtr(t, append([]string{"-r", "-c", "900", "--report-timeout", "5s", "10.20.0.2:443"}, fast...)...)
	if first, rest, _ := strings.Cut(r.Stdout, "\n"); r.Code != 3 || !strings.HasSuffix(first, "exit 3") || !strings.HasPrefix(rest, "INCOMPLETE: ") {
		t.Errorf("text, deadline: status %d, first lines %q / %.80q", r.Code, first, rest)
	}

	// Discovery only: status 0 when it ran to its own stop.
	r = mpmtr(t, "--discover", "--json", "--responder-pps", "200", "10.20.0.2:443")
	if r.Code != 0 || r.R.ExitCode != 0 || !r.R.Complete || r.R.Params.Mode != "discover" {
		t.Errorf("discover: status %d exit_code %d complete %v mode %v", r.Code, r.R.ExitCode, r.R.Complete, r.R.Params.Mode)
	}

	// A wrong command line: status 4, nothing on standard output.
	r = mpmtr(t, "-r", "--no-such-option", "10.20.0.2:443")
	if r.Code != 4 || r.Stdout != "" || !strings.Contains(r.Stderr, "mpmtr:") {
		t.Errorf("bad option: status %d stdout %q stderr %q", r.Code, r.Stdout, r.Stderr)
	}
}

// tcpdump captures on a namespace interface until stop() is called.
type dump struct {
	cmd *exec.Cmd
	out bytes.Buffer
}

func startDump(t *testing.T, ns, dev string, filter ...string) *dump {
	d := &dump{}
	args := append([]string{"netns", "exec", ns, "tcpdump", "-l", "-nn", "-vv", "-i", dev}, filter...)
	d.cmd = exec.Command("ip", args...)
	d.cmd.Stdout = &d.out
	if err := d.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(700 * time.Millisecond)
	return d
}

func (d *dump) stop() string {
	time.Sleep(300 * time.Millisecond)
	d.cmd.Process.Signal(os.Interrupt)
	d.cmd.Wait()
	return d.out.String()
}

var sportRe = regexp.MustCompile(`10\.10\.0\.2\.(\d+) > 10\.20\.0\.2\.443`)

func flowsByGroup(e core.EPSnap) map[string][]core.FlowSnap {
	m := map[string][]core.FlowSnap{}
	for _, f := range e.Flows {
		m[f.Group] = append(m[f.Group], f)
	}
	return m
}

// The source ports really spread over the four arms (checked on the wire),
// and discovery groups flows exactly by arm.
func TestECMPDiscoveryMatchesWire(t *testing.T) {
	var dumps []*dump
	for i := 1; i <= 4; i++ {
		dumps = append(dumps, startDump(t, fmt.Sprintf("mpr%d", i), fmt.Sprintf("r%da", i), "tcp[tcpflags] & tcp-syn != 0 and dst port 443"))
	}
	r := mpmtr(t, append([]string{"-r", "-c", "50", "--json", "10.20.0.2:443"}, fast...)...)
	armOf := map[string]int{}
	for i, d := range dumps {
		for _, m := range sportRe.FindAllStringSubmatch(d.stop(), -1) {
			if a, ok := armOf[m[1]]; ok && a != i+1 {
				t.Fatalf("sport %s seen on arms %d and %d (not per-flow ECMP)", m[1], a, i+1)
			}
			armOf[m[1]] = i + 1
		}
	}
	e := ep0(t, r)
	arms := map[int]bool{}
	for _, f := range e.Flows {
		a, ok := armOf[fmt.Sprint(f.SPort)]
		if !ok {
			t.Fatalf("flow %s sport %d never seen on any arm", f.Name, f.SPort)
		}
		arms[a] = true
	}
	if len(arms) != 4 {
		t.Fatalf("monitored flows cover %d arms, want 4: %v", len(arms), armOf)
	}
	if e.Discovery.Branches != 4 {
		t.Fatalf("discovery found %d branches", e.Discovery.Branches)
	}
	for _, g := range e.Groups {
		arm := 0
		for _, p := range g.Ports {
			a, ok := armOf[fmt.Sprint(p)]
			if !ok {
				continue // discovery-only flow whose SYN went before the capture started
			}
			if arm == 0 {
				arm = a
			} else if a != arm {
				t.Fatalf("group %s mixes arms %d and %d", g.ID, arm, a)
			}
		}
		want := fmt.Sprintf("10.11.%d.2", arm)
		if !strings.Contains(g.Sig, want) {
			t.Fatalf("group %s signature %s does not show arm responder %s", g.ID, g.Sig, want)
		}
	}
	if e.State != core.EPOK || r.Code != 0 {
		t.Fatalf("state %s exit %d", e.State, r.Code)
	}
}

// 30% loss on one arm: only that arm's
// flows degrade, the endpoint is LOSS/PARTIAL and the localization points
// to that arm's segments. Runs of 5 losses in a row are frequent at 30%
// (55% of 450-probe runs); they must not make the flow DOWN.
func TestLossOneArm(t *testing.T) {
	netem(t, "mpr2", "r2b", "loss", "30%")
	r := mpmtr(t, append([]string{"-r", "-c", "450", "--json", "10.20.0.2:443"}, fast...)...)
	e := ep0(t, r)
	if e.State != core.EPLoss || e.Scope != core.ScopePartial || r.Code != 1 {
		t.Fatalf("endpoint %s/%s exit %d", e.State, e.Scope, r.Code)
	}
	for _, f := range e.Flows {
		onArm2 := false
		for _, g := range e.Groups {
			if g.ID == f.Group && strings.Contains(g.Sig, "10.11.2.2") {
				onArm2 = true
			}
		}
		if onArm2 && f.State != core.FLoss && f.State != core.FDown {
			t.Errorf("arm-2 flow %s state %s fail %s", f.Name, f.State, report.Pct(f.W5.FailureRate))
		}
		if !onArm2 && f.State != core.FOK {
			t.Errorf("healthy-arm flow %s state %s", f.Name, f.State)
		}
	}
	L := e.Localization
	if L.Level != core.LocSuspectedSegment {
		t.Fatalf("localization %+v", L)
	}
	found := false
	for _, s := range L.SuspectedSegments {
		if s == "10.11.2.2→10.12.2.2" {
			found = true
		}
		if strings.HasPrefix(s, "SRC") || strings.Contains(s, "10.10.0.1→") && !strings.Contains(s, "10.11.2.2") {
			t.Errorf("shared segment blamed: %s", s)
		}
	}
	if !found {
		t.Fatalf("lossy segment not among candidates: %v", L.SuspectedSegments)
	}
}

// A real outage on a lossy arm: 15% background loss, 15 s of 100% loss,
// then 15% again. The arm's flow is DOWN during the outage, recovers, and
// ends LOSS; the other arms stay OK.
//
// The outage is in the forward direction only, and it has to be this long.
// With 15% loss the RST that ends a handshake is sometimes lost just before
// the outage; the server then keeps the half-open connection and repeats
// its SYN/ACK 1, 3 and 7 s later. Those still arrive (the way back works),
// and for 3 s after each (the guard window) an unanswered probe is not
// counted as lost: a server that holds state for the 4-tuple may leave a
// new SYN unanswered. So the run of failures that makes the flow DOWN (at
// most 20 here) can start as late as 10 s into the outage, which is why the
// outage here lasts 15 s.
func TestOutageOnLossyArm(t *testing.T) {
	netem(t, "mpr2", "r2b", "loss", "15%")
	// When each step of the outage ran and whether tc failed: shown if the
	// test fails.
	var outage []string
	var omu sync.Mutex
	start := time.Now()
	step := func(loss string) {
		out, err := exec.Command("ip", "netns", "exec", "mpr2", "tc", "qdisc", "replace", "dev", "r2b", "root", "netem", "loss", loss).CombinedOutput()
		omu.Lock()
		outage = append(outage, fmt.Sprintf("loss %s at %.2fs err=%v %s", loss, time.Since(start).Seconds(), err, strings.TrimSpace(string(out))))
		omu.Unlock()
	}
	go func() {
		time.Sleep(30 * time.Second)
		step("100%")
		time.Sleep(15 * time.Second)
		step("15%")
	}()
	r := mpmtr(t, append([]string{"-r", "-c", "900", "--json", "10.20.0.2:443"}, fast...)...)
	e := ep0(t, r)
	arm2 := map[string]bool{}
	for _, f := range e.Flows {
		for _, g := range e.Groups {
			if g.ID == f.Group && strings.Contains(g.Sig, "10.11.2.2") {
				arm2[f.Name] = true
			}
		}
	}
	if len(arm2) == 0 {
		t.Fatal("no measured flow on the lossy arm")
	}
	// Simultaneous transitions are reported at the highest level that
	// describes them (e.g. PARTIAL_PATH_FAILURE): read each flow's own
	// transition.
	down, rec := false, false
	for _, ev := range r.R.Events {
		for _, fr := range ev.Flows {
			tr := fr.Transition
			if tr == core.EvNone {
				tr = ev.Type
			}
			if !arm2[fr.Flow] {
				if tr == core.EvFlowDown {
					t.Errorf("healthy-arm flow %s DOWN (%s)", fr.Flow, ev.Type)
				}
				continue
			}
			switch tr {
			case core.EvFlowDown:
				down = true
			case core.EvFlowRecovered:
				rec = true
			}
		}
	}
	if !down || !rec {
		var ts []string
		for _, ev := range r.R.Events {
			for _, fr := range ev.Flows {
				ts = append(ts, ev.Type.String()+":"+fr.Flow+":"+fr.Transition.String())
			}
		}
		// What decides DOWN, for the failure message.
		omu.Lock()
		t.Logf("outage steps: %v", outage)
		omu.Unlock()
		for _, f := range e.Flows {
			t.Logf("flow %s arm2=%v state=%s (%s) down_after_failures=%d consecutive_failures=%d", f.Name, arm2[f.Name], f.State, f.Reason, f.DownNeed, f.ConsecFail)
		}
		t.Fatalf("outage not seen as DOWN + RECOVERED on the lossy arm: %v", ts)
	}
	for _, f := range e.Flows {
		if arm2[f.Name] && f.State != core.FLoss {
			t.Errorf("lossy-arm flow %s ends %s (%s), want LOSS", f.Name, f.State, f.Reason)
		}
		if !arm2[f.Name] && f.State != core.FOK {
			t.Errorf("healthy-arm flow %s %s", f.Name, f.State)
		}
	}
}

// Loss on the common last segment: all flows degrade, no single branch is
// blamed (no healthy controls).
func TestLossCommonSegment(t *testing.T) {
	netem(t, "mprd", "rdd", "loss", "30%")
	r := mpmtr(t, append([]string{"-r", "-c", "450", "--json", "10.20.0.2:443"}, fast...)...)
	e := ep0(t, r)
	if e.State != core.EPLoss || e.Scope != core.ScopeAll {
		t.Fatalf("endpoint %s/%s", e.State, e.Scope)
	}
	if len(e.Localization.SuspectedSegments) > 0 || e.Localization.Level == core.LocSuspectedSegment {
		t.Fatalf("categorical localization without controls: %+v", e.Localization)
	}
}

// Higher RTT on one arm → relative RTT degradation of exactly that arm.
func TestRTTOneArm(t *testing.T) {
	netem(t, "mpr3", "r3b", "delay", "30ms")
	r := mpmtr(t, "-r", "-c", "450", "--json", "-i", "100ms", "--timeout", "100ms", "--responder-pps", "200", "--endpoint-pps", "2000", "10.20.0.2:443")
	e := ep0(t, r)
	for _, f := range e.Flows {
		slow := f.RTT.Median > 25000
		rel := f.Flags.Has(core.FlagRTTRelative)
		if slow != rel {
			t.Errorf("flow %s median %dus flags %v", f.Name, f.RTT.Median, f.Flags)
		}
	}
	if len(e.Hetero.RTTRelative) == 0 {
		t.Fatal("no relative RTT heterogeneity")
	}
}

// Higher RTT on the common segment after a healthy baseline → absolute
// degradation of all flows (no relative outliers).
func TestRTTCommonBaseline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	go func() {
		select {
		case <-time.After(45 * time.Second):
			exec.Command("ip", "netns", "exec", "mprd", "tc", "qdisc", "replace", "dev", "rdd", "root", "netem", "delay", "30ms").Run()
		case <-ctx.Done():
		}
	}()
	t.Cleanup(func() { exec.Command("ip", "netns", "exec", "mprd", "tc", "qdisc", "del", "dev", "rdd", "root").Run() })
	r := mpmtr(t, "-r", "-c", "900", "--json", "-i", "100ms", "--timeout", "100ms", "--responder-pps", "200", "--endpoint-pps", "2000", "--flows", "8", "10.20.0.2:443")
	e := ep0(t, r)
	for _, f := range e.Flows {
		if !f.Flags.Has(core.FlagRTTAbsolute) || f.Flags.Has(core.FlagRTTRelative) {
			t.Errorf("flow %s flags %v median %d baseline %d", f.Name, f.Flags, f.RTT.Median, f.RTT.Baseline)
		}
	}
}

// Destination unreachable → confirmed DOWN, exit 2.
func TestDestinationDown(t *testing.T) {
	netem(t, "mprd", "rdd", "loss", "100%")
	r := mpmtr(t, append([]string{"-r", "-c", "30", "--json", "10.20.0.2:443"}, fast...)...)
	e := ep0(t, r)
	if e.State != core.EPDown || e.Scope != core.ScopeAll || r.Code != 2 {
		t.Fatalf("%s/%s exit %d", e.State, e.Scope, r.Code)
	}
	if e.Discovery.Reason == "" {
		t.Fatal("no discovery stop reason")
	}
}

// Routers that never answer ICMP: E2E remains fully usable, hops show as
// silent, no hop is reported as transit loss.
func TestSilentRouters(t *testing.T) {
	for _, n := range []string{"mpr0", "mpr1", "mpr2", "mpr3", "mpr4", "mprd"} {
		sysctl(t, n, "net.ipv4.icmp_ratelimit=100000000")
		sysctl(t, n, "net.ipv4.icmp_ratemask=6168")
	}
	r := mpmtr(t, append([]string{"-r", "-c", "350", "--json", "10.20.0.2:443"}, fast...)...)
	e := ep0(t, r)
	if e.State != core.EPOK || r.Code != 0 {
		t.Fatalf("E2E must stay usable: %s exit %d", e.State, r.Code)
	}
	if e.Localization.Level != core.LocNone {
		t.Fatalf("%+v", e.Localization)
	}
}

// ICMP rate limiting on one router: apparent hop loss is flagged as possible
// rate limiting, not transit loss; E2E stays OK.
func TestICMPRateLimit(t *testing.T) {
	sysctl(t, "mpr0", "net.ipv4.icmp_ratelimit=1000")
	sysctl(t, "mpr0", "net.ipv4.icmp_msgs_per_sec=2")
	sysctl(t, "mpr0", "net.ipv4.icmp_msgs_burst=2")
	r := mpmtr(t, append([]string{"-r", "-c", "350", "--json", "--responder-pps", "50", "10.20.0.2:443"}, fast[:4]...)...)
	e := ep0(t, r)
	if e.State != core.EPOK {
		t.Fatalf("state %s", e.State)
	}
	flagged := false
	for _, row := range e.Tree {
		if !row.E2E && row.Hop.TTL == 1 && row.Hop.Loss != nil && *row.Hop.Loss > 0.05 && row.Hop.RateLimit {
			flagged = true
		}
	}
	if !flagged {
		t.Fatalf("TTL 1 rate limiting not flagged: %+v", e.Tree[0].Hop)
	}
}

// Route change during a live run: ROUTE_CHANGED events, no loss.
func TestRouteChange(t *testing.T) {
	evf := filepath.Join(t.TempDir(), "ev.jsonl")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	go func() {
		select {
		case <-time.After(40 * time.Second):
			// Arm 1 now routes via a different next hop for TTL 2.
			exec.Command("ip", "netns", "exec", "mpr0", "ip", "route", "replace", "10.20.0.0/24",
				"nexthop", "via", "10.11.2.2", "nexthop", "via", "10.11.3.2", "nexthop", "via", "10.11.4.2").Run()
		case <-ctx.Done():
		}
	}()
	t.Cleanup(func() {
		exec.Command("ip", "netns", "exec", "mpr0", "ip", "route", "replace", "10.20.0.0/24",
			"nexthop", "via", "10.11.1.2", "nexthop", "via", "10.11.2.2", "nexthop", "via", "10.11.3.2", "nexthop", "via", "10.11.4.2").Run()
	})
	r := mpmtr(t, "-r", "-c", "900", "--json", "--events", evf, "-i", "100ms", "--timeout", "100ms", "--responder-pps", "200", "--endpoint-pps", "2000", "10.20.0.2:443")
	b, _ := os.ReadFile(evf)
	if !strings.Contains(string(b), `"ROUTE_CHANGED"`) {
		t.Fatalf("no ROUTE_CHANGED event:\n%s", b)
	}
	e := ep0(t, r)
	for _, f := range e.Flows {
		if f.State == core.FLoss || f.State == core.FDown {
			t.Fatalf("route change reported as loss: %s %s", f.Name, f.State)
		}
	}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		var ev core.Event
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
			t.Fatalf("event line is not an event: %v: %s", err, sc.Text())
		}
		switch ev.Type {
		case core.EvEndpointDown, core.EvEndpointLoss, core.EvPartialPathFailure, core.EvGroupDown, core.EvGroupLoss,
			core.EvFlowDown, core.EvFlowLoss, core.EvFlowLossCleared:
			t.Errorf("unexpected event %s", sc.Text())
		}
	}
}

// Local SNAT of the probe source port → MEASUREMENT_INVALID, no false loss.
func TestLocalSNAT(t *testing.T) {
	nsx(t, "mpsrc", "iptables", "-t", "nat", "-A", "POSTROUTING", "-p", "tcp", "--sport", "20000:20255", "-j", "SNAT", "--to-source", "10.10.0.2:40000-40100")
	t.Cleanup(func() { exec.Command("ip", "netns", "exec", "mpsrc", "iptables", "-t", "nat", "-F").Run() })
	r := mpmtr(t, append([]string{"-r", "-c", "20", "--json", "--no-discovery", "--report-timeout", "20s", "10.20.0.2:443"}, fast...)...)
	e := ep0(t, r)
	if e.Agg.Invalid != e.Agg.Total || r.R.Snapshot.M.NATDetected == 0 {
		t.Fatalf("NAT not detected: agg %+v", e.Agg)
	}
	if e.State == core.EPDown || e.State == core.EPLoss || r.Code == 0 {
		t.Fatalf("state %s exit %d", e.State, r.Code)
	}
}

// A source port held by another local socket is never probed: from an
// explicit list it is skipped with a note naming it, from the default range
// silently.
func TestPortConflict(t *testing.T) {
	l := exec.Command("ip", "netns", "exec", "mpsrc", "python3", "-c",
		"import socket,time;s=socket.socket();s.bind(('0.0.0.0',20010));s.listen();time.sleep(60)")
	l.Start()
	defer l.Process.Kill()
	time.Sleep(500 * time.Millisecond)
	// A port used by another program is skipped (one note), never probed.
	r := mpmtr(t, "-r", "-c", "10", "--json", "--no-discovery", "--flows", "3", "--src-ports", "20010,20011,20012,20013", "10.20.0.2:443")
	if r.Code == 4 || !strings.Contains(r.Stderr, "20010") {
		t.Fatalf("exit %d stderr %q", r.Code, r.Stderr)
	}
	for _, f := range ep0(t, r).Flows {
		if f.SPort == 20010 {
			t.Fatalf("busy port 20010 was used")
		}
	}
	// Default range: busy ports are skipped silently.
	r = mpmtr(t, "-r", "-c", "10", "--json", "--no-discovery", "--flows", "16", "10.20.0.2:443")
	if r.Code == 4 || strings.Contains(r.Stderr, "20010") {
		t.Fatalf("default range: exit %d stderr %q", r.Code, r.Stderr)
	}
	for _, f := range ep0(t, r).Flows {
		if f.SPort == 20010 {
			t.Fatalf("busy port 20010 was used")
		}
	}
}

// Capture drops (tiny ring + stalled reader) are measurement impairment,
// never a network DOWN: drop periods are registered and announced with
// MONITORING_IMPAIRED, and every timeout overlapping a drop period becomes
// capture_impaired (the lab fabric itself loses nothing, so no timeout may
// remain).
func TestCaptureDrops(t *testing.T) {
	evf := filepath.Join(t.TempDir(), "ev.jsonl")
	cmd := exec.Command("ip", "netns", "exec", "mpsrc", bin, "-r", "-c", "300", "--json", "--no-discovery", "--events", evf,
		"-i", "50ms", "--timeout", "50ms", "--flows", "32", "--endpoint-pps", "5000", "10.20.0.2:443")
	cmd.Env = append(os.Environ(), "MPMTR_RING_BLOCK_SIZE=4096", "MPMTR_RING_BLOCKS=2")
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		if _, ok := err.(*exec.ExitError); !ok {
			t.Fatal(err)
		}
	}
	var rep report.JSONReport
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatal(err, out.String())
	}
	e := rep.Snapshot.Endpoints[0]
	m := rep.Snapshot.M
	if m.CaptureDrops+m.UserDrops == 0 {
		t.Skip("could not induce capture drops on this kernel")
	}
	if e.State == core.EPDown || e.Agg.Down > 0 {
		t.Fatalf("capture drops became DOWN: %+v", e.Agg)
	}
	if m.ImpairedPeriods == 0 {
		t.Fatal("drop periods not registered")
	}
	var imp, tmo uint64
	for _, f := range e.Flows {
		imp += f.C.Impaired
		tmo += f.C.Timeout
	}
	if imp == 0 || tmo != 0 {
		t.Fatalf("drop periods not attributed to waiting probes: impaired %d, timeouts %d (lab fabric has no real loss)", imp, tmo)
	}
	b, _ := os.ReadFile(evf)
	if !strings.Contains(string(b), "MONITORING_IMPAIRED") {
		t.Fatalf("no MONITORING_IMPAIRED event (drops %d):\n%s", m.CaptureDrops, b)
	}
	t.Logf("capture drops %d, impaired probes %d, timeouts %d", m.CaptureDrops,
		func() (n uint64) {
			for _, f := range e.Flows {
				n += f.C.Impaired
			}
			return
		}(),
		func() (n uint64) {
			for _, f := range e.Flows {
				n += f.C.Timeout
			}
			return
		}())
}

// A SYN/ACK with a wrong ACK number (middlebox) is a weak reply, not a
// success, and must not produce a false DOWN.
func TestWrongAck(t *testing.T) {
	// Drop the kernel's genuine SYN/ACK but not the injector's (SO_MARK 7),
	// which carries ack+1000.
	nsx(t, "mpdst", "iptables", "-A", "OUTPUT", "-p", "tcp", "--sport", "8443", "-m", "mark", "!", "--mark", "7", "-j", "DROP")
	t.Cleanup(func() { exec.Command("ip", "netns", "exec", "mpdst", "iptables", "-F").Run() })
	py := `
import socket,struct
s=socket.socket(socket.AF_PACKET,socket.SOCK_DGRAM,socket.htons(0x0800))
r=socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_TCP)
r.setsockopt(socket.SOL_SOCKET,36,7)
def cs(b):
    if len(b)%2: b+=b'\0'
    s_=sum(struct.unpack('!%dH'%(len(b)//2),b)); s_=(s_>>16)+(s_&0xffff); s_+=s_>>16; return ~s_&0xffff
while True:
    p,_=s.recvfrom(2000)
    if p[9]!=6: continue
    ihl=(p[0]&15)*4; t=p[ihl:]
    sp,dp,seq=struct.unpack('!HHI',t[:8]); fl=t[13]
    if dp!=8443 or fl!=2: continue
    src,dst=p[12:16],p[16:20]
    h=struct.pack('!HHIIBBHHH',dp,sp,777,(seq+1001)&0xffffffff,5<<4,0x12,65535,0,0)
    c=cs(dst+src+struct.pack('!BBH',0,6,20)+h)
    h=h[:16]+struct.pack('!H',c)+h[18:]
    r.sendto(h,(socket.inet_ntoa(src),0))
`
	inj := exec.Command("ip", "netns", "exec", "mpdst", "python3", "-c", py)
	inj.Start()
	defer inj.Process.Kill()
	srv := exec.Command("ip", "netns", "exec", "mpdst", "python3", "-m", "http.server", "8443")
	srv.Start()
	defer srv.Process.Kill()
	time.Sleep(time.Second)
	r := mpmtr(t, append([]string{"-r", "-c", "30", "--json", "--no-discovery", "--flows", "4", "10.20.0.2:8443"}, fast...)...)
	e := ep0(t, r)
	if e.State == core.EPDown || e.State == core.EPOK {
		t.Fatalf("state %s (weak replies must neither be success nor DOWN)", e.State)
	}
	for _, f := range e.Flows {
		if f.C.SynAck != 0 || f.C.Weak == 0 {
			t.Fatalf("flow %s counters %+v", f.Name, f.C)
		}
		if !f.Flags.Has(core.FlagSeqTranslation) {
			t.Fatalf("flags %v", f.Flags)
		}
	}
}

// SYN/ACK arriving after the deadline: counted as late, never credited.
func TestLateSynAck(t *testing.T) {
	netem(t, "mprd", "rd1", "delay", "300ms")
	netem(t, "mprd", "rd2", "delay", "300ms")
	netem(t, "mprd", "rd3", "delay", "300ms")
	netem(t, "mprd", "rd4", "delay", "300ms")
	r := mpmtr(t, "-r", "-c", "15", "--json", "--no-discovery", "--flows", "4", "-i", "200ms", "--timeout", "200ms", "10.20.0.2:443")
	e := ep0(t, r)
	for _, f := range e.Flows {
		if f.C.SynAck != 0 || f.C.Late == 0 {
			t.Fatalf("%s %+v", f.Name, f.C)
		}
	}
}

// IPv6: raw SYN with fixed flow label and traffic class on the wire, hop
// limit varies for hop probes only.
func TestIPv6FlowLabel(t *testing.T) {
	d := startDump(t, "mpr0", "r0s", "ip6 and tcp dst port 443")
	r := mpmtr(t, append([]string{"-r", "-c", "40", "--json", "--flow-label", "74565", "--tos", "40", "[fd20::2]:443"}, fast...)...)
	out := d.stop()
	e := ep0(t, r)
	if e.State != core.EPOK {
		t.Fatalf("state %s", e.State)
	}
	lines := 0
	for _, l := range strings.Split(out, "\n") {
		if !strings.Contains(l, "flowlabel") || !strings.Contains(l, "Flags [S]") {
			continue // only our SYNs (kernel RSTs carry the kernel's own flow label)
		}
		lines++
		if !strings.Contains(l, "flowlabel 0x12345") || !strings.Contains(l, "class 0x28") {
			t.Fatalf("identity changed on the wire: %s", l)
		}
	}
	if lines < 100 {
		t.Fatalf("only %d SYNs captured", lines)
	}
	if e.Discovery.Branches != 4 {
		t.Fatalf("IPv6 branches %d", e.Discovery.Branches)
	}

	// The real connection of an application check has the same identity:
	// the kernel would otherwise give every connection a label of its own,
	// and a router that balances on the label would lead the check another
	// way than the probes of its port. With no label set, none is sent.
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"--flow-label", "74565", "--tos", "40"}, "flowlabel 0x12345"},
		{nil, ""},
	} {
		d := startDump(t, "mpr0", "r0s", "ip6 and tcp dst port 443")
		args := append([]string{"-r", "-c", "60", "--json", "--app", "http", "--app-interval", "1s", "--app-timeout", "500ms"}, tc.args...)
		r := mpmtr(t, append(append(args, "[fd20::2]:443"), fast...)...)
		out := d.stop()
		checks := uint64(0)
		for _, f := range ep0(t, r).Flows {
			checks += f.C.AppSent
			if f.C.AppFail != 0 {
				t.Errorf("%v: application checks failed on %s", tc.args, f.Name)
			}
		}
		conn := 0
		for _, l := range strings.Split(out, "\n") {
			if !strings.Contains(l, "Flags [") || strings.Contains(l, "Flags [S]") || strings.Contains(l, "Flags [R]") {
				continue // probes, and the kernel's RST that answers a probe's SYN/ACK
			}
			conn++
			if tc.want != "" && (!strings.Contains(l, tc.want) || !strings.Contains(l, "class 0x28")) {
				t.Fatalf("%v: a packet of a check's connection without the probes' identity: %s", tc.args, l)
			}
			if tc.want == "" && strings.Contains(l, "flowlabel") {
				t.Fatalf("no label set, but a check's connection carries one: %s", l)
			}
		}
		if checks == 0 || conn < int(checks) {
			t.Fatalf("%v: %d application checks, %d packets of their connections captured", tc.args, checks, conn)
		}
	}
}

// A server that takes connections and answers nonsense: TCP is fine on every
// probe, the application is not. The checks are counted apart from the TCP
// probes, and their run makes the endpoint DOWN although no TCP probe failed.
func TestAppDownWhileTCPAnswers(t *testing.T) {
	srv := exec.Command("ip", "netns", "exec", "mpdst", "python3", "-c", `
import socket
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", 8444)); s.listen(64)
while True:
    c, _ = s.accept()
    try:
        c.settimeout(1); c.recv(4096); c.sendall(b"not what you asked for\r\n")
    except OSError:
        pass
    c.close()
`)
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer srv.Process.Kill()
	time.Sleep(500 * time.Millisecond)
	r := mpmtr(t, append([]string{"-r", "-c", "150", "--json", "--app", "http", "--app-interval", "1s", "--app-timeout", "500ms", "10.20.0.2:8444"}, fast...)...)
	e := ep0(t, r)
	if e.State != core.EPDown || r.Code != 2 {
		t.Fatalf("state %s, exit %d: want DOWN and 2", e.State, r.Code)
	}
	if e.W5.Timeout+e.W5.Unreach != 0 || e.W5.App == 0 || e.W5.AppFail != e.W5.App {
		t.Fatalf("TCP timeouts %d, unreachable %d; application checks %d of %d failed", e.W5.Timeout, e.W5.Unreach, e.W5.AppFail, e.W5.App)
	}
	if e.W5.FailureRate == nil || *e.W5.FailureRate != 0 || e.W5.AppFailRate == nil || *e.W5.AppFailRate != 1 {
		t.Fatalf("rates: TCP %v, application %v", e.W5.FailureRate, e.W5.AppFailRate)
	}
	for _, f := range e.Flows {
		if f.Role.Monitored() && (f.State != core.FDown || f.Reason != core.ReasonAppDown) {
			t.Errorf("flow %s: %s (%s), want DOWN (app_down)", f.Name, f.State, f.Reason)
		}
	}
}

// Bound-only reservation sockets do not stop the kernel from answering
// SYN/ACK with RST, and TX/RX kernel timestamps are used.
func TestKernelRSTAndTimestamps(t *testing.T) {
	netem(t, "mprd", "rdd", "delay", "20ms")
	d := startDump(t, "mpr0", "r0s", "tcp and port 443")
	r := mpmtr(t, "-r", "-c", "30", "--json", "--no-discovery", "--flows", "4", "-i", "200ms", "--timeout", "200ms", "10.20.0.2:443")
	out := d.stop()
	synack := strings.Count(out, "Flags [S.]")
	rst := strings.Count(out, "Flags [R]")
	if synack == 0 || rst < synack {
		t.Fatalf("SYN/ACK %d but kernel RST %d", synack, rst)
	}
	e := ep0(t, r)
	m := r.R.Snapshot.M
	if m.TxTSFallback != 0 {
		t.Fatalf("tx timestamp fallback used %d times", m.TxTSFallback)
	}
	for _, f := range e.Flows {
		if f.C.RstMissing != 0 {
			t.Fatalf("%s RstMissing %d", f.Name, f.C.RstMissing)
		}
		if f.RTT.Median < 20000 || f.RTT.Median > 23000 {
			t.Fatalf("%s RTT median %dus, want ~20ms (netem)", f.Name, f.RTT.Median)
		}
	}
}

// Routes of different lengths: one arm gets three more routers, and the
// short arms are slowed down so that the long route is the first one whose
// length is known. A port of a short arm then has several TTL-limited SYNs
// of one burst reach the destination together. Every route is found with
// its own length, and the ports stay measurable.
func TestUnequalRouteLengths(t *testing.T) {
	extra := []string{"mpx1", "mpx2", "mpx3"}
	t.Cleanup(func() {
		for _, n := range extra {
			exec.Command("ip", "netns", "del", n).Run()
		}
		exec.Command("ip", "netns", "exec", "mpr4", "ip", "route", "replace", "10.20.0.0/24", "via", "10.12.4.2").Run()
		exec.Command("ip", "netns", "exec", "mpr4", "ip", "route", "del", "10.13.0.0/16").Run()
		exec.Command("ip", "netns", "exec", "mpr0", "ip", "route", "del", "10.13.0.0/16").Run()
	})
	for _, n := range extra {
		sh(t, "ip", "netns", "add", n)
		nsx(t, n, "ip", "link", "set", "lo", "up")
		nsx(t, n, "sysctl", "-qw", "net.ipv4.ip_forward=1", "net.ipv4.icmp_ratelimit=0")
	}
	link := func(nsA, devA, addrA, nsB, devB, addrB string) {
		sh(t, "ip", "link", "add", devA, "netns", nsA, "type", "veth", "peer", "name", devB, "netns", nsB)
		nsx(t, nsA, "ip", "addr", "add", addrA, "dev", devA)
		nsx(t, nsB, "ip", "addr", "add", addrB, "dev", devB)
		nsx(t, nsA, "ip", "link", "set", devA, "up")
		nsx(t, nsB, "ip", "link", "set", devB, "up")
	}
	link("mpr4", "r4x", "10.13.1.1/24", "mpx1", "x1a", "10.13.1.2/24")
	link("mpx1", "x1b", "10.13.2.1/24", "mpx2", "x2a", "10.13.2.2/24")
	link("mpx2", "x2b", "10.13.3.1/24", "mpx3", "x3a", "10.13.3.2/24")
	link("mpx3", "x3b", "10.13.4.1/24", "mprd", "rdx", "10.13.4.2/24")
	for _, r := range [][]string{
		{"mpr4", "10.20.0.0/24", "10.13.1.2"}, {"mpr4", "10.13.0.0/16", "10.13.1.2"}, {"mpr0", "10.13.0.0/16", "10.11.4.2"},
		{"mpx1", "10.20.0.0/24", "10.13.2.2"}, {"mpx1", "10.10.0.0/16", "10.13.1.1"}, {"mpx1", "10.13.0.0/16", "10.13.2.2"},
		{"mpx2", "10.20.0.0/24", "10.13.3.2"}, {"mpx2", "10.10.0.0/16", "10.13.2.1"}, {"mpx2", "10.13.4.0/24", "10.13.3.2"},
		{"mpx3", "10.20.0.0/24", "10.13.4.2"}, {"mpx3", "10.10.0.0/16", "10.13.3.1"},
	} {
		nsx(t, r[0], "ip", "route", "replace", r[1], "via", r[2])
	}
	for _, i := range []string{"1", "2", "3"} {
		netem(t, "mpr0", "r0b"+i, "delay", "150ms")
	}
	d := startDump(t, "mpsrc", "s0", "tcp", "and", "src", "host", "10.20.0.2")
	r := mpmtr(t, "-r", "-c", "30", "--json", "10.20.0.2:443")
	out := d.stop()
	e := ep0(t, r)
	if r.Code != 0 || len(e.Groups) != 4 {
		t.Fatalf("exit %d, %d routes; stderr %s", r.Code, len(e.Groups), r.Stderr)
	}
	long := 0
	for _, f := range e.Flows {
		want := core.TTL(4)
		if strings.Contains(f.Sig, "10.13.") {
			want, long = 7, long+1
		}
		if f.Distance != want || f.State != core.FOK || f.C.Unexpected != 0 || f.C.Weak != 0 || f.Invalid != core.ValidFlow {
			t.Fatalf("%s %s: distance %d (its route has %d), state %s, unexpected %d, weak %d, invalid %q",
				f.Name, f.Sig, f.Distance, want, f.State, f.C.Unexpected, f.C.Weak, f.Invalid)
		}
	}
	if long != 1 {
		t.Fatalf("%d measured ports on the long route", long)
	}
	// The premise: some port did get the destination's answers to more than
	// one SYN of a burst (the answers leave together, 150 ms after the SYNs).
	got := map[string]int{}
	at := ""
	for _, l := range strings.Split(out, "\n") {
		f := strings.Fields(l)
		switch {
		case len(l) > 11 && l[0] >= '0' && l[0] <= '9':
			at = l[:11] // the time, to 10 ms
		case len(f) > 2 && strings.Contains(l, "Flags [S.]"):
			got[at+" "+f[2]]++ // and the port answered
		}
	}
	burst := 0
	for _, n := range got {
		burst = max(burst, n)
	}
	if burst < 2 {
		t.Fatalf("no port had two answers of the destination within 10 ms: the test did not exercise the case")
	}
}

// --discover finds the four routes and stops by its own rule: exit 0.
func TestDiscoverMode(t *testing.T) {
	r := mpmtr(t, "--discover", "--json", "--responder-pps", "200", "10.20.0.2:443")
	e := ep0(t, r)
	if e.Discovery.Reason == "" || e.Discovery.Branches != 4 || r.Code != 0 {
		t.Fatalf("%+v code %d", e.Discovery, r.Code)
	}
}

// Hop-information plugins: two at once, each a separate program speaking
// JSON lines; the name of the first and the notes of both reach the report,
// and a plugin that dies does not disturb the measurement.
func TestHopInfoPlugins(t *testing.T) {
	dir := t.TempDir()
	script := func(name, answer string) string {
		p := filepath.Join(dir, "mpmtr-hop-"+name)
		body := "#!/bin/sh\necho '{\"type\":\"hello\",\"name\":\"" + name + "\",\"version\":\"1\"}'\n" +
			"while read l; do id=${l#*\\\"id\\\":}; id=${id%%,*}; " + answer + "; done\n"
		if err := os.WriteFile(p, []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
		return p
	}
	names := script("names", `echo "{\"type\":\"info\",\"id\":$id,\"name\":\"rtr-lab\",\"note\":\"Eth1\"}"`)
	sites := script("sites", `echo "{\"type\":\"info\",\"id\":$id,\"note\":\"rack 7\"}"`)
	dies := script("dies", `exit 3`)
	r := mpmtr(t, "--discover", "--json", "--responder-pps", "200", "--hop-info", names, "--hop-info", sites, "10.20.0.2:443")
	hi := r.R.HopInfo
	if r.Code != 0 || len(hi) == 0 {
		t.Fatalf("code %d hop_info %v stderr %s", r.Code, r.R.HopInfo, r.Stderr)
	}
	for addr, v := range hi {
		n, s := v["names"], v["sites"]
		if n.Name != "rtr-lab" || n.Note != "Eth1" || s.Note != "rack 7" {
			t.Fatalf("%s: %v", addr, v)
		}
	}
	r = mpmtr(t, "--discover", "--responder-pps", "200", "--hop-info", names, "--hop-info", sites, "10.20.0.2:443")
	if !strings.Contains(r.Stdout, "rtr-lab (10.") || !strings.Contains(r.Stdout, "Eth1 rack 7") || !strings.Contains(r.Stdout, "Jttr PLUGIN      FLAGS") {
		t.Fatalf("text report lacks the plugins' name and notes:\n%s", r.Stdout)
	}
	// with a refresh interval the report is the same
	r = mpmtr(t, "--discover", "--responder-pps", "200", "--hop-info", names, "--hop-info", sites, "--hop-info-interval", "1s", "10.20.0.2:443")
	if r.Code != 0 || !strings.Contains(r.Stdout, "rtr-lab (10.") || !strings.Contains(r.Stdout, "Eth1 rack 7") {
		t.Fatalf("with --hop-info-interval: code %d\n%s\n%s", r.Code, r.Stdout, r.Stderr)
	}
	r = mpmtr(t, "--discover", "--json", "--responder-pps", "200", "--hop-info", dies, "--hop-info", sites, "10.20.0.2:443")
	if e := ep0(t, r); r.Code != 0 || e.Discovery.Branches != 4 {
		t.Fatalf("with a dying plugin: code %d %+v", r.Code, e.Discovery)
	}
	if w := strings.Join(r.R.Warnings, "\n"); !strings.Contains(w, "hop-info plugin dies stopped") {
		t.Fatalf("no warning about the dead plugin: %q", w)
	}
}

// Local ECMP: with a multipath default route on the source host and an L4
// hash policy, each flow must leave through the interface of its own
// port-aware route lookup (checked on the wire), never through another one.
func TestLocalECMP(t *testing.T) {
	nsx(t, "mpsrc", "ip", "route", "replace", "default", "nexthop", "via", "10.10.0.1", "dev", "s0", "nexthop", "via", "10.10.1.1", "dev", "s1")
	t.Cleanup(func() {
		exec.Command("ip", "netns", "exec", "mpsrc", "ip", "route", "replace", "default", "via", "10.10.0.1").Run()
	})
	d0 := startDump(t, "mpr0", "r0s", "tcp[tcpflags] & tcp-syn != 0 and dst port 443")
	d1 := startDump(t, "mpr0", "r0t", "tcp[tcpflags] & tcp-syn != 0 and dst port 443")
	r := mpmtr(t, append([]string{"-r", "-c", "20", "--json", "--no-discovery", "--flows", "16", "10.20.0.2:443"}, fast...)...)
	o0, o1 := d0.stop(), d1.stop()
	if !strings.Contains(strings.Join(r.R.Warnings, "\n"), "local multipath") {
		t.Fatalf("no local multipath note: %v", r.R.Warnings)
	}
	e := ep0(t, r)
	re := regexp.MustCompile(`(10\.10\.[01]\.2)\.(\d+) > 10\.20\.0\.2\.443`)
	seen := map[string]map[string]bool{"r0s": {}, "r0t": {}}
	for dev, out := range map[string]string{"r0s": o0, "r0t": o1} {
		for _, m := range re.FindAllStringSubmatch(out, -1) {
			seen[dev][m[1]+":"+m[2]] = true
		}
	}
	used := map[string]bool{}
	for _, f := range e.Flows {
		if f.State == core.FInvalid || f.C.EgressMismatch > 0 {
			t.Fatalf("flow %s egress mismatch %d", f.Name, f.C.EgressMismatch)
		}
		want := "r0s"
		if f.Src == netip.MustParseAddr("10.10.1.2") {
			want = "r0t"
		}
		other := map[string]string{"r0s": "r0t", "r0t": "r0s"}[want]
		k := fmt.Sprintf("%s:%d", f.Src, f.SPort)
		if !seen[want][k] || seen[other][k] {
			t.Fatalf("flow %s (%s) not exclusively on %s", f.Name, k, want)
		}
		used[want] = true
	}
	if len(used) != 2 {
		t.Fatalf("all flows on one local nexthop: %v", used)
	}
	t.Logf("local ECMP: flows spread over %d source links and each verified on its link", len(used))
}

// Bound-only reservation: the kernel does not hand reserved ports to
// connect() autobind, a SO_REUSEADDR bind cannot steal them, and (see
// TestKernelRSTAndTimestamps / IPv6 test) SYN/ACKs still get kernel RSTs.
func TestReservation(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		name := map[bool]string{false: "ipv4", true: "ipv6"}[v6]
		t.Run(name, func(t *testing.T) {
			sysctl(t, "mpsrc", "net.ipv4.ip_local_port_range=20000 20003")
			target, fam, host := "10.20.0.2:443", "AF_INET", "10.20.0.2"
			if v6 {
				target, fam, host = "[fd20::2]:443", "AF_INET6", "fd20::2"
			}
			cmd := exec.Command("ip", "netns", "exec", "mpsrc", bin, "--events", "-", "--no-discovery", "--flows", "3",
				"--src-ports", "20000,20001,20002", target)
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() { cmd.Process.Signal(os.Interrupt); cmd.Wait() }()
			time.Sleep(2 * time.Second)
			py := fmt.Sprintf(`
import socket,errno
ports=[]
for i in range(4):
    s=socket.socket(socket.%s)
    try:
        s.connect(("%s",443)); ports.append(s.getsockname()[1])
    except OSError as e:
        ports.append("ERR"+str(e.errno))
r=socket.socket(socket.%s); r.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
try:
    r.bind(("", 20001)); print("STOLEN")
except OSError:
    print("REUSEADDR_REFUSED")
print(ports)`, fam, host, fam)
			out := nsx(t, "mpsrc", "python3", "-c", py)
			if !strings.Contains(out, "REUSEADDR_REFUSED") {
				t.Fatalf("SO_REUSEADDR bind took a reserved port: %s", out)
			}
			for _, p := range []string{"20000", "20001", "20002"} {
				if strings.Contains(out, " "+p+",") || strings.Contains(out, "["+p+",") || strings.Contains(out, " "+p+"]") {
					t.Fatalf("reserved port %s handed out by autobind: %s", p, out)
				}
			}
			if !strings.Contains(out, "20003") {
				t.Fatalf("free port not used: %s", out)
			}
		})
	}
}

// IPv6 kernel RST after SYN/ACK with the reservation socket in place.
func TestIPv6KernelRST(t *testing.T) {
	d := startDump(t, "mpr0", "r0s", "ip6 and tcp port 443")
	r := mpmtr(t, append([]string{"-r", "-c", "20", "--json", "--no-discovery", "--flows", "4", "[fd20::2]:443"}, fast...)...)
	out := d.stop()
	sa, rst := strings.Count(out, "Flags [S.]"), strings.Count(out, "Flags [R]")
	if sa == 0 || rst < sa {
		t.Fatalf("v6 SYN/ACK %d RST %d", sa, rst)
	}
	for _, f := range ep0(t, r).Flows {
		if f.C.RstMissing != 0 || f.C.SynAck == 0 {
			t.Fatalf("%s %+v", f.Name, f.C)
		}
	}
}

// Smoke test: a stateful middlebox (conntrack, INVALID dropped) on the path
// while hop and E2E probes share 4-tuples: nothing is lost to the middlebox.
// (That sequence numbers only move forward, which stricter middleboxes
// require, is checked by the TestSeqMonotonic* unit tests.)
func TestConntrackMiddleboxSmoke(t *testing.T) {
	nsx(t, "mpr0", "iptables", "-A", "FORWARD", "-m", "conntrack", "--ctstate", "INVALID", "-j", "DROP")
	t.Cleanup(func() { exec.Command("ip", "netns", "exec", "mpr0", "iptables", "-F", "FORWARD").Run() })
	sysctl(t, "mpr0", "net.netfilter.nf_conntrack_tcp_be_liberal=0")
	r := mpmtr(t, append([]string{"-r", "-c", "300", "--json", "10.20.0.2:443"}, fast...)...)
	e := ep0(t, r)
	if e.State != core.EPOK {
		t.Fatalf("state %s", e.State)
	}
	for _, f := range e.Flows {
		if f.C.Timeout != 0 {
			t.Fatalf("%s: %d timeouts behind a conntrack middlebox", f.Name, f.C.Timeout)
		}
	}
}
