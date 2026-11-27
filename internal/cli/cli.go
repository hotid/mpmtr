// Package cli parses and validates the command line and runs the selected
// mode. All parameters are validated before any probe is sent.
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"regexp"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/hotid/mpmtr/internal/wire"

	"golang.org/x/term"

	"github.com/hotid/mpmtr/internal/app"
	"github.com/hotid/mpmtr/internal/core"
	"github.com/hotid/mpmtr/internal/report"
	"github.com/hotid/mpmtr/internal/sys"
	"github.com/hotid/mpmtr/internal/ui"
)

// Version of mpmtr, set at build time (make sets it from git describe):
// -ldflags "-X github.com/hotid/mpmtr/internal/cli.Version=v1.2.3".
// Without it (go install, go build) the module version Go recorded in the
// binary is used.
var Version = ""

func init() {
	if Version == "" {
		Version = moduleVersion(debug.ReadBuildInfo())
	}
}

// moduleVersion is the version from the build info, as "make" names it
// (git describe): the tag of a tagged build ("go install …@v1.2.3", a
// checkout at a tag), otherwise the commit (a9681d3, with -dirty for
// uncommitted changes) in place of Go's pseudo-version; "devel" when Go
// recorded neither.
func moduleVersion(bi *debug.BuildInfo, ok bool) string {
	if !ok {
		return "devel"
	}
	v := bi.Main.Version
	if v != "" && v != "(devel)" && !pseudoVersion.MatchString(v) {
		return v
	}
	rev, dirty := "", strings.HasSuffix(v, "+dirty")
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.modified":
			dirty = s.Value == "true"
		}
	}
	if rev == "" {
		if m := pseudoVersion.FindStringSubmatch(v); m != nil {
			rev = m[1]
		}
	}
	if rev == "" {
		return "devel"
	}
	rev = rev[:min(len(rev), 7)]
	if dirty {
		rev += "-dirty"
	}
	return rev
}

// pseudoVersion matches the end of a Go pseudo-version
// (v0.0.0-20261127120255-a9681d3c0d53, v0.1.3-0.20261127120255-…).
var pseudoVersion = regexp.MustCompile(`[-.]\d{14}-([0-9a-f]{12})(\+dirty)?$`)

// Exit codes (report mode). Priority across endpoints: execution error,
// confirmed DOWN, insufficient data, degradation, OK.
const (
	ExitOK       = 0
	ExitLoss     = 1
	ExitDown     = 2
	ExitUnknown  = 3
	ExitError    = 4
	DefaultPort  = 443
	usageSummary = "usage: mpmtr [options] target[:port]...   (mpmtr --help for options)"
)

type flags struct {
	report, json, noDNS, dns, v4, v6, discover, noDiscovery, noQuoteFallback, sharedHops, anycast, help, version bool
	asn, ix                                                                                                      bool
	geoip                                                                                                        string
	hopInfoInterval                                                                                              time.Duration
	hopInfo                                                                                                      multiFlag
	app                                                                                                          string
	appInterval, appTimeout                                                                                      time.Duration
	traceOnFailure                                                                                               bool
	count, flows, maxTTL, maxInflight, tos, fwmark                                                               int
	flowLabel                                                                                                    int
	interval, timeout, hopTimeout, reportTimeout                                                                 time.Duration
	pps, endpointPPS, responderPPS                                                                               float64
	sportRange, srcPorts, src, iface, events                                                                     string
	set                                                                                                          map[string]bool
}

func newFlagSet(f *flags, out io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet("mpmtr", flag.ContinueOnError)
	if out == nil {
		out = io.Discard
	}
	fs.SetOutput(out)
	b := func(p *bool, def bool, usage string, names ...string) {
		for _, n := range names {
			fs.BoolVar(p, n, def, usage)
		}
	}
	i := func(p *int, def int, usage string, names ...string) {
		for _, n := range names {
			fs.IntVar(p, n, def, usage)
		}
	}
	d := func(p *time.Duration, def time.Duration, usage string, names ...string) {
		*p = def
		for _, n := range names {
			fs.Var((*secDuration)(p), n, usage)
		}
	}
	fl := func(p *float64, def float64, usage string, names ...string) {
		for _, n := range names {
			fs.Float64Var(p, n, def, usage)
		}
	}
	s := func(p *string, def string, usage string, names ...string) {
		for _, n := range names {
			fs.StringVar(p, n, def, usage)
		}
	}
	b(&f.report, false, "report mode: run -c E2E probes per flow, print a report and exit", "r", "report")
	i(&f.count, 0, "E2E probes actually executed per flow (report default 100; live: stop after N)", "c", "count")
	d(&f.interval, time.Second, "E2E interval per flow", "i", "interval")
	d(&f.timeout, time.Second, "E2E reply deadline (must not exceed --interval)", "timeout")
	d(&f.hopTimeout, 0, "hop probe deadline (default min(timeout, interval/2))", "hop-timeout")
	i(&f.flows, 1, "source ports measured per route (with --no-discovery: ports measured in total)", "flows")
	s(&f.sportRange, "20000-20255", "source port range, used in order (--anycast: default 20000-22047)", "sport-range")
	s(&f.srcPorts, "", "explicit source ports, comma separated (overrides --sport-range)", "src-ports")
	i(&f.maxTTL, 30, "maximum TTL / hop limit for traces", "max-ttl")
	fl(&f.pps, 1000, "global probe rate limit (packets/s)", "pps")
	fl(&f.endpointPPS, 500, "per-endpoint probe rate limit (packets/s)", "endpoint-pps")
	i(&f.maxInflight, 0, "maximum probes in flight (0 = derived from --pps and --timeout)", "max-inflight")
	fs.BoolVar(&f.sharedHops, "shared-hops", false, "probe a hop shared by several measured ports from one of them only")
	fs.BoolVar(&f.anycast, "anycast", false, "tell the servers behind the address apart (TCP timestamp clocks) and measure every one")
	fs.StringVar(&f.app, "app", "", "application check plugin: \"NAME [ARGS]\" (mpmtr-app-NAME next to mpmtr or in PATH, or a path)")
	fs.Var(&f.hopInfo, "hop-info", "hop information plugin: \"NAME [ARGS]\" (mpmtr-hop-NAME next to mpmtr or in PATH, or a path); repeatable")
	d(&f.hopInfoInterval, 0, "refresh what the --hop-info plugins say at this interval (0 = ask each address once)", "hop-info-interval")
	d(&f.appInterval, 10*time.Second, "application check interval per measured port", "app-interval")
	d(&f.appTimeout, 5*time.Second, "application check timeout", "app-timeout")
	fl(&f.responderPPS, 100, "hop probes per second per ICMP responder, across all endpoints", "responder-pps")
	s(&f.src, "", "source address", "src")
	s(&f.iface, "", "egress interface", "interface")
	i(&f.tos, 0, "IPv4 TOS / IPv6 traffic class (0-255)", "tos")
	i(&f.flowLabel, 0, "IPv6 flow label (0-1048575), fixed for all probes", "flow-label")
	i(&f.fwmark, 0, "fwmark for route lookup and SO_MARK (needs CAP_NET_ADMIN)", "fwmark")
	b(&f.v4, false, "IPv4 only", "4")
	b(&f.v6, false, "IPv6 only", "6")
	b(&f.noDNS, false, "no reverse DNS (default)", "n", "no-dns")
	b(&f.dns, false, "enable reverse DNS of hops", "dns")
	b(&f.asn, false, "annotate hops with their AS (asks whois.cymru.com about public hop addresses)", "asn")
	b(&f.ix, false, "mark hops on Internet exchange peering LANs and name the IX member there (PeeringDB data, cached for a day)", "ix")
	s(&f.geoip, "", "offline GeoIP and/or ASN databases (.mmdb, comma separated): country/city, AS without --asn", "geoip")
	b(&f.json, false, "JSON report (with --report or --discover)", "json")
	s(&f.events, "", "write JSONL events to FILE ('-' = stdout, disables the interactive screen)", "events")
	b(&f.discover, false, "discovery only: explore ECMP routes until a stop condition, print the tree and exit", "discover")
	b(&f.noDiscovery, false, "no discovery and no continuous hop probing (E2E only)", "no-discovery")
	b(&f.traceOnFailure, true, "incident traces when flows degrade (--trace-on-failure=false to disable)", "trace-on-failure")
	d(&f.reportTimeout, 5*time.Minute, "report/discover deadline; a partial report is printed when reached", "report-timeout")
	b(&f.noQuoteFallback, false, "disable ICMP quote seq-mismatch fallback correlation", "no-quote-fallback")
	b(&f.help, false, "help", "h", "help")
	b(&f.version, false, "print version", "version")
	return fs
}

// parseArgs parses flags anywhere on the command line.
func parseArgs(args []string, out io.Writer) (*flags, []string, error) {
	f := &flags{}
	fs := newFlagSet(f, out)
	var targets []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, nil, err
		}
		args = fs.Args()
		if len(args) == 0 {
			break
		}
		targets = append(targets, args[0])
		args = args[1:]
	}
	f.set = map[string]bool{}
	fs.Visit(func(fl *flag.Flag) { f.set[fl.Name] = true })
	return f, targets, nil
}

// ParseTarget splits host[:port] / [v6]:port / bare IPv6.
func ParseTarget(s string) (host string, port wire.Port, err error) {
	port = DefaultPort
	switch {
	case strings.HasPrefix(s, "["):
		i := strings.Index(s, "]")
		if i < 0 {
			return "", 0, fmt.Errorf("target %q: missing ]", s)
		}
		host = s[1:i]
		rest := s[i+1:]
		if rest != "" {
			if !strings.HasPrefix(rest, ":") {
				return "", 0, fmt.Errorf("target %q: expected :port after ]", s)
			}
			p, err := strconv.ParseUint(rest[1:], 10, 16)
			if err != nil || p == 0 {
				return "", 0, fmt.Errorf("target %q: bad port", s)
			}
			port = wire.Port(p)
		}
	case strings.Count(s, ":") > 1:
		host = s // bare IPv6 without port
	case strings.Contains(s, ":"):
		h, ps, _ := strings.Cut(s, ":")
		p, err := strconv.ParseUint(ps, 10, 16)
		if err != nil || p == 0 {
			return "", 0, fmt.Errorf("target %q: bad port", s)
		}
		host, port = h, wire.Port(p)
	default:
		host = s
	}
	if host == "" {
		return "", 0, fmt.Errorf("target %q: empty host", s)
	}
	return host, port, nil
}

func parseRange(s string) ([]wire.Port, error) {
	lo, hi, ok := strings.Cut(s, "-")
	if !ok {
		return nil, fmt.Errorf("--sport-range %q: want LO-HI", s)
	}
	a, err1 := strconv.ParseUint(lo, 10, 16)
	b, err2 := strconv.ParseUint(hi, 10, 16)
	if err1 != nil || err2 != nil || a == 0 || a > b {
		return nil, fmt.Errorf("--sport-range %q: invalid", s)
	}
	var out []wire.Port
	for p := a; p <= b; p++ {
		out = append(out, wire.Port(p))
	}
	return out, nil
}

func parseList(s string) ([]wire.Port, error) {
	seen := map[wire.Port]bool{}
	var out []wire.Port
	for _, x := range strings.Split(s, ",") {
		p, err := strconv.ParseUint(strings.TrimSpace(x), 10, 16)
		if err != nil || p == 0 {
			return nil, fmt.Errorf("--src-ports: bad port %q", x)
		}
		if seen[wire.Port(p)] {
			return nil, fmt.Errorf("--src-ports: duplicate port %d", p)
		}
		seen[wire.Port(p)] = true
		out = append(out, wire.Port(p))
	}
	return out, nil
}

// Build validates flags and targets into app options.
func Build(f *flags, targets []string, stdout, stderr io.Writer) (*app.Options, error) {
	if len(targets) == 0 {
		return nil, errors.New("no target given")
	}
	if f.v4 && f.v6 {
		return nil, errors.New("-4 and -6 are mutually exclusive")
	}
	if f.dns && f.noDNS {
		return nil, errors.New("--dns and -n/--no-dns are mutually exclusive")
	}
	if f.discover && f.noDiscovery {
		return nil, errors.New("--discover and --no-discovery are mutually exclusive")
	}
	if f.discover && f.report {
		return nil, errors.New("--discover and --report are separate modes")
	}
	if f.json && !f.report && !f.discover {
		return nil, errors.New("--json needs --report (or --discover)")
	}
	if f.interval < 10*time.Millisecond || f.interval > time.Hour {
		return nil, errors.New("--interval must be between 10ms and 1h")
	}
	if !f.set["timeout"] && f.timeout > f.interval {
		f.timeout = f.interval // default timeout follows a short --interval
	}
	if f.app != "" && (f.appTimeout <= 0 || f.appTimeout >= f.appInterval || f.appInterval < time.Second) {
		return nil, errors.New("--app-interval must be >= 1s and --app-timeout between 0 and the interval")
	}
	if f.timeout <= 0 || f.timeout > f.interval {
		return nil, errors.New("--timeout must be > 0 and not exceed --interval (one probe per flow at a time)")
	}
	if f.hopTimeout < 0 || f.hopTimeout > f.timeout {
		return nil, errors.New("--hop-timeout must be between 0 and --timeout")
	}
	if f.count < 0 {
		return nil, errors.New("--count must not be negative")
	}
	if f.report && f.count == 0 {
		f.count = 100
	}
	if f.flows < 1 {
		return nil, errors.New("--flows must be >= 1")
	}
	if f.maxTTL < 1 || f.maxTTL > 255 {
		return nil, errors.New("--max-ttl must be 1..255")
	}
	for _, v := range []float64{f.pps, f.endpointPPS, f.responderPPS} {
		if !(v > 0) || math.IsInf(v, 0) { // also rejects NaN
			return nil, errors.New("--pps, --endpoint-pps and --responder-pps must be > 0")
		}
	}
	if f.maxInflight < 0 {
		return nil, errors.New("--max-inflight must be >= 0")
	}
	if f.tos < 0 || f.tos > 255 {
		return nil, errors.New("--tos must be 0..255")
	}
	if f.flowLabel < 0 || f.flowLabel > 0xFFFFF {
		return nil, errors.New("--flow-label must be 0..1048575")
	}
	if f.reportTimeout <= 0 {
		return nil, errors.New("--report-timeout must be > 0")
	}
	if f.fwmark < 0 || f.fwmark > math.MaxUint32 {
		return nil, errors.New("--fwmark must be 0..4294967295")
	}
	// "-" is standard output; from here on that is a flag, not a file name.
	eventsStdout := f.events == "-"
	eventsPath := f.events
	if eventsStdout {
		eventsPath = ""
	}
	if eventsStdout && (f.report || f.discover) {
		return nil, errors.New("--events - writes events to standard output, where the report goes: give --events a file")
	}
	var ports []wire.Port
	var err error
	var lock *sys.PortBlockLock
	var blockNote string
	switch {
	case f.srcPorts != "":
		if ports, err = parseList(f.srcPorts); err != nil {
			return nil, err
		}
		lo, hi := ports[0], ports[0]
		for _, p := range ports {
			lo, hi = min(lo, p), max(hi, p)
		}
		if lock, err = sys.LockPortBlock(lo, hi); err != nil {
			return nil, err
		}
	case f.set["sport-range"]:
		if ports, err = parseRange(f.sportRange); err != nil {
			return nil, err
		}
		if lock, err = sys.LockPortBlock(ports[0], ports[len(ports)-1]); err != nil {
			return nil, err
		}
	default:
		// Default range: if another mpmtr instance in this network
		// namespace holds it, move to the next free 256-port block below
		// the kernel's ephemeral range.
		if f.anycast {
			f.sportRange = "20000-22047" // the census needs more ports than routes do: a server that gets few ports must still be seen twice
		}
		base, _ := parseRange(f.sportRange)
		size := wire.Port(len(base)) // a block of ports
		ephLo := 32768
		if lo, _, e := sys.PortRange(); e == nil {
			ephLo = lo
		}
		for k := wire.Port(0); ; k++ { // the k-th block
			lo := base[0] + k*size
			hi := lo + size - 1
			if int(hi) >= ephLo || hi < lo {
				if k == 0 {
					return nil, fmt.Errorf("the default source ports %d-%d are inside ip_local_port_range (starts at %d), where the kernel takes ports for other connections; choose a range with --sport-range", lo, hi, ephLo)
				}
				return nil, fmt.Errorf("no free source port block below ip_local_port_range (%d): other mpmtr instances hold them; use --sport-range", ephLo)
			}
			l, e := sys.LockPortBlock(lo, hi)
			if e != nil {
				var busy *sys.ErrBlockBusy
				if errors.As(e, &busy) {
					if k == 0 {
						blockNote = busy.Error()
					}
					continue
				}
				return nil, e
			}
			lock = l
			ports, _ = parseRange(fmt.Sprintf("%d-%d", lo, hi))
			if k > 0 {
				blockNote = fmt.Sprintf("note: %s; using %d-%d", blockNote, lo, hi)
			} else {
				blockNote = ""
			}
			break
		}
	}
	if len(ports) < f.flows {
		return nil, fmt.Errorf("%d source ports available but --flows %d", len(ports), f.flows)
	}
	o := &app.Options{Ports: ports, PortLock: lock, TOS: uint8(f.tos), FlowLabel: uint32(f.flowLabel), Mark: f.fwmark,
		Report: f.report, JSON: f.json, Discover: f.discover, ReportTimeout: f.reportTimeout, EventsPath: eventsPath, EventsStdout: eventsStdout,
		DNS: f.dns && !f.noDNS, Count: f.count, Stdout: stdout, Stderr: stderr, Interface: f.iface,
		ASN: f.asn, IX: f.ix}
	if f.geoip != "" {
		for _, p := range strings.Split(f.geoip, ",") {
			if p = strings.TrimSpace(p); p != "" {
				if _, err := os.Stat(p); err != nil {
					return nil, fmt.Errorf("--geoip: %w", err)
				}
				o.MMDB = append(o.MMDB, p)
			}
		}
	}
	if f.src != "" {
		a, err := netip.ParseAddr(f.src)
		if err != nil {
			return nil, fmt.Errorf("--src: %w", err)
		}
		o.Src = a.Unmap()
	}
	if f.iface != "" {
		ifc, err := net.InterfaceByName(f.iface)
		if err != nil {
			return nil, fmt.Errorf("--interface: %w", err)
		}
		o.Ifindex = ifc.Index
	}
	seen := map[string]bool{}
	for _, t := range targets {
		host, port, err := ParseTarget(t)
		if err != nil {
			return nil, err
		}
		addr, err := resolve(host, f.v4, f.v6)
		if err != nil {
			return nil, err
		}
		if o.Src.IsValid() && o.Src.Is4() != addr.Is4() {
			return nil, fmt.Errorf("--src %s and target %s are different address families", o.Src, addr)
		}
		k := netip.AddrPortFrom(addr, uint16(port)).String()
		if seen[k] {
			return nil, fmt.Errorf("duplicate endpoint %s", k)
		}
		seen[k] = true
		o.Endpoints = append(o.Endpoints, app.Endpoint{Target: t, Host: host, Addr: addr, Port: port})
	}
	e2eTTL := uint8(64)
	if f.maxTTL >= 64 {
		e2eTTL = 255
	}
	o.Core = core.Config{Interval: f.interval, Timeout: f.timeout, HopTimeout: f.hopTimeout, Flows: f.flows,
		MaxFlows: len(ports), MaxTTL: core.TTL(f.maxTTL), E2ETTL: e2eTTL, PPS: f.pps, EndpointPPS: f.endpointPPS,
		MaxInflight: f.maxInflight, ResponderPPS: f.responderPPS, Discovery: !f.noDiscovery,
		TraceOnFailure: f.traceOnFailure, QuoteFallback: !f.noQuoteFallback,
		DiscoverOnly: f.discover, Seed: 1, SharedHops: f.sharedHops, Anycast: f.anycast,
		App: f.app != "", AppInterval: f.appInterval, AppTimeout: f.appTimeout}
	if words := splitArgs(f.app); len(words) > 0 {
		// --app "NAME ARGS...": the plugin and its own arguments
		if o.AppPath, err = app.FindPlugin(words[0]); err != nil {
			return nil, err
		}
		o.AppArgs = words[1:]
	}
	if f.hopInfoInterval != 0 && (len(f.hopInfo) == 0 || f.hopInfoInterval < time.Second) {
		return nil, errors.New("--hop-info-interval needs --hop-info and at least 1s")
	}
	o.HopInterval = f.hopInfoInterval
	for _, spec := range f.hopInfo {
		words := splitArgs(spec)
		if len(words) == 0 {
			return nil, errors.New("--hop-info: empty plugin name")
		}
		path, err := app.FindHopPlugin(words[0])
		if err != nil {
			return nil, err
		}
		o.HopPlugins = append(o.HopPlugins, app.HopPluginSpec{Path: path, Args: words[1:]})
	}
	if f.report || (f.count > 0 && !f.discover) {
		o.Core.ReportCount = f.count
	}
	if blockNote != "" {
		o.Warnings = append(o.Warnings, blockNote)
	}
	if o.Core.ReportCount > 0 && o.Core.ReportCount < 30 {
		o.Warnings = append(o.Warnings, fmt.Sprintf("note: -c %d is below the 30 results a flow needs to be called OK or LOSS: unless it is DOWN the result will be UNKNOWN (exit 3); use -c 30 or more", o.Core.ReportCount))
	}
	need := f.flows
	if !f.noDiscovery {
		need = max(8, need) // discovery needs spare ports to find routes with
	}
	free, pw, err := preflightPorts(ports, f.srcPorts != "", need)
	o.Warnings = append(o.Warnings, pw...)
	if err != nil {
		return nil, err
	}
	if len(free) < f.flows {
		return nil, fmt.Errorf("%d free source ports but --flows %d", len(free), f.flows)
	}
	o.Ports = free
	o.Core.MaxFlows = len(free)
	return o, nil
}

func resolve(host string, v4, v6 bool) (netip.Addr, error) {
	if a, err := netip.ParseAddr(host); err == nil {
		a = a.Unmap()
		if v4 && !a.Is4() || v6 && a.Is4() {
			return netip.Addr{}, fmt.Errorf("%s does not match -4/-6", host)
		}
		return a, nil
	}
	nw := "ip"
	if v4 {
		nw = "ip4"
	} else if v6 {
		nw = "ip6"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, nw, host)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("resolve %s: %w", host, err)
	}
	if len(addrs) == 0 {
		return netip.Addr{}, fmt.Errorf("resolve %s: no addresses", host)
	}
	return addrs[0].Unmap(), nil
}

// preflightPorts drops source ports that local sockets already use (other
// programs' connections, e.g. when the range overlaps the ephemeral range):
// mpmtr simply takes the next free ones. Used ports are then held by a
// bound, non-listening socket each, so the kernel cannot hand them out.
func preflightPorts(ports []wire.Port, explicit bool, need int) ([]wire.Port, []string, error) {
	var w []string
	busy := map[int]bool{}
	for _, s := range sys.TCPSockets() {
		if s.State != 6 { // TIME_WAIT does not block an explicit bind
			busy[s.Port] = true
		}
	}
	free := make([]wire.Port, 0, len(ports))
	var skipped []string
	for _, p := range ports {
		if busy[int(p)] {
			skipped = append(skipped, fmt.Sprint(p))
			continue
		}
		free = append(free, p)
	}
	if explicit && len(skipped) > 0 {
		w = append(w, "note: skipping --src-ports in use by local sockets: "+strings.Join(skipped, ","))
	}
	if len(free) == 0 || (!explicit && len(free) < need) {
		return nil, w, fmt.Errorf("only %d of %d source ports are free (the others are used by local sockets); use --sport-range with a less busy range", len(free), len(ports))
	}
	return free, w, nil
}

// Main runs mpmtr and returns the process exit code.
func Main(args []string) int { return run(args, os.Stdout, os.Stderr) }

// run is Main with its output streams given.
func run(args []string, stdout, stderr io.Writer) int {
	f, targets, err := parseArgs(args, io.Discard)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(stdout, usageText)
			return ExitOK
		}
		fmt.Fprintln(stderr, "mpmtr:", err)
		fmt.Fprintln(stderr, usageSummary)
		return ExitError
	}
	if len(targets) == 0 && !f.help && !f.version {
		fmt.Fprint(stderr, usageText)
		return ExitError
	}
	if f.help {
		fmt.Fprint(stdout, usageText)
		return ExitOK
	}
	if f.version {
		fmt.Fprintln(stdout, "mpmtr", Version)
		return ExitOK
	}
	o, err := Build(f, targets, stdout, stderr)
	if err != nil {
		fmt.Fprintln(stderr, "mpmtr:", err)
		fmt.Fprintln(stderr, usageSummary)
		return ExitError
	}
	rt, err := app.Start(o)
	if err != nil {
		fmt.Fprintln(stderr, "mpmtr:", err)
		return ExitError
	}
	defer rt.Close()
	for _, w := range o.Warnings {
		fmt.Fprintln(stderr, "mpmtr:", w)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	switch {
	case o.Report || o.Discover:
		return runReport(ctx, rt, o, f)
	default:
		return runLive(ctx, rt, o)
	}
}

func runReport(ctx context.Context, rt *app.Runtime, o *app.Options, f *flags) int {
	started := time.Now()
	deadline := started.Add(o.ReportTimeout)
	timedOut := false
	isTTY := term.IsTerminal(int(os.Stderr.Fd()))
	lastProg := time.Now()
	rt.Loop(ctx, func(c *core.Core) bool {
		if time.Now().After(deadline) {
			timedOut = true
			return true
		}
		if isTTY && time.Since(lastProg) > time.Second && !o.Discover {
			d, t := c.ReportProgress()
			fmt.Fprintf(os.Stderr, "\rmpmtr: %d/%d E2E probes executed", d, t)
			lastProg = time.Now()
		}
		if o.Discover {
			return c.DiscoveryDone()
		}
		return c.ReportDone()
	})
	if isTTY && !o.Discover {
		fmt.Fprint(os.Stderr, "\r\x1b[K")
	}
	interrupted := ctx.Err() != nil
	var snap *core.Snapshot
	var events []core.Event
	var inc []string
	finish := func(c *core.Core) {
		if p := os.Getenv("MPMTR_DEBUG_ANYCAST"); p != "" {
			if b, err := json.Marshal(c.AnycastAnswers(0)); err == nil {
				os.WriteFile(p, b, 0o644)
			}
		}
		c.StopDiscovery()
		c.EvaluateNow()
		c.Flush()
		snap = c.Snapshot(core.SnapOpts{Hops: true, Tree: true, Only: core.AllEndpoints})
		events = c.RecentEvents()
		if !o.Discover {
			d, t := c.ReportProgress()
			if d < t {
				inc = append(inc, fmt.Sprintf("executed %d of %d E2E probes", d, t))
			}
		}
	}
	finish(rt.C) // core goroutine has stopped; safe to call directly
	if timedOut {
		inc = append(inc, "report-timeout reached")
	}
	if interrupted {
		inc = append(inc, "interrupted")
	}
	if err := rt.Err(); err != nil {
		inc = append(inc, err.Error())
		fmt.Fprintln(o.Stderr, "mpmtr:", err)
	}
	if p := rt.Plugin(); p != nil {
		if err := p.Dead(); err != nil {
			inc = append(inc, fmt.Sprintf("application check plugin %s stopped: %v", p.Name, err))
		}
	}
	code := exitCode(snap, len(inc) > 0)
	if o.Discover {
		// Nothing is measured end to end here: the result is the route
		// list, and it is trustworthy when discovery ran to its own stop.
		code = ExitOK
		if len(inc) > 0 {
			code = ExitUnknown
		}
		for _, e := range snap.Endpoints {
			if e.Discovery.Reason == core.StopInsufficientData || e.Discovery.Branches == 0 {
				code = ExitUnknown
			}
		}
	}
	if rt.Err() != nil {
		code = ExitError
	}
	settleNames(rt, o, snap)
	if o.JSON {
		r := &report.JSONReport{Tool: "mpmtr", Version: Version, Started: started, Finished: time.Now(),
			Complete: len(inc) == 0, Incomplete: inc, ExitCode: code, Snapshot: snap, Events: events, Warnings: rt.Warnings(),
			IPInfo:  rt.Names.Info.All(),
			HopInfo: rt.Names.Hops.All(),
			Params: report.Params{Mode: "report", Count: o.Count, Interval: o.Core.Interval.String(), Timeout: o.Core.Timeout.String(),
				FlowsPerRoute: o.Core.Flows, Ports: len(o.Ports), MaxTTL: int(o.Core.MaxTTL), PPS: o.Core.PPS,
				ResponderPPS: o.Core.ResponderPPS, Discovery: o.Core.Discovery, PcapFilter: rt.PcapFilter()}}
		if o.Discover {
			r.Params.Mode = "discover"
		}
		if err := report.JSON(o.Stdout, r); err != nil {
			return ExitError
		}
		return code
	}
	hdr := fmt.Sprintf("mpmtr %s report  %s  duration %s  E2E probes/flow %d  exit %d", Version,
		started.Format(time.RFC3339), time.Since(started).Round(time.Second), o.Count, code)
	if o.Discover {
		hdr = fmt.Sprintf("mpmtr %s discovery  %s  duration %s", Version, started.Format(time.RFC3339), time.Since(started).Round(time.Second))
	}
	if len(inc) > 0 {
		hdr += "\nINCOMPLETE: " + strings.Join(inc, "; ") + " (counts below are the real ones)"
	}
	if long, short := o.Core.WindowDur(); long != 5*time.Minute {
		hdr += fmt.Sprintf("\nwindows at --interval %s: \"5m\" below is %s, \"60s\" is %s (300 and 60 probe intervals)", o.Core.Interval, long, short)
	}
	hdr += "\npcap filter: " + rt.PcapFilter()
	report.Text(o.Stdout, snap, rt.Names, hdr)
	for _, w := range rt.Names.Warnings() {
		fmt.Fprintln(o.Stderr, "mpmtr:", w)
	}
	return code
}

// settleNames gives the hop lookups (reverse DNS, AS, IX) of a final
// report a few seconds to answer: rendering once asks for every address.
func settleNames(rt *app.Runtime, o *app.Options, snap *core.Snapshot) {
	if !o.DNS && rt.Names.Info == nil && rt.Names.Hops == nil {
		return
	}
	report.Text(io.Discard, snap, rt.Names, "")
	rt.Names.Settle(10 * time.Second)
}

// exitCode applies the documented priority across endpoints.
func exitCode(s *core.Snapshot, incomplete bool) int {
	down, unknown, loss := false, false, false
	for _, e := range s.Endpoints {
		switch e.State {
		case core.EPDown:
			down = true
		case core.EPLoss:
			loss = true
		case core.EPOK:
			// Flows without a verdict, and ports that cannot be measured
			// at all, are both missing data.
			if e.Agg.Total > 0 && float64(e.Agg.Unknown+e.Agg.Invalid)/float64(e.Agg.Total) > 0.25 {
				unknown = true
			}
		default:
			unknown = true
		}
	}
	switch {
	case down:
		return ExitDown
	case unknown, incomplete:
		return ExitUnknown
	case loss:
		return ExitLoss
	}
	return ExitOK
}

func runLive(ctx context.Context, rt *app.Runtime, o *app.Options) int {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan struct{})
	go func() {
		rt.Loop(ctx, func(c *core.Core) bool { return o.Count > 0 && c.ReportDone() })
		cancel()
		close(done)
	}()
	tty := term.IsTerminal(int(os.Stdout.Fd())) && !o.EventsStdout
	switch {
	case tty:
		_ = ui.Run(ctx, rt, os.Stdout, Version)
	case o.EventsStdout:
		<-ctx.Done()
	default:
		// Not a terminal: periodic plain-text summaries, no ANSI.
		t := time.NewTicker(10 * time.Second)
		defer t.Stop()
	loop:
		for {
			select {
			case <-ctx.Done():
				break loop
			case <-t.C:
				var s *core.Snapshot
				rt.Do(func(c *core.Core) { s = c.Snapshot(core.SnapOpts{Tree: true, Only: core.AllEndpoints}) })
				report.Text(o.Stdout, s, rt.Names, "---- "+s.Time.Format(time.RFC3339))
			}
		}
	}
	cancel()
	<-done
	if err := rt.Err(); err != nil {
		fmt.Fprintln(o.Stderr, "mpmtr:", err)
		return ExitError
	}
	if o.Count > 0 {
		rt.C.EvaluateNow()
		s := rt.C.Snapshot(core.SnapOpts{Tree: true, Only: core.AllEndpoints})
		d, t := rt.C.ReportProgress()
		incomplete := d < t
		hdr := "mpmtr final"
		if incomplete {
			hdr += fmt.Sprintf("\nINCOMPLETE: executed %d of %d E2E probes", d, t)
		}
		// A plugin that stopped left its servers unchecked: not a full result.
		if p := rt.Plugin(); p != nil {
			if err := p.Dead(); err != nil {
				incomplete = true
				hdr += fmt.Sprintf("\nINCOMPLETE: application check plugin %s stopped: %v", p.Name, err)
			}
		}
		if !o.EventsStdout {
			settleNames(rt, o, s)
			report.Text(o.Stdout, s, rt.Names, hdr)
		}
		return exitCode(s, incomplete)
	}
	return ExitOK
}

// secDuration is a duration flag that also accepts a bare number of seconds
// like mtr/ping ("0.2" = 200ms, "5" = 5s) besides Go units ("200ms", "1m30s").
type secDuration time.Duration

func (d *secDuration) String() string { return time.Duration(*d).String() }

func (d *secDuration) Set(s string) error {
	v, err := parseSeconds(s)
	if err != nil {
		return err
	}
	*d = secDuration(v)
	return nil
}

func parseSeconds(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if f, err := strconv.ParseFloat(strings.Replace(s, ",", ".", 1), 64); err == nil {
		if f < 0 || f > 1e6 {
			return 0, fmt.Errorf("%q: out of range", s)
		}
		return time.Duration(f * float64(time.Second)), nil
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("%q: use seconds (0.2, 5) or units (200ms, 1m30s)", s)
	}
	return v, nil
}

// multiFlag is a string flag that may be given several times.
type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ", ") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

// splitArgs splits a plugin's "NAME [ARGS]" into words at spaces; a part in
// single or double quotes is one word (an argument with spaces in it).
func splitArgs(s string) []string {
	var out []string
	var cur strings.Builder
	var quote rune
	in := false
	for _, r := range s {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			} else {
				cur.WriteRune(r)
			}
		case r == '\'' || r == '"':
			quote, in = r, true
		case r == ' ' || r == '\t':
			if in {
				out = append(out, cur.String())
				cur.Reset()
				in = false
			}
		default:
			cur.WriteRune(r)
			in = true
		}
	}
	if in {
		out = append(out, cur.String())
	}
	return out
}
