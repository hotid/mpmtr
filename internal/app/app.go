// Package app wires the measurement core to the Linux raw I/O, the
// terminal UI and the report/event writers. All modes (live, report, JSON,
// events, discover) run on the same core.
package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"

	"github.com/hotid/mpmtr/internal/core"
	"github.com/hotid/mpmtr/internal/enrich"
	"github.com/hotid/mpmtr/internal/sys"
	"github.com/hotid/mpmtr/internal/wire"
)

// Endpoint to measure.
type Endpoint struct {
	Target string
	Host   string // the target without its port, as typed: a name or an address
	Addr   netip.Addr
	Port   wire.Port
}

// Options are the validated CLI options.
type Options struct {
	Core          core.Config
	Endpoints     []Endpoint
	Ports         []wire.Port
	PortLock      *sys.PortBlockLock // held for the process lifetime (instance port-block claim)
	Src           netip.Addr
	Interface     string
	Ifindex       int
	Mark          int
	TOS           uint8
	FlowLabel     uint32
	Report        bool
	JSON          bool
	Discover      bool
	ReportTimeout time.Duration
	EventsPath    string // a file for the events ("" = none)
	EventsStdout  bool   // the events go to standard output: no screen, no report there
	DNS           bool
	Count         int
	Warnings      []string
	Stderr        io.Writer
	Stdout        io.Writer
	AppPath       string   // application-check plugin executable ("" = none)
	AppArgs       []string // its arguments
	ASN           bool     // annotate hops with their AS (Team Cymru whois)
	IX            bool     // annotate hops on IX peering LANs (PeeringDB)
	MMDB          []string // offline GeoIP / ASN databases (.mmdb)
	HopPlugins    []HopPluginSpec
	HopInterval   time.Duration // > 0: refresh what the plugins say at this interval
}

var debugPkt = os.Getenv("MPMTR_DEBUG_PKT") != ""
var debugApp = os.Getenv("MPMTR_DEBUG_APP") != ""

type clock struct{ start time.Time }

func (c clock) Now() (core.Mono, core.Wall) {
	n := time.Now()
	return core.Mono(n.Sub(c.start)), core.Wall(n.UnixNano())
}

type transport struct{ s *sys.Sender }

// appTransport adds application checks through a plugin.
type appTransport struct {
	transport
	p     *Plugin
	rt    *Runtime
	dial  sys.DialOpts
	hosts map[netip.AddrPort]string // endpoint → the target as typed, without its port
}

// AppCheck opens a real connection from the flow's port, hands it to the
// plugin, and posts the verdict back to the core. Called on the core
// goroutine: everything read from core state is copied before the work
// moves to its own goroutine.
func (t appTransport) AppCheck(f *core.Flow, id uint64, timeout time.Duration) {
	src, sport, dst, dport := f.Tmpl.Src, f.Tmpl.SPort, f.Tmpl.Dst, f.Tmpl.DPort
	server := ""
	if s := f.EP.ServerOf(sport); s != nil {
		server = s.Name()
	}
	go func() {
		var r core.AppResult
		start := time.Now()
		fd, rtt, refused, err := sys.DialFrom(src, sport, dst, dport, t.dial, timeout)
		switch {
		case err == nil:
			r.ConnectRTT = rtt
			m := pluginMsg{Src: src.String(), SPort: uint16(sport), Dst: dst.String(), DPort: uint16(dport), Server: server,
				Host: t.hosts[netip.AddrPortFrom(dst, uint16(dport))]}
			// One budget for the whole check: what the connect used is
			// not given to the plugin again (the core stops waiting at
			// the timeout plus a margin).
			left := max(timeout-time.Since(start), 100*time.Millisecond)
			r.Outcome, r.Stage, r.Err, r.Note, r.AppTime = t.p.Check(id, fd, m, left)
			unix.Close(fd) // the last copy: SO_LINGER 0 sends RST
		case refused:
			r.Outcome, r.Stage, r.Err = core.AppRefused, "tcp", "connection refused"
		case errors.Is(err, unix.ETIMEDOUT):
			r.Outcome, r.Stage, r.Err = core.AppNoAnswer, "tcp", "no answer to the SYN"
		default:
			r.Outcome, r.Stage, r.Err = core.AppLocal, "local", err.Error()
		}
		if debugApp {
			fmt.Fprintf(os.Stderr, "app %s sport %d %s connected=%v rtt=%v ok=%v stage=%s err=%s took=%v\n",
				time.Now().Format("15:04:05.000"), sport, server, r.Outcome.Connected(), r.ConnectRTT.Round(time.Millisecond), r.Outcome == core.AppPassed, r.Stage, r.Err, r.AppTime.Round(time.Millisecond))
		}
		t.rt.Do(func(c *core.Core) { c.OnAppResult(id, r) })
	}()
}

func (t transport) Send(f *core.Flow, seq uint32, ttl uint8, ipid uint16) error {
	return t.s.Send(&f.Tmpl, f.IfIndex, seq, ttl, ipid)
}

type env struct {
	r   *sys.Router
	res *sys.Reserver
}

func (e env) Route(dst netip.Addr, sport, dport wire.Port) (core.Route, error) {
	rr, err := e.r.Lookup(dst, sport, dport)
	if err != nil {
		return core.Route{}, err
	}
	r := core.Route{Src: rr.Src, IfIndex: rr.Oif, Gateway: rr.Gateway}
	if rr.MTU > 0 {
		if dst.Is4() {
			r.MSS = uint16(rr.MTU - 40)
		} else {
			r.MSS = uint16(rr.MTU - 60)
		}
	}
	return r, nil
}

func (e env) Reserve(src netip.Addr, sport wire.Port) error { return e.res.Reserve(src, sport) }

// msg from the capture goroutine to the core goroutine (one ordered stream
// for packets and watermarks).
type msg struct {
	pkts             []wire.Packet
	wm               bool
	rt               int64
	drops            uint64
	user             uint64
	dropFrom, dropTo int64
}

type sink struct {
	ch        chan msg
	pool      sync.Pool
	userDrops atomic.Uint64
	userFrom  atomic.Int64 // realtime of the first unreported userspace drop
	kernDrops uint64
	dropFrom  int64
	dropTo    int64
}

func (s *sink) Packets(b []wire.Packet) {
	var buf []wire.Packet
	if v := s.pool.Get(); v != nil {
		buf = v.([]wire.Packet)[:0]
	}
	buf = append(buf, b...)
	select {
	case s.ch <- msg{pkts: buf}:
	default:
		// Core is behind: count as capture loss (never as network loss).
		if s.userDrops.Add(uint64(len(b))) == uint64(len(b)) {
			s.userFrom.Store(b[0].TS)
		}
	}
}

func (s *sink) Watermark(rt int64, drops uint64, dropFrom, dropTo int64) {
	if drops > 0 {
		if s.kernDrops == 0 || dropFrom < s.dropFrom {
			s.dropFrom = dropFrom
		}
		s.dropTo = max(s.dropTo, dropTo)
		s.kernDrops += drops
	}
	u := s.userDrops.Swap(0)
	from, to := s.dropFrom, s.dropTo
	if u > 0 {
		uf := s.userFrom.Load()
		if from == 0 || uf < from {
			from = uf
		}
		to = max(to, time.Now().UnixNano())
	}
	select {
	case s.ch <- msg{wm: true, rt: rt, drops: s.kernDrops, user: u, dropFrom: from, dropTo: to}:
		s.kernDrops, s.dropFrom, s.dropTo = 0, 0, 0
	default:
		s.userDrops.Add(u) // carried to the next watermark
	}
}

// Runtime is the running measurement.
type Runtime struct {
	o       *Options
	C       *core.Core
	snd     *sys.Sender
	cap     *sys.Capture
	rtr     *sys.Router
	res     *sys.Reserver
	sink    *sink
	reqs    chan func(*core.Core)
	routeCh chan struct{}
	stopW   func()
	evw     *eventWriter
	Names   *Resolver
	start   time.Time
	plugin  *Plugin
	failed  chan error
	err     error
}

// Err is the error that stopped the measurement (the capture died), or nil.
// It is valid once Loop has returned.
func (rt *Runtime) Err() error { return rt.err }

// Plugin is the running application-check plugin (nil without --app).
func (rt *Runtime) Plugin() *Plugin { return rt.plugin }

// Start opens sockets, reserves ports, creates flows and starts capture.
func Start(o *Options) (*Runtime, error) {
	sys.RaiseNoFile()
	v4, v6 := false, false
	for _, e := range o.Endpoints {
		if e.Addr.Is4() {
			v4 = true
		} else {
			v6 = true
		}
	}
	rt := &Runtime{o: o, reqs: make(chan func(*core.Core), 16), routeCh: make(chan struct{}, 1), start: time.Now()}
	// The raw sockets first: without the privilege nothing else is started
	// (no plugin, no download), and the user is told what is missing.
	var err error
	if rt.snd, err = sys.NewSender(v4, v6, sys.SenderOpts{Interface: o.Interface, Mark: o.Mark}); err != nil {
		return nil, err
	}
	rt.Names = NewResolver(o.DNS)
	if o.ASN || o.IX || len(o.MMDB) > 0 {
		cache := ""
		if d, err := os.UserCacheDir(); err == nil {
			cache = filepath.Join(d, "mpmtr")
		}
		info, err := enrich.New(enrich.Options{ASN: o.ASN, IX: o.IX, MMDB: o.MMDB, CacheDir: cache, Warn: rt.Names.warn})
		if err != nil {
			rt.snd.Close()
			return nil, err
		}
		rt.Names.Info = info
	}
	if rt.Names.Hops, err = StartHopInfo(o.HopPlugins, o.HopInterval, rt.Names.warn); err != nil {
		rt.Names.Close()
		rt.snd.Close()
		return nil, err
	}
	lo, hi := o.Ports[0], o.Ports[0]
	for _, p := range o.Ports {
		lo, hi = min(lo, p), max(hi, p)
	}
	co := sys.CaptureOpts{Ifindex: o.Ifindex, PortLo: lo, PortHi: hi}
	// Debug/test knobs for the capture ring (used by the capture-drop
	// integration test); not part of the documented CLI.
	if v, err := strconv.Atoi(os.Getenv("MPMTR_RING_BLOCK_SIZE")); err == nil && v > 0 {
		co.BlockSize = v
	}
	if v, err := strconv.Atoi(os.Getenv("MPMTR_RING_BLOCKS")); err == nil && v > 0 {
		co.BlockNr = v
	}
	if rt.cap, err = sys.NewCapture(co); err != nil {
		rt.snd.Close()
		return nil, err
	}
	if rt.rtr, err = sys.NewRouter(); err != nil {
		rt.Close()
		return nil, err
	}
	rt.rtr.Src, rt.rtr.Oif, rt.rtr.Mark, rt.rtr.TOS = o.Src, o.Ifindex, uint32(o.Mark), o.TOS
	rt.res = sys.NewReserver()
	o.Core.TOS, o.Core.FlowLabel = o.TOS, o.FlowLabel
	var tr core.Transport = transport{rt.snd}
	if o.AppPath != "" {
		if rt.plugin, err = StartPlugin(o.AppPath, o.AppArgs); err != nil {
			rt.Close()
			return nil, err
		}
		rt.Names.AppW = rt.plugin.NoteWidth
		hosts := map[netip.AddrPort]string{}
		for _, e := range o.Endpoints {
			hosts[netip.AddrPortFrom(e.Addr, uint16(e.Port))] = e.Host
		}
		tr = appTransport{transport: transport{rt.snd}, p: rt.plugin, rt: rt, hosts: hosts,
			dial: sys.DialOpts{Interface: o.Interface, Mark: o.Mark, TOS: o.TOS, FlowLabel: o.FlowLabel}}
	}
	rt.C = core.New(o.Core, tr, env{rt.rtr, rt.res}, clock{rt.start})
	if o.EventsPath != "" || o.EventsStdout {
		if rt.evw, err = newEventWriter(o.EventsPath, o.EventsStdout, o.Stdout); err != nil {
			rt.Close()
			return nil, err
		}
		rt.C.SetEventHandler(rt.evw.write)
	}
	for _, e := range o.Endpoints {
		if _, err := rt.C.AddEndpoint(e.Target, e.Addr, e.Port, o.Ports); err != nil {
			rt.Close()
			return nil, err
		}
	}
	o.Warnings = append(o.Warnings, rt.localMultipath()...)
	if n := rt.C.Metrics().PortConflicts; n > 0 {
		o.Warnings = append(o.Warnings, fmt.Sprintf("warning: %d source ports skipped: reservation bind failed (first: %s)", n, rt.C.FirstEnvErr))
	}
	if n := rt.C.Metrics().RouteErrors; n > 0 {
		o.Warnings = append(o.Warnings, fmt.Sprintf("%d flows skipped: route lookup failed", n))
	}
	rt.sink = &sink{ch: make(chan msg, 4096)}
	if debugPkt {
		rt.cap.Debug = func(s string) { fmt.Fprintln(os.Stderr, s) }
	}
	rt.failed = make(chan error, 1)
	go func() {
		// Without the capture nothing that follows can be measured: the run
		// ends with an error instead of reporting silence as a result.
		if err := rt.cap.Run(rt.sink); err != nil {
			rt.failed <- fmt.Errorf("packet capture failed: %w", err)
		}
	}()
	stop, warn, err := sys.WatchChanges(rt.routeCh)
	if err != nil {
		warn = append(warn, fmt.Sprintf("changes of local routes and addresses are not followed: %v", err))
	} else {
		rt.stopW = stop
	}
	warn = append(append(warn, rt.snd.Warnings...), rt.cap.Warnings...)
	if w := rt.res.Warning(); w != "" {
		warn = append(warn, w)
	}
	for _, w := range warn {
		o.Warnings = append(o.Warnings, "warning: "+w)
	}
	return rt, nil
}

// localMultipath inspects the local FIB entry towards each endpoint. Raw
// IP_HDRINCL packets are routed by destination (ports are not part of the
// kernel's raw-socket flow key), so a local multipath route may pin all raw
// flows to one nexthop although real TCP connections would be spread.
// mpmtr pins each flow to the egress interface of its own port-aware route
// lookup (IP_PKTINFO) and verifies the captured egress of every probe;
// nexthops that share an interface (different gateways on one link) cannot
// be selected that way, which is reported here.
func (rt *Runtime) localMultipath() []string {
	var w []string
	for _, e := range rt.o.Endpoints {
		nhs, ok, err := rt.rtr.FIBNexthops(e.Addr)
		if err != nil {
			continue
		}
		if !ok {
			w = append(w, fmt.Sprintf("route to %s uses nexthop objects; local multipath could not be inspected — "+
				"raw SYN may pin to a single nexthop; observed ECMP branching may be absent or incomplete", e.Addr))
			continue
		}
		if len(nhs) < 2 {
			continue
		}
		oifs := map[int]int{}
		for _, nh := range nhs {
			oifs[nh.Oif]++
		}
		shared := false
		for _, n := range oifs {
			if n > 1 {
				shared = true
			}
		}
		if shared {
			w = append(w, fmt.Sprintf("local multipath detected towards %s (%d nexthops, some sharing an interface): "+
				"raw SYN may pin to a single nexthop; observed ECMP branching may be absent or incomplete", e.Addr, len(nhs)))
		} else {
			w = append(w, fmt.Sprintf("local multipath towards %s: %d nexthops on distinct interfaces; each flow is pinned to the "+
				"egress interface of its port-aware route lookup and the captured egress is verified per probe "+
				"(flows sent elsewhere become MEASUREMENT_INVALID)", e.Addr, len(nhs)))
		}
	}
	return w
}

// Warnings returns startup warnings and notes.
func (rt *Runtime) Warnings() []string {
	return append(append([]string(nil), rt.o.Warnings...), rt.Names.Warnings()...)
}

// Do runs fn on the core goroutine and waits for it.
func (rt *Runtime) Do(fn func(*core.Core)) {
	done := make(chan struct{})
	rt.reqs <- func(c *core.Core) { fn(c); close(done) }
	<-done
}

// Loop drives the core until ctx is done. stopIf is evaluated on the core
// goroutine after each wakeup.
func (rt *Runtime) Loop(ctx context.Context, stopIf func(*core.Core) bool) {
	c := rt.C
	timer := time.NewTimer(time.Millisecond)
	defer timer.Stop()
	var routeDirty time.Time
	for {
		next := c.Advance()
		if stopIf != nil && stopIf(c) {
			return
		}
		wait := time.Duration(next) - time.Since(rt.start)
		if wait < 0 {
			wait = 0
		}
		if wait > 20*time.Millisecond {
			wait = 20 * time.Millisecond
		}
		if !routeDirty.IsZero() && time.Since(routeDirty) > time.Second {
			routeDirty = time.Time{}
			c.RevalidateRoutes()
		}
		timer.Reset(wait)
		select {
		case <-ctx.Done():
			return
		case rt.err = <-rt.failed:
			return
		case m := <-rt.sink.ch:
			rt.handle(m)
			// Drain what is already queued, bounded.
			for i := 0; i < 64; i++ {
				select {
				case m := <-rt.sink.ch:
					rt.handle(m)
					continue
				default:
				}
				break
			}
		case fn := <-rt.reqs:
			fn(c)
		case <-rt.routeCh:
			if routeDirty.IsZero() {
				routeDirty = time.Now()
			}
		case <-timer.C:
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
	}
}

func (rt *Runtime) handle(m msg) {
	if m.wm {
		rt.C.OnWatermarkDrops(core.Wall(m.rt), m.drops, m.user, core.Wall(m.dropFrom), core.Wall(m.dropTo))
		if n := rt.cap.Malformed.Swap(0); n > 0 {
			rt.C.OnMalformed(n)
		}
		return
	}
	for i := range m.pkts {
		if debugPkt {
			p := &m.pkts[i]
			fmt.Fprintf(os.Stderr, "pkt out=%v if=%d kind=%d %s:%d>%s:%d fl=%#x seq=%d ack=%d icmp=%d inner=%s:%d>%s:%d\n", p.Outgoing, p.IfIndex, p.Kind, p.Src, p.SPort, p.Dst, p.DPort, p.Flags, p.Seq, p.Ack, p.ICMPType, p.InnerSrc, p.InnerSPort, p.InnerDst, p.InnerDPort)
		}
		rt.C.OnPacket(&m.pkts[i])
	}
	rt.sink.pool.Put(m.pkts[:0]) //nolint:staticcheck // slice reuse
}

// Close releases all resources.
func (rt *Runtime) Close() {
	rt.Names.Close()
	if rt.stopW != nil {
		rt.stopW()
	}
	if rt.plugin != nil {
		rt.plugin.Close()
	}
	if rt.cap != nil {
		rt.cap.Close()
	}
	if rt.snd != nil {
		rt.snd.Close()
	}
	if rt.rtr != nil {
		rt.rtr.Close()
	}
	if rt.res != nil {
		rt.res.Close()
	}
	if rt.evw != nil {
		if rt.C != nil {
			rt.C.Flush()
		}
		rt.evw.close()
	}
}

// PcapFilter is a tcpdump/libpcap filter for this run's packets: the TCP
// probes and answers between our source ports and each endpoint, and the
// ICMP errors quoting a probe to it (the quoted destination is matched at
// its fixed offset: our probes carry no IP options or extension headers).
func (rt *Runtime) PcapFilter() string {
	lo, hi := rt.o.Ports[0], rt.o.Ports[0]
	for _, p := range rt.o.Ports {
		lo, hi = min(lo, p), max(hi, p)
	}
	ports := fmt.Sprintf("portrange %d-%d", lo, hi)
	if lo == hi {
		ports = fmt.Sprintf("port %d", lo)
	}
	var parts []string
	for _, e := range rt.o.Endpoints {
		a := e.Addr.Unmap()
		tcp := fmt.Sprintf("(tcp and host %s and port %d and %s)", a, e.Port, ports)
		b := a.AsSlice()
		var icmp string
		if a.Is4() {
			icmp = fmt.Sprintf("(icmp and icmp[24:4] = 0x%x)", b)
		} else {
			var w []string
			for i := 0; i < 16; i += 4 {
				w = append(w, fmt.Sprintf("ip6[%d:4] = 0x%x", 72+i, b[i:i+4]))
			}
			icmp = "(icmp6 and " + strings.Join(w, " and ") + ")"
		}
		parts = append(parts, tcp, icmp)
	}
	return strings.Join(parts, " or ")
}
