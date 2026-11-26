package core

import (
	"container/heap"
	"errors"
	"math/rand/v2"
	"net/netip"
	"testing"
	"time"

	"github.com/hotid/mpmtr/internal/wire"
)

// --- simulated network with a virtual clock ---

type simHop struct {
	addr        netip.Addr
	silent      bool
	icmpLoss    float64 // ICMP reply suppression (rate limiting), not transit loss
	transitLoss float64
	rtt         time.Duration
	both        time.Duration // > 0: the hop answers (this much later, a slow path) and lets the probe go on as well
}

type simPath struct {
	hops    []simHop
	loss    float64 // E2E loss at the destination side
	rtt     time.Duration
	unreach bool // destination answers with ICMP unreachable from the last hop
	noReply bool // destination never answers TTL-limited probes (filtered)
}

type delivery struct {
	at  Mono
	pkt wire.Packet
}

type dheap []delivery

func (h dheap) Len() int           { return len(h) }
func (h dheap) Less(i, j int) bool { return h[i].at < h[j].at }
func (h dheap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *dheap) Push(x any)        { *h = append(*h, x.(delivery)) }
func (h *dheap) Pop() any          { o := *h; n := len(o); d := o[n-1]; *h = o[:n-1]; return d }

type simNet struct {
	// holdOn: while it says so, the server keeps the connection of the
	// probe it answered and answers later SYNs of the port with an ACK of it.
	holdOn func(f *Flow, now Mono) bool
	held   map[*Flow]uint32
	t      *testing.T
	now    Mono
	rtBase int64
	c      *Core
	rng    *rand.Rand
	q      dheap

	path      func(f *Flow, now Mono) *simPath
	sendErr   func(f *Flow) bool
	dropsFn   func(now Mono) uint64 // capture drops per watermark
	noTxCap   func(f *Flow) bool
	onSend    func(f *Flow, ttl uint8)
	serverTS  func(f *Flow, rt int64) uint32           // anycast: TSval of the server a port reaches
	appFn     func(f *Flow) (AppResult, time.Duration) // application check outcome and duration
	appFn0    func(f *Flow)                            // called at the start of each check
	appQ      []simApp
	appCalls  int
	noRST     bool
	reserveFn func(sport wire.Port) error

	events    []Event
	sent      int
	sentE2E   int
	sentHop   int
	collision int
	lastSeq   map[int]uint32
}

var simSrc = netip.MustParseAddr("192.0.2.1")
var simDst = netip.MustParseAddr("198.51.100.10")

func (s *simNet) Now() (Mono, Wall) { return s.now, Wall(s.rtBase + int64(s.now)) }

func (s *simNet) Route(dst netip.Addr, sport, dport wire.Port) (Route, error) {
	return Route{Src: simSrc, IfIndex: 2, Gateway: netip.MustParseAddr("192.0.2.254")}, nil
}

func (s *simNet) Reserve(src netip.Addr, sport wire.Port) error {
	if s.reserveFn != nil {
		return s.reserveFn(sport)
	}
	return nil
}

func (s *simNet) deliver(at Mono, p wire.Packet) {
	p.TS = s.rtBase + int64(at)
	p.TSKernel = true
	heap.Push(&s.q, delivery{at: at, pkt: p})
}

func (s *simNet) Send(f *Flow, seq uint32, ttl uint8, ipid uint16) error {
	// Per-flow serialization invariant: never a second active probe.
	if f.active != nil {
		s.collision++
		s.t.Errorf("collision: flow %s has an active probe while sending another", f.Name())
	}
	if s.sendErr != nil && s.sendErr(f) {
		return errors.New("simulated local error")
	}
	s.sent++
	if s.onSend != nil {
		s.onSend(f, ttl)
	}
	if ttl >= 64 {
		s.sentE2E++
	} else {
		s.sentHop++
	}
	src, dst := f.Tmpl.Src, f.Tmpl.Dst
	if s.noTxCap == nil || !s.noTxCap(f) {
		s.deliver(s.now, wire.Packet{Kind: wire.KindTCP, Outgoing: true, IfIndex: int32(f.IfIndex), Src: src, Dst: dst,
			SPort: f.Tmpl.SPort, DPort: f.Tmpl.DPort, Seq: seq, Flags: wire.SYN, IPID: ipid})
	}
	p := s.path(f, s.now)
	if p == nil {
		return nil
	}
	for i := 1; i <= int(ttl); i++ {
		if i <= len(p.hops) {
			h := p.hops[i-1]
			if i == int(ttl) {
				lost := h.silent || s.rng.Float64() < h.icmpLoss
				if lost && h.both == 0 {
					return nil
				}
				if !lost {
					s.deliver(s.now+Mono(h.rtt+h.both), wire.Packet{Kind: wire.KindICMP, Src: h.addr, Dst: src, TTL: uint8(256 - i),
						ICMPType: wire.ICMP4TimeExceed, InnerSrc: src, InnerDst: dst, InnerSPort: f.Tmpl.SPort,
						InnerDPort: f.Tmpl.DPort, InnerSeq: seq, HasInnerSeq: true, InnerIPID: ipid, QuoteL4Len: 8})
				}
				if h.both > 0 && i < len(p.hops) {
					ttl++ // and the same packet expires again one hop on
					continue
				}
				return nil
			}
			if s.rng.Float64() < h.transitLoss {
				return nil
			}
			continue
		}
		// destination
		if s.rng.Float64() < p.loss {
			return nil
		}
		if ttl < 64 && p.noReply {
			return nil
		}
		if p.unreach {
			last := p.hops[len(p.hops)-1]
			s.deliver(s.now+Mono(p.rtt), wire.Packet{Kind: wire.KindICMP, Src: last.addr, Dst: src,
				ICMPType: wire.ICMP4Unreach, ICMPCode: 13, InnerSrc: src, InnerDst: dst, InnerSPort: f.Tmpl.SPort,
				InnerDPort: f.Tmpl.DPort, InnerSeq: seq, HasInnerSeq: true, InnerIPID: ipid, QuoteL4Len: 8})
			return nil
		}
		if s.holdOn != nil && s.holdOn(f, s.now) {
			if old, ok := s.held[f]; ok {
				s.deliver(s.now+Mono(p.rtt), wire.Packet{Kind: wire.KindTCP, Src: dst, Dst: src, SPort: f.Tmpl.DPort,
					DPort: f.Tmpl.SPort, Seq: 12346, Ack: old + 1, Flags: wire.ACK, TTL: uint8(64 - len(p.hops))})
				return nil
			}
			if s.held == nil {
				s.held = map[*Flow]uint32{}
			}
			s.held[f] = seq
		} else {
			delete(s.held, f)
		}
		at := s.now + Mono(p.rtt)
		sa := wire.Packet{Kind: wire.KindTCP, Src: dst, Dst: src, SPort: f.Tmpl.DPort, DPort: f.Tmpl.SPort,
			Seq: 12345, Ack: seq + 1, Flags: wire.SYN | wire.ACK, TTL: uint8(64 - len(p.hops))}
		if s.serverTS != nil {
			sa.TSval, sa.HasTS = s.serverTS(f, s.rtBase+int64(at)), true
		}
		s.deliver(at, sa)
		if !s.noRST {
			s.deliver(at+Mono(10*time.Microsecond), wire.Packet{Kind: wire.KindTCP, Outgoing: true, Src: src, Dst: dst,
				SPort: f.Tmpl.SPort, DPort: f.Tmpl.DPort, Seq: seq + 1, Flags: wire.RST})
		}
		return nil
	}
	return nil
}

func newSim(t *testing.T, cfg Config, path func(f *Flow, now Mono) *simPath) *simNet {
	s := &simNet{t: t, rtBase: 1_700_000_000_000_000_000, rng: rand.New(rand.NewPCG(1, 2)), path: path, lastSeq: map[int]uint32{}}
	if cfg.Seed == 0 {
		cfg.Seed = 7
	}
	s.c = New(cfg, s, s, s)
	s.c.SetEventHandler(func(e Event) { s.events = append(s.events, e) })
	return s
}

func (s *simNet) add(ports int) *Endpoint {
	var ps []wire.Port
	for i := 0; i < ports; i++ {
		ps = append(ps, wire.Port(20000+i))
	}
	ep, err := s.c.AddEndpoint("sim", simDst, 443, ps)
	if err != nil {
		s.t.Fatal(err)
	}
	return ep
}

// run advances virtual time by d.
func (s *simNet) run(d time.Duration) {
	end := s.now + Mono(d)
	for s.now < end {
		next := s.c.Advance()
		if len(s.q) > 0 && s.q[0].at < next {
			next = s.q[0].at
		}
		step := s.now + Mono(10*time.Millisecond) // watermark cadence
		if next > step || next <= s.now {
			next = step
		}
		if next > end {
			next = end
		}
		s.now = next
		for len(s.q) > 0 && s.q[0].at <= s.now {
			d := heap.Pop(&s.q).(delivery)
			p := d.pkt
			s.c.OnPacket(&p)
		}
		for i := 0; i < len(s.appQ); {
			if s.appQ[i].at <= s.now {
				a := s.appQ[i]
				s.appQ = append(s.appQ[:i], s.appQ[i+1:]...)
				s.c.OnAppResult(a.id, a.r)
				continue
			}
			i++
		}
		var drops uint64
		if s.dropsFn != nil {
			drops = s.dropsFn(s.now)
		}
		s.c.OnWatermark(Wall(s.rtBase+int64(s.now)), drops, 0)
	}
	s.c.Advance()
}

func (s *simNet) count(typ EventKind) int {
	n := 0
	for _, e := range s.events {
		if e.Type == typ {
			n++
		}
	}
	return n
}

func a4(s string) netip.Addr { return netip.MustParseAddr(s) }

func simpleCfg() Config {
	return Config{Interval: time.Second, Timeout: time.Second, Flows: 16, MaxTTL: 30,
		PPS: 1000, QuoteFallback: true, TraceOnFailure: false}
}

func linear(n int, rtt time.Duration) *simPath {
	p := &simPath{rtt: rtt}
	for i := 1; i <= n; i++ {
		p.hops = append(p.hops, simHop{addr: netip.AddrFrom4([4]byte{10, 0, byte(i), 1}), rtt: rtt * time.Duration(i) / time.Duration(n+1)})
	}
	return p
}

func flowBySport(ep *Endpoint, sport wire.Port) *Flow { return ep.byPort[sport] }

type simApp struct {
	at Mono
	id uint64
	r  AppResult
}

// AppCheck implements AppChecker in the simulation.
func (s *simNet) AppCheck(f *Flow, id uint64, timeout time.Duration) {
	s.appCalls++
	if s.appFn0 != nil {
		s.appFn0(f)
	}
	r, d := AppResult{Outcome: AppPassed, ConnectRTT: 20 * time.Millisecond}, 60*time.Millisecond
	if s.appFn != nil {
		r, d = s.appFn(f)
	}
	s.appQ = append(s.appQ, simApp{at: s.now + Mono(d), id: id, r: r})
}
