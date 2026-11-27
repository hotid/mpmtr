package sys

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"

	"github.com/hotid/mpmtr/internal/wire"
)

// CaptureOpts configure the AF_PACKET receiver.
type CaptureOpts struct {
	Ifindex       int // 0 = all interfaces
	PortLo        wire.Port
	PortHi        wire.Port
	BlockSize     int // TPACKET_V3 block size (default 1 MiB)
	BlockNr       int // number of blocks (default 32)
	RetireTovMs   int // block retire timeout (default 4 ms)
	Snaplen       int // bytes kept per packet (default 384)
	FilterAllICMP bool
}

// Capture is an AF_PACKET SOCK_RAW socket (ETH_P_ALL, so outgoing frames
// including kernel RSTs are visible) with a PACKET_RX_RING TPACKET_V3 ring
// and a classic BPF filter evaluated in the kernel.
type Capture struct {
	// Warnings lists socket options that could not be set; the capture
	// works without them.
	Warnings  []string
	fd        int
	ring      []byte
	bsize     int
	bnr       int
	cur       int
	tov       time.Duration
	closed    atomic.Bool
	running   atomic.Bool
	done      chan struct{}
	relMu     sync.Mutex
	Malformed atomic.Uint64
	Debug     func(string)
	Packets   atomic.Uint64
}

const skfNetOff = 0xFFF00000 // SKF_NET_OFF (-0x100000) as uint32

type insn struct {
	i      bpf.Instruction
	label  string
	jt, jf string
}

// assemble resolves label-relative jumps.
func assemble(prog []insn) ([]bpf.RawInstruction, error) {
	idx := map[string]int{}
	for i, p := range prog {
		if p.label != "" {
			idx[p.label] = i
		}
	}
	var out []bpf.Instruction
	for i, p := range prog {
		ins := p.i
		if j, ok := ins.(bpf.JumpIf); ok {
			if p.jt != "" {
				t, ok := idx[p.jt]
				if !ok || t <= i {
					return nil, fmt.Errorf("bpf: bad label %q", p.jt)
				}
				j.SkipTrue = uint8(t - i - 1)
			}
			if p.jf != "" {
				t, ok := idx[p.jf]
				if !ok || t <= i {
					return nil, fmt.Errorf("bpf: bad label %q", p.jf)
				}
				j.SkipFalse = uint8(t - i - 1)
			}
			ins = j
		}
		out = append(out, ins)
	}
	return bpf.Assemble(out)
}

// filterProgram accepts: TCP with source or destination port in our range
// (replies, our own SYNs and kernel RSTs), ICMP dest-unreachable/time-
// exceeded, ICMPv6 dest-unreachable/time-exceeded, and IPv6 packets with
// extension headers (parsed in userspace). Everything else is dropped in
// the kernel. Offsets are relative to the network header (SKF_NET_OFF), so
// the program works for any link type.
func filterProgram(lo, hi wire.Port, snap uint32) ([]bpf.RawInstruction, error) {
	n := func(off uint32) uint32 { return skfNetOff + off }
	L, H := uint32(lo), uint32(hi)
	p := []insn{
		{i: bpf.LoadExtension{Num: bpf.ExtProto}},
		{i: bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0800}, jt: "v4"},
		{i: bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x86DD}, jt: "v6", jf: "drop"},
		// IPv4
		{label: "v4", i: bpf.LoadAbsolute{Off: n(9), Size: 1}},
		{i: bpf.JumpIf{Cond: bpf.JumpEqual, Val: 6}, jt: "v4tcp"},
		{i: bpf.JumpIf{Cond: bpf.JumpEqual, Val: 1}, jt: "v4icmp", jf: "drop"},
		{label: "v4icmp", i: bpf.LoadMemShift{Off: n(0)}},
		{i: bpf.LoadIndirect{Off: n(0), Size: 1}},
		{i: bpf.JumpIf{Cond: bpf.JumpEqual, Val: 3}, jt: "accept"},
		{i: bpf.JumpIf{Cond: bpf.JumpEqual, Val: 11}, jt: "accept", jf: "drop"},
		{label: "v4tcp", i: bpf.LoadAbsolute{Off: n(6), Size: 2}},
		{i: bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 0x1fff}, jt: "drop"},
		{i: bpf.LoadMemShift{Off: n(0)}},
		// Every outgoing pure SYN (any port): needed to see our own SYN after
		// a local SNAT moved it out of the port range.
		{i: bpf.LoadExtension{Num: bpf.ExtType}},
		{i: bpf.JumpIf{Cond: bpf.JumpEqual, Val: unix.PACKET_OUTGOING}, jf: "v4sport"},
		{i: bpf.LoadIndirect{Off: n(13), Size: 1}},
		{i: bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x02}, jt: "accept"},
		{label: "v4sport", i: bpf.LoadIndirect{Off: n(0), Size: 2}},
		{i: bpf.LoadIndirect{Off: n(0), Size: 2}},
		{i: bpf.JumpIf{Cond: bpf.JumpGreaterOrEqual, Val: L}, jf: "v4dport"},
		{i: bpf.JumpIf{Cond: bpf.JumpGreaterThan, Val: H}, jt: "v4dport", jf: "accept"},
		{label: "v4dport", i: bpf.LoadIndirect{Off: n(2), Size: 2}},
		{i: bpf.JumpIf{Cond: bpf.JumpGreaterOrEqual, Val: L}, jf: "drop"},
		{i: bpf.JumpIf{Cond: bpf.JumpGreaterThan, Val: H}, jt: "drop", jf: "accept"},
		// IPv6
		{label: "v6", i: bpf.LoadAbsolute{Off: n(6), Size: 1}},
		{i: bpf.JumpIf{Cond: bpf.JumpEqual, Val: 6}, jt: "v6tcp"},
		{i: bpf.JumpIf{Cond: bpf.JumpEqual, Val: 58}, jt: "v6icmp"},
		{i: bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0}, jt: "accept"},
		{i: bpf.JumpIf{Cond: bpf.JumpEqual, Val: 43}, jt: "accept"},
		{i: bpf.JumpIf{Cond: bpf.JumpEqual, Val: 44}, jt: "accept"},
		{i: bpf.JumpIf{Cond: bpf.JumpEqual, Val: 60}, jt: "accept", jf: "drop"},
		{label: "v6icmp", i: bpf.LoadAbsolute{Off: n(40), Size: 1}},
		{i: bpf.JumpIf{Cond: bpf.JumpEqual, Val: 1}, jt: "accept"},
		{i: bpf.JumpIf{Cond: bpf.JumpEqual, Val: 3}, jt: "accept", jf: "drop"},
		{label: "v6tcp", i: bpf.LoadExtension{Num: bpf.ExtType}},
		{i: bpf.JumpIf{Cond: bpf.JumpEqual, Val: unix.PACKET_OUTGOING}, jf: "v6sport"},
		{i: bpf.LoadAbsolute{Off: n(53), Size: 1}},
		{i: bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x02}, jt: "accept"},
		{label: "v6sport", i: bpf.LoadAbsolute{Off: n(40), Size: 2}},
		{i: bpf.JumpIf{Cond: bpf.JumpGreaterOrEqual, Val: L}, jf: "v6dport"},
		{i: bpf.JumpIf{Cond: bpf.JumpGreaterThan, Val: H}, jt: "v6dport", jf: "accept"},
		{label: "v6dport", i: bpf.LoadAbsolute{Off: n(42), Size: 2}},
		{i: bpf.JumpIf{Cond: bpf.JumpGreaterOrEqual, Val: L}, jf: "drop"},
		{i: bpf.JumpIf{Cond: bpf.JumpGreaterThan, Val: H}, jt: "drop", jf: "accept"},
		{label: "drop", i: bpf.RetConstant{Val: 0}},
		{label: "accept", i: bpf.RetConstant{Val: snap}},
	}
	return assemble(p)
}

func attachFilter(fd int, prog []bpf.RawInstruction) error {
	fp := unix.SockFprog{Len: uint16(len(prog)), Filter: (*unix.SockFilter)(unsafe.Pointer(&prog[0]))}
	if err := unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &fp); err != nil {
		return fmt.Errorf("attach BPF: %w", err)
	}
	return nil
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }

// NewCapture opens the receiver.
func NewCapture(o CaptureOpts) (*Capture, error) {
	if o.BlockSize == 0 {
		o.BlockSize = 1 << 20
	}
	if o.BlockNr == 0 {
		o.BlockNr = 32
	}
	if o.RetireTovMs == 0 {
		o.RetireTovMs = 4
	}
	if o.Snaplen == 0 {
		o.Snaplen = 384
	}
	proto := int(htons(unix.ETH_P_ALL))
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, proto)
	if err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			return nil, ErrPermission
		}
		return nil, fmt.Errorf("AF_PACKET socket: %w", err)
	}
	c := &Capture{fd: fd, bsize: o.BlockSize, bnr: o.BlockNr, tov: time.Duration(o.RetireTovMs) * time.Millisecond,
		done: make(chan struct{})}
	fail := func(err error) (*Capture, error) { c.release(); return nil, err }
	// Drop everything until bound and filtered.
	if err := attachFilter(fd, []bpf.RawInstruction{{Op: 0x06, K: 0}}); err != nil {
		return fail(err)
	}
	if err := unix.SetsockoptInt(fd, unix.SOL_PACKET, unix.PACKET_VERSION, unix.TPACKET_V3); err != nil {
		return fail(fmt.Errorf("TPACKET_V3 unsupported: %w", err))
	}
	// Kernel software RX timestamps for every packet (also enables
	// netstamp so skb->tstamp is set at receive time).
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_TIMESTAMPNS, 1); err != nil {
		c.Warnings = append(c.Warnings, fmt.Sprintf("capture SO_TIMESTAMPNS: %v (packet times may be taken later than arrival)", err))
	}
	req := unix.TpacketReq3{Block_size: uint32(o.BlockSize), Block_nr: uint32(o.BlockNr),
		Frame_size: 2048, Frame_nr: uint32(o.BlockSize / 2048 * o.BlockNr), Retire_blk_tov: uint32(o.RetireTovMs)}
	if err := unix.SetsockoptTpacketReq3(fd, unix.SOL_PACKET, unix.PACKET_RX_RING, &req); err != nil {
		return fail(fmt.Errorf("PACKET_RX_RING: %w", err))
	}
	ring, err := unix.Mmap(fd, 0, o.BlockSize*o.BlockNr, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED|unix.MAP_LOCKED)
	if err != nil {
		ring, err = unix.Mmap(fd, 0, o.BlockSize*o.BlockNr, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
		if err != nil {
			return fail(fmt.Errorf("mmap ring: %w", err))
		}
	}
	c.ring = ring
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: uint16(proto), Ifindex: o.Ifindex}); err != nil {
		return fail(fmt.Errorf("bind AF_PACKET: %w", err))
	}
	prog, err := filterProgram(o.PortLo, o.PortHi, uint32(o.Snaplen))
	if err != nil {
		return fail(err)
	}
	if err := attachFilter(fd, prog); err != nil {
		return fail(err)
	}
	// Discard anything that slipped in before the real filter, and reset
	// the drop counters.
	c.Stats()
	return c, nil
}

// Stats returns and resets (kernel semantics) the ring counters.
func (c *Capture) Stats() (packets, drops uint64) {
	st, err := unix.GetsockoptTpacketStatsV3(c.fd, unix.SOL_PACKET, unix.PACKET_STATISTICS)
	if err != nil {
		return 0, 0
	}
	return uint64(st.Packets), uint64(st.Drops)
}

// TPACKET_V3 layout offsets.
const (
	bdStatus   = 8 // tpacket_block_desc.hdr.bh1.block_status
	bdNumPkts  = 12
	bdFirstOff = 16
	tpNext     = 0
	tpSec      = 4
	tpNsec     = 8
	tpSnaplen  = 12
	tpLen      = 16
	tpStatus   = 20
	tpMac      = 24
	tpNet      = 26
	tpHdrLen   = 48 // TPACKET_ALIGN(sizeof(struct tpacket3_hdr))
	sllIfindex = 4
	sllHatype  = 8
	sllPkttype = 10

	tpStatusUser         = 1
	tpStatusCsumNotReady = 1 << 3
	tpStatusCsumValid    = 1 << 7
	tpStatusTSSoftware   = 1 << 29
	tpStatusTSRawHW      = 1 << 31
)

func (c *Capture) u32(off int) uint32 { return *(*uint32)(unsafe.Pointer(&c.ring[off])) }
func (c *Capture) u16(off int) uint16 { return *(*uint16)(unsafe.Pointer(&c.ring[off])) }

func (c *Capture) blockStatus(b int) *uint32 {
	return (*uint32)(unsafe.Pointer(&c.ring[b*c.bsize+bdStatus]))
}

// Sink receives parsed packets in batches and periodic watermarks.
type Sink interface {
	// Packets delivers a batch (the slice is reused after return).
	Packets(batch []wire.Packet)
	// Watermark: all packets with kernel timestamp <= rt were delivered;
	// drops is the number of packets lost since the previous statistics
	// read, which happened in the realtime interval (dropFrom, dropTo].
	Watermark(rt int64, drops uint64, dropFrom, dropTo int64)
}

// Run reads the ring until Close. Watermarks are emitted at least every
// ~10 ms. A packet sitting in a not-yet-retired block can be up to the
// retire timeout old, so the watermark lags wall time by tov+margin.
func (c *Capture) Run(sink Sink) error {
	c.running.Store(true)
	defer func() { c.release(); close(c.done) }()
	batch := make([]wire.Packet, 0, 256)
	pfd := []unix.PollFd{{Fd: int32(c.fd), Events: unix.POLLIN | unix.POLLERR}}
	lastWM := time.Now()
	lastStats := lastWM.UnixNano()
	// watermark reports that everything up to rt was delivered, with the
	// drops since the previous statistics read. Drops happened at packet
	// arrival, after that read and before this one — not bounded by the
	// lagging watermark.
	watermark := func(now time.Time, rt int64) {
		_, drops := c.Stats()
		sink.Watermark(rt, drops, lastStats, now.UnixNano())
		lastStats = now.UnixNano()
		lastWM = now
	}
	var blockTS int64 // kernel time of the newest packet delivered so far
	for !c.closed.Load() {
		st := atomic.LoadUint32(c.blockStatus(c.cur))
		if st&tpStatusUser == 0 {
			now := time.Now()
			if now.Sub(lastWM) >= 5*time.Millisecond {
				watermark(now, now.Add(-c.tov-6*time.Millisecond).UnixNano())
			}
			_, err := unix.Poll(pfd, 10)
			if err != nil && !errors.Is(err, unix.EINTR) {
				return err
			}
			continue
		}
		base := c.cur * c.bsize
		num := int(c.u32(base + bdNumPkts))
		off := base + int(c.u32(base+bdFirstOff))
		for i := 0; i < num; i++ {
			snap := int(c.u32(off + tpSnaplen))
			status := c.u32(off + tpStatus)
			mac := int(c.u16(off + tpMac))
			sll := off + tpHdrLen
			hatype := c.u16(sll + sllHatype)
			pkttype := c.ring[sll+sllPkttype]
			if off+mac+snap <= len(c.ring) && snap > 0 {
				data := c.ring[off+mac : off+mac+snap]
				outgoing := pkttype == unix.PACKET_OUTGOING
				skip := outgoing || status&(tpStatusCsumNotReady|tpStatusCsumValid) != 0
				batch = append(batch, wire.Packet{})
				p := &batch[len(batch)-1]
				if err := wire.Parse(data, wire.ParseOpts{Hatype: hatype, SkipL4Checksum: skip}, p); err != nil {
					if c.Debug != nil {
						c.Debug(fmt.Sprintf("parse err=%v hatype=%d pkttype=%d status=%#x snap=%d mac=%d net=%d", err, hatype, pkttype, status, snap, mac, c.u16(off+tpNet)))
					}
					batch = batch[:len(batch)-1]
					// A packet longer than the snap length (data of a real
					// connection on our port, e.g. an application check) is
					// cut short by design: never one of our replies.
					truncated := int(c.u32(off+tpLen)) > snap && errors.Is(err, wire.ErrShort)
					if !errors.Is(err, wire.ErrIrrelevant) && !truncated {
						c.Malformed.Add(1)
					}
				} else {
					p.Outgoing = outgoing
					p.IfIndex = int32(*(*int32)(unsafe.Pointer(&c.ring[sll+sllIfindex])))
					p.TS = int64(c.u32(off+tpSec))*1e9 + int64(c.u32(off+tpNsec))
					p.TSKernel = true
				}
			}
			if ts := int64(c.u32(off+tpSec))*1e9 + int64(c.u32(off+tpNsec)); ts > blockTS {
				blockTS = ts
			}
			c.Packets.Add(1)
			next := int(c.u32(off + tpNext))
			if next == 0 {
				break
			}
			off += next
		}
		atomic.StoreUint32(c.blockStatus(c.cur), 0) // TP_STATUS_KERNEL
		c.cur = (c.cur + 1) % c.bnr
		if len(batch) > 0 {
			sink.Packets(batch)
			batch = batch[:0]
		}
		// A reader that is behind always finds the next block ready and
		// never reaches the idle branch: the watermark and the drop
		// counters must not wait for it to catch up. Blocks are filled in
		// order, so everything up to this block's newest packet is out.
		if now := time.Now(); blockTS != 0 && now.Sub(lastWM) >= 5*time.Millisecond {
			watermark(now, min(blockTS, now.Add(-c.tov-6*time.Millisecond).UnixNano()))
		}
	}
	return nil
}

// Close stops Run (within one poll period) and releases the socket.
func (c *Capture) Close() {
	if c.closed.Swap(true) {
		return
	}
	if !c.running.Load() {
		c.release()
		return
	}
	<-c.done
}

func (c *Capture) release() {
	// Run and a Close that came before Run started may both get here.
	c.relMu.Lock()
	defer c.relMu.Unlock()
	if c.ring != nil {
		_ = unix.Munmap(c.ring)
		c.ring = nil
	}
	if c.fd >= 0 {
		unix.Close(c.fd)
		c.fd = -1
	}
}
