package wire

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

// Kind of a parsed packet that is relevant to mpmtr.
type Kind uint8

const (
	KindNone Kind = iota
	KindTCP       // a TCP segment (incoming reply or our own outgoing SYN/RST)
	KindICMP      // ICMP/ICMPv6 error carrying a quote of a TCP packet
)

// ICMP types we care about.
const (
	ICMP4Unreach      = 3
	ICMP4TimeExceed   = 11
	ICMP6Unreach      = 1
	ICMP6TimeExceed   = 3
	ICMP6PacketTooBig = 2
)

// Link-layer header types (sll_hatype) handled explicitly.
const (
	HatypeEther    = 1
	HatypeLoopback = 772
	HatypeNone     = 0xFFFE
)

// MaxMPLS is the number of MPLS label stack entries retained from RFC 4950
// extensions.
const MaxMPLS = 4

// MPLSEntry is one RFC 4950 label stack entry.
type MPLSEntry struct {
	Label uint32
	TC    uint8
	S     bool
	TTL   uint8
}

// Packet is the result of parsing a captured frame. It is a plain value;
// Parse resets it fully.
type Packet struct {
	Kind     Kind
	Outgoing bool
	IfIndex  int32
	TS       int64 // kernel timestamp, CLOCK_REALTIME ns (set by capture)
	TSKernel bool  // TS came from the kernel (not a userspace fallback)

	V6       bool
	Src, Dst netip.Addr
	TTL      uint8 // outer TTL / hop limit
	IPID     uint16

	// TCP (Kind==KindTCP)
	SPort, DPort Port
	Seq, Ack     uint32
	Flags        uint8
	TCPLen       int    // TCP header+payload length
	TSval        uint32 // TCP timestamp option of the packet (HasTS)
	HasTS        bool

	// ICMP (Kind==KindICMP)
	ICMPType, ICMPCode uint8
	InnerProto         uint8
	InnerSrc, InnerDst netip.Addr
	InnerSPort         Port
	InnerDPort         Port
	InnerSeq           uint32
	HasInnerSeq        bool
	InnerIPID          uint16 // IPv4 only
	InnerTTL           uint8
	InnerFlowLabel     uint32 // IPv6 only
	InnerTOS           uint8
	QuoteL4Len         int // bytes of the quoted L4 header available
	MPLS               [MaxMPLS]MPLSEntry
	NMPLS              int
}

// Parse errors. They are counters in the receiver, never fatal.
var (
	ErrShort      = errors.New("wire: truncated packet")
	ErrMalformed  = errors.New("wire: malformed header")
	ErrFragment   = errors.New("wire: fragment")
	ErrChecksum   = errors.New("wire: bad checksum")
	ErrIrrelevant = errors.New("wire: irrelevant packet")
)

// ParseOpts control link-layer handling and checksum verification.
type ParseOpts struct {
	Hatype uint16 // sll_hatype; HatypeEther/Loopback → Ethernet header present
	// SkipL4Checksum disables TCP/ICMP checksum verification. Set it for frames
	// whose checksum is not computed yet (TP_STATUS_CSUMNOTREADY, typical for
	// locally generated or veth-forwarded packets) or already verified by HW.
	SkipL4Checksum bool
}

// Parse decodes a link-layer frame into p.
func Parse(b []byte, o ParseOpts, p *Packet) error {
	*p = Packet{}
	switch o.Hatype {
	case HatypeEther, HatypeLoopback:
		var err error
		if b, err = stripEthernet(b); err != nil {
			return err
		}
	}
	return ParseL3(b, o.SkipL4Checksum, p)
}

// stripEthernet removes the Ethernet header and up to two VLAN tags and
// returns the network-layer payload (IPv4 or IPv6 only).
func stripEthernet(b []byte) ([]byte, error) {
	if len(b) < 14 {
		return nil, ErrShort
	}
	et := binary.BigEndian.Uint16(b[12:])
	b = b[14:]
	for i := 0; i < 2 && (et == 0x8100 || et == 0x88a8); i++ {
		if len(b) < 4 {
			return nil, ErrShort
		}
		et = binary.BigEndian.Uint16(b[2:])
		b = b[4:]
	}
	switch et {
	case 0x0800, 0x86DD:
		return b, nil
	}
	return nil, ErrIrrelevant
}

// ParseL3 decodes a packet starting at the IP header.
func ParseL3(b []byte, skipCsum bool, p *Packet) error {
	if len(b) < 1 {
		return ErrShort
	}
	switch b[0] >> 4 {
	case 4:
		return parse4(b, skipCsum, p)
	case 6:
		return parse6(b, skipCsum, p)
	}
	return ErrMalformed
}

func addr4(b []byte) netip.Addr { return netip.AddrFrom4([4]byte(b[:4])) }
func addr16(b []byte) netip.Addr {
	return netip.AddrFrom16([16]byte(b[:16]))
}

// ipv4Header validates an IPv4 header and returns (ihl, total length).
func ipv4Header(b []byte, quoted bool) (int, int, error) {
	if len(b) < 20 {
		return 0, 0, ErrShort
	}
	ihl := int(b[0]&0x0f) * 4
	if ihl < 20 || len(b) < ihl {
		return 0, 0, ErrMalformed
	}
	tot := int(binary.BigEndian.Uint16(b[2:]))
	if !quoted {
		if tot < ihl {
			return 0, 0, ErrMalformed
		}
		if tot > len(b) {
			return 0, 0, ErrShort
		}
	}
	return ihl, tot, nil
}

func parse4(b []byte, skipCsum bool, p *Packet) error {
	ihl, tot, err := ipv4Header(b, false)
	if err != nil {
		return err
	}
	if fold(sum(b[:ihl], 0)) != 0xffff {
		return ErrChecksum
	}
	b = b[:tot]
	frag := binary.BigEndian.Uint16(b[6:])
	if frag&0x3fff != 0 { // MF or offset
		return ErrFragment
	}
	p.V6 = false
	p.Src, p.Dst = addr4(b[12:]), addr4(b[16:])
	p.TTL = b[8]
	p.IPID = binary.BigEndian.Uint16(b[4:])
	l4 := b[ihl:]
	switch b[9] {
	case 6:
		return parseTCP(l4, skipCsum, p)
	case 1:
		return parseICMP4(l4, skipCsum, p)
	}
	return ErrIrrelevant
}

// skipExt6 walks IPv6 extension headers starting with nh at b and returns
// the upper-layer protocol and its payload. Fragments other than a first
// fragment that is also the last one are rejected.
func skipExt6(nh uint8, b []byte) (uint8, []byte, error) {
	for i := 0; i < 8; i++ {
		switch nh {
		case 0, 43, 60: // hop-by-hop, routing, destination options
			if len(b) < 8 {
				return 0, nil, ErrShort
			}
			l := (int(b[1]) + 1) * 8
			if len(b) < l {
				return 0, nil, ErrShort
			}
			nh, b = b[0], b[l:]
		case 44: // fragment
			if len(b) < 8 {
				return 0, nil, ErrShort
			}
			off := binary.BigEndian.Uint16(b[2:])
			if off&0xfff9 != 0 { // offset != 0 or M flag
				return 0, nil, ErrFragment
			}
			nh, b = b[0], b[8:]
		case 51: // AH
			if len(b) < 8 {
				return 0, nil, ErrShort
			}
			l := (int(b[1]) + 2) * 4
			if len(b) < l {
				return 0, nil, ErrShort
			}
			nh, b = b[0], b[l:]
		default:
			return nh, b, nil
		}
	}
	return 0, nil, ErrMalformed
}

func parse6(b []byte, skipCsum bool, p *Packet) error {
	if len(b) < 40 {
		return ErrShort
	}
	pl := int(binary.BigEndian.Uint16(b[4:]))
	if 40+pl > len(b) {
		return ErrShort
	}
	b = b[:40+pl]
	p.V6 = true
	p.Src, p.Dst = addr16(b[8:]), addr16(b[24:])
	p.TTL = b[7]
	nh, l4, err := skipExt6(b[6], b[40:])
	if err != nil {
		return err
	}
	switch nh {
	case 6:
		return parseTCP(l4, skipCsum, p)
	case 58:
		return parseICMP6(l4, skipCsum, p)
	}
	return ErrIrrelevant
}

func parseTCP(b []byte, skipCsum bool, p *Packet) error {
	if len(b) < 20 {
		return ErrShort
	}
	off := int(b[12]>>4) * 4
	if off < 20 || off > len(b) {
		return ErrMalformed
	}
	if !skipCsum && !TCPChecksumOK(p.Src, p.Dst, b) {
		return ErrChecksum
	}
	p.Kind = KindTCP
	p.SPort = Port(binary.BigEndian.Uint16(b[0:]))
	p.DPort = Port(binary.BigEndian.Uint16(b[2:]))
	p.Seq = binary.BigEndian.Uint32(b[4:])
	p.Ack = binary.BigEndian.Uint32(b[8:])
	p.Flags = b[13]
	p.TCPLen = len(b)
	p.HasTS = false
	o := b[20:off]
opts:
	for len(o) > 0 {
		switch {
		case o[0] == 0: // end of options
			break opts
		case o[0] == 1: // NOP
			o = o[1:]
		case len(o) < 2 || int(o[1]) < 2 || int(o[1]) > len(o):
			break opts // malformed: ignore the rest
		default:
			if o[0] == 8 && o[1] == 10 {
				p.TSval, p.HasTS = binary.BigEndian.Uint32(o[2:]), true
			}
			o = o[o[1]:]
		}
	}
	return nil
}

func parseICMP4(b []byte, skipCsum bool, p *Packet) error {
	if len(b) < 8 {
		return ErrShort
	}
	t := b[0]
	if t != ICMP4Unreach && t != ICMP4TimeExceed {
		return ErrIrrelevant
	}
	if !skipCsum && Checksum(b) != 0 {
		return ErrChecksum
	}
	p.ICMPType, p.ICMPCode = t, b[1]
	q := b[8:]
	// RFC 4884: length of the original datagram in 32-bit words (byte 5).
	origLen := int(b[5]) * 4
	ihl, _, err := ipv4Header(q, true)
	if err != nil {
		return err
	}
	if q[9] != 6 {
		return ErrIrrelevant
	}
	p.InnerProto = 6
	p.InnerSrc, p.InnerDst = addr4(q[12:]), addr4(q[16:])
	p.InnerIPID = binary.BigEndian.Uint16(q[4:])
	p.InnerTTL = q[8]
	p.InnerTOS = q[1]
	quoteEnd := len(q)
	if origLen >= ihl+4 && origLen <= len(q) {
		// A length that does not even cover the quoted header and the ports
		// is not an RFC 4884 length (old routers leave garbage there).
		quoteEnd = origLen
	} else if origLen == 0 && len(q) > 128+4 {
		// Non-RFC4884 router with extensions: RFC 4884 §5 "compliant"
		// heuristic — original datagram is the first 128 bytes.
		if hasExt(q[128:]) {
			quoteEnd = 128
		}
	}
	if err := quotedTCP(q[ihl:quoteEnd], p); err != nil {
		return err
	}
	parseExtensions(q, origLen, p)
	p.Kind = KindICMP
	return nil
}

func parseICMP6(b []byte, skipCsum bool, p *Packet) error {
	if len(b) < 8 {
		return ErrShort
	}
	t := b[0]
	if t != ICMP6Unreach && t != ICMP6TimeExceed {
		return ErrIrrelevant
	}
	if !skipCsum {
		s, d := p.Src.As16(), p.Dst.As16()
		ps := sum(s[:], 0)
		ps = sum(d[:], ps)
		ps += uint32(len(b)) + 58
		if fold(sum(b, ps)) != 0xffff {
			return ErrChecksum
		}
	}
	p.ICMPType, p.ICMPCode = t, b[1]
	q := b[8:]
	// RFC 4884 for ICMPv6: length in 64-bit words at byte 4.
	origLen := int(b[4]) * 8
	if len(q) < 40 {
		return ErrShort
	}
	if q[0]>>4 != 6 {
		return ErrMalformed
	}
	vtcfl := binary.BigEndian.Uint32(q[0:])
	p.InnerTOS = uint8(vtcfl >> 20)
	p.InnerFlowLabel = vtcfl & 0xFFFFF
	p.InnerSrc, p.InnerDst = addr16(q[8:]), addr16(q[24:])
	p.InnerTTL = q[7]
	quoteEnd := len(q)
	if origLen >= 40+4 && origLen <= len(q) {
		quoteEnd = origLen
	} else if origLen == 0 && len(q) > 128+4 && hasExt(q[128:]) {
		quoteEnd = 128
	}
	nh, l4, err := skipExt6(q[6], q[40:quoteEnd])
	if err != nil {
		return err
	}
	if nh != 6 {
		return ErrIrrelevant
	}
	p.InnerProto = 6
	if err := quotedTCP(l4, p); err != nil {
		return err
	}
	parseExtensions(q, origLen, p)
	p.Kind = KindICMP
	return nil
}

func quotedTCP(l4 []byte, p *Packet) error {
	if len(l4) < 4 {
		// Not enough to identify the flow: never correlate on less.
		return ErrShort
	}
	p.QuoteL4Len = len(l4)
	p.InnerSPort = Port(binary.BigEndian.Uint16(l4[0:]))
	p.InnerDPort = Port(binary.BigEndian.Uint16(l4[2:]))
	if len(l4) >= 8 {
		p.InnerSeq = binary.BigEndian.Uint32(l4[4:])
		p.HasInnerSeq = true
	}
	return nil
}

// hasExt reports whether b starts with a plausible RFC 4884 extension header.
func hasExt(b []byte) bool {
	return len(b) >= 4 && b[0]>>4 == 2
}

// parseExtensions extracts RFC 4950 MPLS label stacks from an RFC 4884
// extension structure following the quote. q is the ICMP payload after the
// 8-byte header.
func parseExtensions(q []byte, origLen int, p *Packet) {
	start := origLen
	if start == 0 {
		start = 128
	}
	if start < 128 || start >= len(q) {
		return
	}
	e := q[start:]
	if !hasExt(e) {
		return
	}
	if Checksum(e) != 0 && binary.BigEndian.Uint16(e[2:]) != 0 {
		return
	}
	e = e[4:]
	for len(e) >= 4 {
		l := int(binary.BigEndian.Uint16(e[0:]))
		if l < 4 || l > len(e) {
			return
		}
		class, ctype := e[2], e[3]
		if class == 1 && ctype == 1 {
			for o := e[4:l]; len(o) >= 4 && p.NMPLS < MaxMPLS; o = o[4:] {
				v := binary.BigEndian.Uint32(o)
				p.MPLS[p.NMPLS] = MPLSEntry{Label: v >> 12, TC: uint8(v>>9) & 7, S: v&0x100 != 0, TTL: uint8(v)}
				p.NMPLS++
			}
		}
		e = e[l:]
	}
}
