// Package wire builds the outgoing TCP SYN probes byte by byte and parses
// captured frames (Ethernet/VLAN/IPv4/IPv6/extension headers/TCP/ICMP/ICMPv6
// with quotes and RFC 4950 MPLS extensions). It allocates nothing on the hot
// path: builders write into caller buffers, the parser fills a caller struct.
package wire

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

// TCP flags.
const (
	FIN = 0x01
	SYN = 0x02
	RST = 0x04
	PSH = 0x08
	ACK = 0x10
	URG = 0x20
)

// Fixed SYN layout. Every probe of every flow has exactly this format, so the
// size, option set and option order never change between probes of a flow.
const (
	SYNOptLen  = 20
	TCPHdrLen  = 20 + SYNOptLen // 40
	IPv4HdrLen = 20
	IPv6HdrLen = 40
	SYNWindow  = 64240
	SYNWScale  = 7
)

// Port is a TCP port. It is its own type so that a port cannot be passed
// or compared where another 16-bit number is meant (an IP ID, a length, a
// window), nor the other way round.
type Port uint16

// FlowTemplate is the immutable identity part of a flow's SYN.
type FlowTemplate struct {
	Src, Dst     netip.Addr
	SPort, DPort Port
	TOS          uint8  // IPv4 TOS / IPv6 traffic class
	FlowLabel    uint32 // IPv6 only, 20 bits
	MSS          uint16
}

// PacketLen returns the size of the SYN for the template's family.
func (t *FlowTemplate) PacketLen() int {
	if t.Src.Is4() {
		return IPv4HdrLen + TCPHdrLen
	}
	return IPv6HdrLen + TCPHdrLen
}

// ErrFamily is returned when src/dst families differ or are invalid.
var ErrFamily = errors.New("wire: source and destination address families differ")

// BuildSYN writes a complete IP+TCP SYN into buf and returns its length.
// ttl is the IPv4 TTL / IPv6 hop limit; ipid is ignored for IPv6.
func BuildSYN(buf []byte, t *FlowTemplate, seq uint32, ttl uint8, ipid uint16) (int, error) {
	switch {
	case t.Src.Is4() && t.Dst.Is4():
		return buildSYN4(buf, t, seq, ttl, ipid)
	case t.Src.Is6() && t.Dst.Is6() && !t.Src.Is4In6() && !t.Dst.Is4In6():
		return buildSYN6(buf, t, seq, ttl)
	}
	return 0, ErrFamily
}

func putSYNTCP(b []byte, t *FlowTemplate, seq uint32) {
	binary.BigEndian.PutUint16(b[0:], uint16(t.SPort))
	binary.BigEndian.PutUint16(b[2:], uint16(t.DPort))
	binary.BigEndian.PutUint32(b[4:], seq)
	binary.BigEndian.PutUint32(b[8:], 0)
	b[12] = byte(TCPHdrLen/4) << 4
	b[13] = SYN
	binary.BigEndian.PutUint16(b[14:], SYNWindow)
	b[16], b[17] = 0, 0 // checksum
	b[18], b[19] = 0, 0 // urgent
	o := b[20:40]
	// MSS, SACK_PERMITTED, TIMESTAMP, NOP, WS (20 bytes; the order Linux
	// uses). The timestamp makes the server put its own clock (TSval) into
	// the SYN/ACK — what tells servers behind one anycast address apart.
	// Our TSval is the probe's sequence number: monotonic per 4-tuple, as
	// PAWS on the server expects.
	o[0], o[1] = 2, 4
	binary.BigEndian.PutUint16(o[2:], t.MSS)
	o[4], o[5] = 4, 2
	o[6], o[7] = 8, 10
	binary.BigEndian.PutUint32(o[8:], seq)
	binary.BigEndian.PutUint32(o[12:], 0)
	o[16] = 1
	o[17], o[18], o[19] = 3, 3, SYNWScale
}

func buildSYN4(buf []byte, t *FlowTemplate, seq uint32, ttl uint8, ipid uint16) (int, error) {
	n := IPv4HdrLen + TCPHdrLen
	if len(buf) < n {
		return 0, errors.New("wire: buffer too small")
	}
	ip := buf[:IPv4HdrLen]
	ip[0] = 0x45
	ip[1] = t.TOS
	binary.BigEndian.PutUint16(ip[2:], uint16(n))
	binary.BigEndian.PutUint16(ip[4:], ipid)
	binary.BigEndian.PutUint16(ip[6:], 0x4000) // DF
	ip[8] = ttl
	ip[9] = 6
	ip[10], ip[11] = 0, 0
	s, d := t.Src.As4(), t.Dst.As4()
	copy(ip[12:16], s[:])
	copy(ip[16:20], d[:])
	binary.BigEndian.PutUint16(ip[10:], ^fold(sum(ip, 0)))
	tcp := buf[IPv4HdrLen:n]
	putSYNTCP(tcp, t, seq)
	ps := sum(s[:], 0)
	ps = sum(d[:], ps)
	ps += 6 + uint32(TCPHdrLen)
	binary.BigEndian.PutUint16(tcp[16:], ^fold(sum(tcp, ps)))
	return n, nil
}

func buildSYN6(buf []byte, t *FlowTemplate, seq uint32, hlim uint8) (int, error) {
	n := IPv6HdrLen + TCPHdrLen
	if len(buf) < n {
		return 0, errors.New("wire: buffer too small")
	}
	ip := buf[:IPv6HdrLen]
	vtcfl := uint32(6)<<28 | uint32(t.TOS)<<20 | (t.FlowLabel & 0xFFFFF)
	binary.BigEndian.PutUint32(ip[0:], vtcfl)
	binary.BigEndian.PutUint16(ip[4:], uint16(TCPHdrLen))
	ip[6] = 6
	ip[7] = hlim
	s, d := t.Src.As16(), t.Dst.As16()
	copy(ip[8:24], s[:])
	copy(ip[24:40], d[:])
	tcp := buf[IPv6HdrLen:n]
	putSYNTCP(tcp, t, seq)
	ps := sum(s[:], 0)
	ps = sum(d[:], ps)
	ps += 6 + uint32(TCPHdrLen)
	binary.BigEndian.PutUint16(tcp[16:], ^fold(sum(tcp, ps)))
	return n, nil
}

func sum(b []byte, acc uint32) uint32 {
	i := 0
	for ; i+1 < len(b); i += 2 {
		acc += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if i < len(b) {
		acc += uint32(b[i]) << 8
	}
	return acc
}

func fold(acc uint32) uint16 {
	for acc>>16 != 0 {
		acc = acc&0xffff + acc>>16
	}
	return uint16(acc)
}

// Checksum returns the Internet checksum of b (RFC 1071).
func Checksum(b []byte) uint16 { return ^fold(sum(b, 0)) }

// TCPChecksumOK verifies a TCP segment checksum against its pseudo-header.
func TCPChecksumOK(src, dst netip.Addr, seg []byte) bool {
	var ps uint32
	if src.Is4() {
		s, d := src.As4(), dst.As4()
		ps = sum(s[:], 0)
		ps = sum(d[:], ps)
	} else {
		s, d := src.As16(), dst.As16()
		ps = sum(s[:], 0)
		ps = sum(d[:], ps)
	}
	ps += 6 + uint32(len(seg))
	return fold(sum(seg, ps)) == 0xffff
}
