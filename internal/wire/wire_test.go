package wire

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

var (
	src4 = netip.MustParseAddr("192.0.2.1")
	dst4 = netip.MustParseAddr("198.51.100.7")
	src6 = netip.MustParseAddr("2001:db8::1")
	dst6 = netip.MustParseAddr("2001:db8:1::7")
)

func tmpl4() *FlowTemplate {
	return &FlowTemplate{Src: src4, Dst: dst4, SPort: 20001, DPort: 443, TOS: 0x10, MSS: 1460}
}

func tmpl6() *FlowTemplate {
	return &FlowTemplate{Src: src6, Dst: dst6, SPort: 20002, DPort: 80, TOS: 0x28, FlowLabel: 0xABCDE, MSS: 1440}
}

func TestBuildSYN4(t *testing.T) {
	var buf [128]byte
	n, err := BuildSYN(buf[:], tmpl4(), 0xdeadbeef, 7, 0x1234)
	if err != nil {
		t.Fatal(err)
	}
	if n != 60 {
		t.Fatalf("len %d", n)
	}
	b := buf[:n]
	if Checksum(b[:20]) != 0 {
		t.Fatal("ip checksum")
	}
	if !TCPChecksumOK(src4, dst4, b[20:]) {
		t.Fatal("tcp checksum")
	}
	if b[8] != 7 || binary.BigEndian.Uint16(b[4:]) != 0x1234 || b[1] != 0x10 {
		t.Fatal("ttl/ipid/tos")
	}
	if binary.BigEndian.Uint16(b[6:]) != 0x4000 {
		t.Fatal("DF")
	}
	opts := b[40:60]
	want := []byte{2, 4, 0x05, 0xb4, 4, 2, 8, 10, 0xde, 0xad, 0xbe, 0xef, 0, 0, 0, 0, 1, 3, 3, 7}
	for i := range want {
		if opts[i] != want[i] {
			t.Fatalf("opts %x", opts)
		}
	}
	var p Packet
	if err := ParseL3(b, false, &p); err != nil {
		t.Fatal(err)
	}
	if p.Kind != KindTCP || p.Seq != 0xdeadbeef || p.Flags != SYN || p.SPort != 20001 || p.DPort != 443 || p.IPID != 0x1234 ||
		!p.HasTS || p.TSval != 0xdeadbeef {
		t.Fatalf("%+v", p)
	}
}

// Identity invariant: probes of one flow differ only in seq (also carried
// as our TSval), IP ID, TTL and checksums.
func TestSYNStableFormat(t *testing.T) {
	var a, b [128]byte
	for _, tm := range []*FlowTemplate{tmpl4(), tmpl6()} {
		na, _ := BuildSYN(a[:], tm, 1, 1, 1)
		nb, _ := BuildSYN(b[:], tm, 0xffffffff, 64, 999)
		if na != nb {
			t.Fatal("size differs")
		}
		mask := map[int]bool{}
		if tm.Src.Is4() {
			for _, i := range []int{4, 5, 8, 10, 11, 20 + 4, 20 + 5, 20 + 6, 20 + 7, 20 + 16, 20 + 17, 20 + 28, 20 + 29, 20 + 30, 20 + 31} {
				mask[i] = true
			}
		} else {
			for _, i := range []int{7, 40 + 4, 40 + 5, 40 + 6, 40 + 7, 40 + 16, 40 + 17, 40 + 28, 40 + 29, 40 + 30, 40 + 31} {
				mask[i] = true
			}
		}
		for i := 0; i < na; i++ {
			if !mask[i] && a[i] != b[i] {
				t.Fatalf("byte %d differs between probes of one flow", i)
			}
		}
	}
}

func TestBuildSYN6(t *testing.T) {
	var buf [128]byte
	n, err := BuildSYN(buf[:], tmpl6(), 42, 3, 0)
	if err != nil {
		t.Fatal(err)
	}
	b := buf[:n]
	if n != 80 {
		t.Fatal(n)
	}
	v := binary.BigEndian.Uint32(b)
	if v>>28 != 6 || (v>>20)&0xff != 0x28 || v&0xfffff != 0xABCDE {
		t.Fatalf("vtcfl %x", v)
	}
	if !TCPChecksumOK(src6, dst6, b[40:]) {
		t.Fatal("tcp6 checksum")
	}
	var p Packet
	if err := ParseL3(b, false, &p); err != nil {
		t.Fatal(err)
	}
	if !p.V6 || p.Seq != 42 || p.TTL != 3 {
		t.Fatalf("%+v", p)
	}
}

func TestFamilyMismatch(t *testing.T) {
	var buf [128]byte
	tm := tmpl4()
	tm.Dst = dst6
	if _, err := BuildSYN(buf[:], tm, 1, 1, 1); err != ErrFamily {
		t.Fatal("want ErrFamily")
	}
}

// --- test packet generators (also used to build ICMP quotes) ---

func ipv4(src, dst netip.Addr, proto uint8, ttl uint8, ipid uint16, payload []byte) []byte {
	b := make([]byte, 20+len(payload))
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:], uint16(len(b)))
	binary.BigEndian.PutUint16(b[4:], ipid)
	b[8], b[9] = ttl, proto
	s, d := src.As4(), dst.As4()
	copy(b[12:], s[:])
	copy(b[16:], d[:])
	binary.BigEndian.PutUint16(b[10:], Checksum(b[:20]))
	copy(b[20:], payload)
	return b
}

func tcpSeg(src, dst netip.Addr, sp, dp Port, seq, ack uint32, flags uint8) []byte {
	b := make([]byte, 20)
	binary.BigEndian.PutUint16(b[0:], uint16(sp))
	binary.BigEndian.PutUint16(b[2:], uint16(dp))
	binary.BigEndian.PutUint32(b[4:], seq)
	binary.BigEndian.PutUint32(b[8:], ack)
	b[12] = 5 << 4
	b[13] = flags
	var ps uint32
	if src.Is4() {
		s, d := src.As4(), dst.As4()
		ps = sum(d[:], sum(s[:], 0))
	} else {
		s, d := src.As16(), dst.As16()
		ps = sum(d[:], sum(s[:], 0))
	}
	ps += 6 + 20
	binary.BigEndian.PutUint16(b[16:], ^fold(sum(b, ps)))
	return b
}

func icmp4(typ, code uint8, quote []byte, ext []byte, rfc4884 bool) []byte {
	q := append([]byte(nil), quote...)
	if ext != nil {
		for len(q) < 128 {
			q = append(q, 0)
		}
	}
	b := make([]byte, 8, 8+len(q)+len(ext))
	b[0], b[1] = typ, code
	if ext != nil && rfc4884 {
		b[5] = byte(len(q) / 4)
	}
	b = append(b, q...)
	b = append(b, ext...)
	binary.BigEndian.PutUint16(b[2:], Checksum(b))
	return b
}

func mplsExt(labels ...uint32) []byte {
	obj := make([]byte, 4+4*len(labels))
	binary.BigEndian.PutUint16(obj[0:], uint16(len(obj)))
	obj[2], obj[3] = 1, 1
	for i, l := range labels {
		v := l<<12 | 1 /*ttl*/
		if i == len(labels)-1 {
			v |= 0x100
		}
		binary.BigEndian.PutUint32(obj[4+4*i:], v)
	}
	e := append([]byte{0x20, 0, 0, 0}, obj...)
	binary.BigEndian.PutUint16(e[2:], Checksum(e))
	return e
}

func TestICMPTimeExceededQuote(t *testing.T) {
	var buf [128]byte
	n, _ := BuildSYN(buf[:], tmpl4(), 0x01020304, 3, 777)
	router := netip.MustParseAddr("10.0.0.1")
	for _, ql := range []int{20 + 8, n} { // RFC 792 minimum and full quote
		pkt := ipv4(router, src4, 1, 250, 5, icmp4(11, 0, buf[:ql], nil, false))
		var p Packet
		if err := ParseL3(pkt, false, &p); err != nil {
			t.Fatal(ql, err)
		}
		if p.Kind != KindICMP || p.ICMPType != 11 || p.Src != router {
			t.Fatalf("%+v", p)
		}
		if p.InnerSrc != src4 || p.InnerDst != dst4 || p.InnerSPort != 20001 || p.InnerDPort != 443 || !p.HasInnerSeq || p.InnerSeq != 0x01020304 || p.InnerIPID != 777 {
			t.Fatalf("quote %+v", p)
		}
	}
	// 4-byte quote: ports only, no seq.
	pkt := ipv4(router, src4, 1, 250, 5, icmp4(11, 0, buf[:24], nil, false))
	var p Packet
	if err := ParseL3(pkt, false, &p); err != nil {
		t.Fatal(err)
	}
	if p.HasInnerSeq {
		t.Fatal("seq must be absent in a 4-byte quote")
	}
	// Quote too short to identify the flow.
	pkt = ipv4(router, src4, 1, 250, 5, icmp4(11, 0, buf[:22], nil, false))
	if err := ParseL3(pkt, false, &p); err == nil {
		t.Fatal("2-byte L4 quote must not parse")
	}
}

func TestICMPMPLS(t *testing.T) {
	var buf [128]byte
	n, _ := BuildSYN(buf[:], tmpl4(), 9, 3, 1)
	router := netip.MustParseAddr("10.0.0.1")
	for _, compliant := range []bool{true, false} {
		pkt := ipv4(router, src4, 1, 250, 5, icmp4(11, 0, buf[:n], mplsExt(16001, 24005), compliant))
		var p Packet
		if err := ParseL3(pkt, false, &p); err != nil {
			t.Fatal(err)
		}
		if p.NMPLS != 2 || p.MPLS[0].Label != 16001 || p.MPLS[1].Label != 24005 || !p.MPLS[1].S {
			t.Fatalf("compliant=%v mpls %+v", compliant, p.MPLS[:p.NMPLS])
		}
		if p.InnerSeq != 9 {
			t.Fatal("seq")
		}
	}
}

func TestICMP6Quote(t *testing.T) {
	var buf [128]byte
	n, _ := BuildSYN(buf[:], tmpl6(), 0xabc, 2, 0)
	router := netip.MustParseAddr("2001:db8:ff::1")
	ic := make([]byte, 8+n)
	ic[0] = ICMP6TimeExceed
	copy(ic[8:], buf[:n])
	pkt := make([]byte, 40+len(ic))
	binary.BigEndian.PutUint32(pkt, 6<<28)
	binary.BigEndian.PutUint16(pkt[4:], uint16(len(ic)))
	pkt[6], pkt[7] = 58, 60
	r, s := router.As16(), src6.As16()
	copy(pkt[8:], r[:])
	copy(pkt[24:], s[:])
	ps := sum(s[:], sum(r[:], 0)) + uint32(len(ic)) + 58
	binary.BigEndian.PutUint16(ic[2:], ^fold(sum(ic, ps)))
	copy(pkt[40:], ic)
	var p Packet
	if err := ParseL3(pkt, false, &p); err != nil {
		t.Fatal(err)
	}
	if p.Kind != KindICMP || p.InnerFlowLabel != 0xABCDE || p.InnerSeq != 0xabc || p.InnerSPort != 20002 {
		t.Fatalf("%+v", p)
	}
	// corrupt checksum
	pkt[50] ^= 0xff
	if err := ParseL3(pkt, false, &p); err != ErrChecksum {
		t.Fatalf("want checksum error, got %v", err)
	}
}

func TestIPv6ExtHeaders(t *testing.T) {
	seg := tcpSeg(dst6, src6, 443, 20001, 1, 2, SYN|ACK)
	hbh := []byte{6, 0, 1, 4, 0, 0, 0, 0} // next=TCP, len=0 (8 bytes), PadN
	payload := append(hbh, seg...)
	pkt := make([]byte, 40+len(payload))
	binary.BigEndian.PutUint32(pkt, 6<<28)
	binary.BigEndian.PutUint16(pkt[4:], uint16(len(payload)))
	pkt[6], pkt[7] = 0, 55
	d, s := dst6.As16(), src6.As16()
	copy(pkt[8:], d[:])
	copy(pkt[24:], s[:])
	copy(pkt[40:], payload)
	var p Packet
	if err := ParseL3(pkt, false, &p); err != nil {
		t.Fatal(err)
	}
	if p.Kind != KindTCP || p.Flags != SYN|ACK || p.Ack != 2 {
		t.Fatalf("%+v", p)
	}
	// Non-first fragment is rejected.
	frag := []byte{6, 0, 0, 8, 0, 0, 0, 1}
	payload = append(frag, seg...)
	pkt2 := append(append([]byte(nil), pkt[:40]...), payload...)
	pkt2[6] = 44
	binary.BigEndian.PutUint16(pkt2[4:], uint16(len(payload)))
	if err := ParseL3(pkt2, false, &p); err != ErrFragment {
		t.Fatalf("want fragment, got %v", err)
	}
}

func TestEthernetVLAN(t *testing.T) {
	seg := tcpSeg(dst4, src4, 443, 20001, 100, 5, RST|ACK)
	ip := ipv4(dst4, src4, 6, 60, 1, seg)
	eth := make([]byte, 14, 64)
	binary.BigEndian.PutUint16(eth[12:], 0x8100)
	eth = append(eth, 0, 10, 0x08, 0x00) // VLAN 10, inner ethertype IPv4
	frame := append(eth, ip...)
	var p Packet
	if err := Parse(frame, ParseOpts{Hatype: HatypeEther}, &p); err != nil {
		t.Fatal(err)
	}
	if p.Flags != RST|ACK || p.Ack != 5 || p.Src != dst4 {
		t.Fatalf("%+v", p)
	}
	// Ethernet padding beyond IP total length is ignored.
	frame = append(frame, 0, 0, 0, 0, 0, 0)
	if err := Parse(frame, ParseOpts{Hatype: HatypeEther}, &p); err != nil {
		t.Fatal(err)
	}
}

func TestMalformed(t *testing.T) {
	var p Packet
	seg := tcpSeg(dst4, src4, 443, 20001, 100, 5, SYN|ACK)
	ip := ipv4(dst4, src4, 6, 60, 1, seg)
	// bad TCP checksum detected unless skipped
	ip[20+16] ^= 1
	if err := ParseL3(ip, false, &p); err != ErrChecksum {
		t.Fatal("tcp checksum")
	}
	if err := ParseL3(ip, true, &p); err != nil {
		t.Fatal("skip csum", err)
	}
	// truncated
	if err := ParseL3(ip[:30], true, &p); err == nil {
		t.Fatal("truncated accepted")
	}
	// fragment
	ip2 := ipv4(dst4, src4, 6, 60, 1, seg)
	binary.BigEndian.PutUint16(ip2[6:], 0x2000)
	binary.BigEndian.PutUint16(ip2[10:], 0)
	binary.BigEndian.PutUint16(ip2[10:], Checksum(ip2[:20]))
	if err := ParseL3(ip2, true, &p); err != ErrFragment {
		t.Fatal("fragment", err)
	}
	// bad IP header checksum
	ip2[10] ^= 0xff
	if err := ParseL3(ip2, true, &p); err != ErrChecksum {
		t.Fatal("ip checksum", err)
	}
	// garbage never panics
	for l := 0; l < 80; l++ {
		g := make([]byte, l)
		for i := range g {
			g[i] = byte(i*37 + l)
		}
		if l > 0 {
			g[0] = 0x45
		}
		_ = ParseL3(g, false, &p)
		_ = Parse(g, ParseOpts{Hatype: HatypeEther}, &p)
	}
}

func FuzzParse(f *testing.F) {
	var buf [128]byte
	n, _ := BuildSYN(buf[:], tmpl4(), 1, 1, 1)
	f.Add(append([]byte(nil), buf[:n]...))
	router := netip.MustParseAddr("10.0.0.1")
	f.Add(ipv4(router, src4, 1, 250, 5, icmp4(11, 0, buf[:n], nil, false)))
	f.Add(ipv4(router, src4, 1, 250, 5, icmp4(11, 0, buf[:n], mplsExt(16001, 24005), true)))
	short := icmp4(3, 1, buf[:24], nil, false)
	short[5] = 1 // RFC 4884 length below the quoted header
	binary.BigEndian.PutUint16(short[2:], 0)
	binary.BigEndian.PutUint16(short[2:], Checksum(short))
	f.Add(ipv4(router, src4, 1, 250, 5, short))
	f.Fuzz(func(t *testing.T, b []byte) {
		var p Packet
		_ = ParseL3(b, false, &p)
		_ = Parse(b, ParseOpts{Hatype: HatypeEther}, &p)
	})
}

func BenchmarkBuildSYN4(b *testing.B) {
	var buf [128]byte
	tm := tmpl4()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		BuildSYN(buf[:], tm, uint32(i), 64, uint16(i))
	}
}

func BenchmarkParseICMP(b *testing.B) {
	var buf [128]byte
	n, _ := BuildSYN(buf[:], tmpl4(), 9, 3, 1)
	pkt := ipv4(netip.MustParseAddr("10.0.0.1"), src4, 1, 250, 5, icmp4(11, 0, buf[:n], nil, false))
	var p Packet
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		ParseL3(pkt, false, &p)
	}
}

// TCP options of a reply: the timestamp is found among other options, and a
// malformed option list neither hangs nor invents a timestamp.
func TestParseTSOption(t *testing.T) {
	var buf [128]byte
	n, _ := BuildSYN(buf[:], tmpl4(), 0x01020304, 64, 1)
	b := buf[:n]
	var p Packet
	if err := ParseL3(b, true, &p); err != nil || !p.HasTS || p.TSval != 0x01020304 {
		t.Fatalf("%v %+v", err, p)
	}
	// Malformed: option of length 0 right at the start.
	b[40], b[41] = 5, 0
	if err := ParseL3(b, true, &p); err != nil || p.HasTS {
		t.Fatalf("malformed options: %v hasTS=%v", err, p.HasTS)
	}
}

// A router may put anything into the RFC 4884 length byte: every value must
// parse or be rejected, never panic, and a length that does not even cover the
// quoted IP header is ignored.
func TestICMPLengthByteNeverPanics(t *testing.T) {
	var buf [128]byte
	router := netip.MustParseAddr("10.0.0.1")
	n, _ := BuildSYN(buf[:], tmpl4(), 0x01020304, 3, 777)
	for _, ql := range []int{24, 28, n} {
		for l := 0; l < 256; l++ {
			ic := icmp4(11, 0, buf[:ql], nil, false)
			ic[5] = byte(l)
			binary.BigEndian.PutUint16(ic[2:], 0)
			binary.BigEndian.PutUint16(ic[2:], Checksum(ic))
			var p Packet
			err := ParseL3(ipv4(router, src4, 1, 250, 5, ic), false, &p)
			if l*4 < 24 && (err != nil || p.InnerSPort != 20001) {
				t.Fatalf("quote %d length byte %d: %v %+v", ql, l, err, p)
			}
		}
	}
	router6 := netip.MustParseAddr("2001:db8:ff::1")
	n, _ = BuildSYN(buf[:], tmpl6(), 0xabc, 2, 0)
	for _, ql := range []int{44, 48, n} {
		for l := 0; l < 256; l++ {
			ic := make([]byte, 8+ql)
			ic[0], ic[4] = ICMP6TimeExceed, byte(l)
			copy(ic[8:], buf[:ql])
			pkt := make([]byte, 40+len(ic))
			binary.BigEndian.PutUint32(pkt, 6<<28)
			binary.BigEndian.PutUint16(pkt[4:], uint16(len(ic)))
			pkt[6], pkt[7] = 58, 60
			r, s := router6.As16(), src6.As16()
			copy(pkt[8:], r[:])
			copy(pkt[24:], s[:])
			ps := sum(s[:], sum(r[:], 0)) + uint32(len(ic)) + 58
			binary.BigEndian.PutUint16(ic[2:], ^fold(sum(ic, ps)))
			copy(pkt[40:], ic)
			var p Packet
			err := ParseL3(pkt, false, &p)
			if l*8 < 44 && (err != nil || p.InnerSPort != 20002) {
				t.Fatalf("v6 quote %d length byte %d: %v %+v", ql, l, err, p)
			}
		}
	}
}
