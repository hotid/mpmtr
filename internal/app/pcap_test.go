package app

import (
	"net/netip"
	"testing"

	"github.com/hotid/mpmtr/internal/wire"
)

func TestPcapFilter(t *testing.T) {
	rt := &Runtime{o: &Options{Ports: []wire.Port{20000, 20001, 20255},
		Endpoints: []Endpoint{
			{Addr: netip.MustParseAddr("192.0.2.1"), Port: 443},
			{Addr: netip.MustParseAddr("2001:db8::a"), Port: 80},
		}}}
	want := "(tcp and host 192.0.2.1 and port 443 and portrange 20000-20255) or (icmp and icmp[24:4] = 0xc0000201) or " +
		"(tcp and host 2001:db8::a and port 80 and portrange 20000-20255) or " +
		"(icmp6 and ip6[72:4] = 0x20010db8 and ip6[76:4] = 0x00000000 and ip6[80:4] = 0x00000000 and ip6[84:4] = 0x0000000a)"
	if got := rt.PcapFilter(); got != want {
		t.Fatalf("filter\n got %s\nwant %s", got, want)
	}
}
