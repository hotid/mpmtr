package sys

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/hotid/mpmtr/internal/wire"

	"golang.org/x/sys/unix"
)

// A real connection from a reserved port (application checks): connects
// next to the reservation, closes with RST (no TIME_WAIT on the port), and
// the reservation survives; a closed port is reported as refused.
func TestDialFromReservedPort(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Write([]byte("hi"))
			time.Sleep(50 * time.Millisecond)
			c.Close()
		}
	}()
	lo := netip.MustParseAddr("127.0.0.1")
	dport := wire.Port(l.Addr().(*net.TCPAddr).Port)
	r := NewReserver()
	defer r.Close()
	const sport = 23311
	if err := r.Reserve(lo, sport); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		fd, rtt, refused, err := DialFrom(lo, sport, lo, dport, DialOpts{}, time.Second)
		if err != nil || refused || rtt <= 0 {
			t.Fatalf("dial %d: %v refused=%v", i, err, refused)
		}
		var b [2]byte
		if n, _ := unix.Read(fd, b[:]); n != 2 {
			t.Fatalf("read %d", n)
		}
		unix.Close(fd)
		time.Sleep(20 * time.Millisecond)
		for _, s := range TCPSockets() {
			if s.Port == sport && s.State == 6 {
				t.Fatal("TIME_WAIT left on the reserved port")
			}
		}
	}
	// closed port
	c, _ := net.Listen("tcp", "127.0.0.1:0")
	closed := wire.Port(c.Addr().(*net.TCPAddr).Port)
	c.Close()
	if _, _, refused, err := DialFrom(lo, sport, lo, closed, DialOpts{}, time.Second); err == nil || !refused {
		t.Fatalf("closed port: err %v refused %v", err, refused)
	}
	if r.Count() != 1 {
		t.Fatal("reservation lost")
	}
}

// The connection of an application check carries the probes' TOS and IPv6
// flow label: the options are accepted, with a label and without one, and
// the socket reports the traffic class it was given. (That the packets
// really carry them is checked on the wire by the integration tests.)
func TestDialFromIdentity(t *testing.T) {
	var noAddr []string
	defer func() {
		if len(noAddr) > 0 && !t.Failed() {
			t.Skipf("%d of the cases did not run: no listener on %v (IPv6 disabled on this machine?)", len(noAddr), noAddr)
		}
	}()
	for _, tc := range []struct {
		addr string
		o    DialOpts
	}{
		{"127.0.0.1", DialOpts{TOS: 40}},
		{"::1", DialOpts{}},
		{"::1", DialOpts{TOS: 40, FlowLabel: 0x12345}},
		{"::1", DialOpts{FlowLabel: 0xFFFFF}},
	} {
		l, err := net.Listen("tcp", net.JoinHostPort(tc.addr, "0"))
		if err != nil {
			// Not a silent pass: without this address the cases below it
			// check nothing, and the result has to say so.
			noAddr = append(noAddr, tc.addr)
			continue
		}
		go func() {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				c.Close()
			}
		}()
		a := netip.MustParseAddr(tc.addr)
		fd, _, refused, err := DialFrom(a, 0, a, wire.Port(l.Addr().(*net.TCPAddr).Port), tc.o, time.Second)
		l.Close()
		if err != nil || refused {
			t.Errorf("%s %+v: %v refused=%v", tc.addr, tc.o, err, refused)
			continue
		}
		level, opt := unix.IPPROTO_IP, unix.IP_TOS
		if a.Is6() {
			level, opt = unix.IPPROTO_IPV6, unix.IPV6_TCLASS
		}
		if got, err := unix.GetsockoptInt(fd, level, opt); err != nil || got != int(tc.o.TOS) {
			t.Errorf("%s %+v: traffic class %d (err %v)", tc.addr, tc.o, got, err)
		}
		unix.Close(fd)
	}
}
