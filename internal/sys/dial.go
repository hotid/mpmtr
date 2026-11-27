package sys

import (
	"errors"
	"fmt"
	"net/netip"
	"time"
	"unsafe"

	"github.com/hotid/mpmtr/internal/wire"

	"golang.org/x/sys/unix"
)

// DialOpts of a real TCP connection from a reserved source port.
type DialOpts struct {
	Interface string // SO_BINDTODEVICE
	Mark      int    // SO_MARK
	TOS       uint8  // IP_TOS / IPV6_TCLASS, as in the probes
	FlowLabel uint32 // IPv6 flow label (20 bits), as in the probes; 0 = none
}

// Linux flow label manager (linux/in6.h), not in x/sys/unix.
const (
	ipv6FlowlabelMgr = 32  // IPV6_FLOWLABEL_MGR
	ipv6FlowinfoSend = 33  // IPV6_FLOWINFO_SEND
	ipv6FlAGet       = 0   // IPV6_FL_A_GET
	ipv6FlFCreate    = 1   // IPV6_FL_F_CREATE
	ipv6FlSAny       = 255 // IPV6_FL_S_ANY
	flowLabelMask    = 0xFFFFF
	// The lease is held by the socket for as long as it lives; the time
	// asked for only says how long the label lingers after the last socket
	// that uses it is gone. The kernel refuses more than 150 s to a process
	// without CAP_NET_ADMIN, and the least it gives is 6 s.
	flowLabelLeaseSec = 6
)

// in6FlowlabelReq is struct in6_flowlabel_req.
type in6FlowlabelReq struct {
	Dst     [16]byte
	Label   uint32 // network byte order
	Action  uint8
	Share   uint8
	Flags   uint16
	Expires uint16
	Linger  uint16
	_       uint32
}

func htonl(v uint32) uint32 {
	b := [4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
	return *(*uint32)(unsafe.Pointer(&b[0]))
}

// setIdentity6 makes the connection's packets carry the probes' traffic
// class and flow label. A router that balances on the flow label would
// otherwise send the connection another way than the probes of its port:
// the kernel picks a label of its own for every connection.
func setIdentity6(fd int, dst netip.Addr, tos uint8, label uint32) error {
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_TCLASS, int(tos)); err != nil {
		return fmt.Errorf("traffic class: %w", err)
	}
	label &= flowLabelMask
	if label == 0 {
		// The probes carry no label: none here either.
		if err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_AUTOFLOWLABEL, 0); err != nil {
			return fmt.Errorf("flow label off: %w", err)
		}
		return nil
	}
	// A label has to be leased from the kernel before a socket may send it.
	req := in6FlowlabelReq{Dst: dst.As16(), Label: htonl(label), Action: ipv6FlAGet, Share: ipv6FlSAny,
		Flags: ipv6FlFCreate, Expires: flowLabelLeaseSec, Linger: 0}
	if _, _, e := unix.Syscall6(unix.SYS_SETSOCKOPT, uintptr(fd), unix.IPPROTO_IPV6, ipv6FlowlabelMgr,
		uintptr(unsafe.Pointer(&req)), unsafe.Sizeof(req), 0); e != 0 {
		return fmt.Errorf("flow label %#x: %w", label, e)
	}
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, ipv6FlowinfoSend, 1); err != nil {
		return fmt.Errorf("flow label %#x: %w", label, err)
	}
	return nil
}

// connect6 is connect(2) with the flow label in sin6_flowinfo, which
// unix.SockaddrInet6 cannot carry.
func connect6(fd int, dst netip.Addr, dport wire.Port, label uint32) error {
	sa := unix.RawSockaddrInet6{Family: unix.AF_INET6, Flowinfo: htonl(label & flowLabelMask), Addr: dst.As16()}
	p := (*[2]byte)(unsafe.Pointer(&sa.Port))
	p[0], p[1] = byte(dport>>8), byte(dport)
	if _, _, e := unix.Syscall(unix.SYS_CONNECT, uintptr(fd), uintptr(unsafe.Pointer(&sa)), unsafe.Sizeof(sa)); e != 0 {
		return e
	}
	return nil
}

// DialFrom opens a kernel TCP connection src:sport → dst:dport next to the
// port's reservation (SO_REUSEPORT). The socket has SO_LINGER 0, so its last
// close sends RST: no TIME_WAIT, and the server and stateful middleboxes
// drop the connection's state before the next raw probe of the 4-tuple.
// refused: the server answered the SYN with RST. The caller owns fd.
func DialFrom(src netip.Addr, sport wire.Port, dst netip.Addr, dport wire.Port, o DialOpts, timeout time.Duration) (fd int, rtt time.Duration, refused bool, err error) {
	fam := addrFamily(src)
	fd, err = unix.Socket(fam, unix.SOCK_STREAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0)
	if err != nil {
		return -1, 0, false, err
	}
	fail := func(e error) (int, time.Duration, bool, error) {
		unix.Close(fd)
		return -1, 0, false, e
	}
	// The port is held by a reservation (Reserver) that allows sharing.
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEPORT, 1); err != nil {
		return fail(fmt.Errorf("SO_REUSEPORT: %w", err))
	}
	if err := unix.SetsockoptLinger(fd, unix.SOL_SOCKET, unix.SO_LINGER, &unix.Linger{Onoff: 1, Linger: 0}); err != nil {
		return fail(err)
	}
	if o.Interface != "" {
		if err := unix.SetsockoptString(fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, o.Interface); err != nil {
			return fail(err)
		}
	}
	if o.Mark != 0 {
		if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_MARK, o.Mark); err != nil {
			return fail(err)
		}
	}
	var la unix.Sockaddr
	connect := func() error { return unix.Connect(fd, &unix.SockaddrInet4{Addr: dst.As4(), Port: int(dport)}) }
	if fam == unix.AF_INET {
		la = &unix.SockaddrInet4{Addr: src.As4(), Port: int(sport)}
		if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_TOS, int(o.TOS)); err != nil {
			return fail(fmt.Errorf("TOS: %w", err))
		}
	} else {
		if err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_V6ONLY, 1); err != nil {
			return fail(fmt.Errorf("IPV6_V6ONLY: %w", err))
		}
		la = &unix.SockaddrInet6{Addr: src.As16(), Port: int(sport)}
		if err := setIdentity6(fd, dst, o.TOS, o.FlowLabel); err != nil {
			return fail(err)
		}
		connect = func() error { return connect6(fd, dst, dport, o.FlowLabel) }
	}
	if err := unix.Bind(fd, la); err != nil {
		return fail(fmt.Errorf("bind %s: %w", netip.AddrPortFrom(src, uint16(sport)), err))
	}
	start := time.Now()
	if err := connect(); err != nil && !errors.Is(err, unix.EINPROGRESS) {
		if errors.Is(err, unix.ECONNREFUSED) {
			unix.Close(fd)
			return -1, time.Since(start), true, err
		}
		return fail(err)
	}
	deadline := start.Add(timeout)
	for {
		left := time.Until(deadline)
		if left <= 0 {
			return fail(unix.ETIMEDOUT)
		}
		pfd := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLOUT}}
		n, err := unix.Poll(pfd, int(left/time.Millisecond)+1)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return fail(err)
		}
		if n == 0 {
			continue
		}
		break
	}
	rtt = time.Since(start)
	soerr, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ERROR)
	if err != nil {
		return fail(err)
	}
	if soerr != 0 {
		e := unix.Errno(soerr)
		unix.Close(fd)
		return -1, rtt, e == unix.ECONNREFUSED, e
	}
	// back to blocking: the plugin uses it as an ordinary socket
	_ = unix.SetNonblock(fd, false)
	return fd, rtt, false, nil
}
