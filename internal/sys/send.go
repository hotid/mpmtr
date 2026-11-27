// Package sys contains the Linux-specific I/O: raw IPv4/IPv6 senders,
// the AF_PACKET TPACKET_V3 receiver with a classic BPF filter, rtnetlink
// route lookups and change notifications, and source-port reservation.
// Everything is cgo-free (golang.org/x/sys/unix).
package sys

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/hotid/mpmtr/internal/wire"
)

// ErrPermission is returned when raw sockets cannot be opened.
var ErrPermission = errors.New("raw sockets need CAP_NET_RAW: run as root or `sudo setcap cap_net_raw,cap_net_admin+ep " + exePath() + "`")

// exePath is the file to grant the capabilities to: the binary that runs.
func exePath() string {
	if p, err := os.Executable(); err == nil {
		return p
	}
	return "mpmtr"
}

// SenderOpts configure the raw sockets.
type SenderOpts struct {
	Interface string // SO_BINDTODEVICE
	Mark      int    // SO_MARK (needs CAP_NET_ADMIN)
}

// Sender transmits hand-built SYNs. IPv4 uses IPPROTO_RAW (IP_HDRINCL
// implied), IPv6 uses IPPROTO_RAW which on Linux implies IPV6_HDRINCL, so
// hop limit, traffic class and flow label are exactly as built.
type Sender struct {
	// Warnings lists socket options that could not be set; the sender
	// works without them.
	Warnings []string
	fd4, fd6 int
	buf      [128]byte
	oob4     map[int][]byte
	oob6     map[int][]byte
}

// NewSender opens the raw sockets for the requested families.
func NewSender(v4, v6 bool, o SenderOpts) (*Sender, error) {
	s := &Sender{fd4: -1, fd6: -1, oob4: map[int][]byte{}, oob6: map[int][]byte{}}
	open := func(fam int) (int, error) {
		fd, err := unix.Socket(fam, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.IPPROTO_RAW)
		if err != nil {
			if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
				return -1, ErrPermission
			}
			return -1, fmt.Errorf("raw socket: %w", err)
		}
		if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUF, 4<<20); err != nil {
			s.Warnings = append(s.Warnings, fmt.Sprintf("raw socket SO_SNDBUF: %v (sends may fail with ENOBUFS at high rates)", err))
		}
		if o.Interface != "" {
			if err := unix.SetsockoptString(fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, o.Interface); err != nil {
				unix.Close(fd)
				return -1, fmt.Errorf("SO_BINDTODEVICE %s: %w", o.Interface, err)
			}
		}
		if o.Mark != 0 {
			if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_MARK, o.Mark); err != nil {
				unix.Close(fd)
				return -1, fmt.Errorf("SO_MARK (needs CAP_NET_ADMIN): %w", err)
			}
		}
		return fd, nil
	}
	var err error
	if v4 {
		if s.fd4, err = open(unix.AF_INET); err != nil {
			return nil, err
		}
	}
	if v6 {
		if s.fd6, err = open(unix.AF_INET6); err != nil {
			s.Close()
			return nil, err
		}
		// IPPROTO_RAW implies IPV6_HDRINCL; it is also set explicitly where
		// the option exists (Linux >= 4.5). Where it cannot be set, the
		// header is still sent as built unless the kernel is older still.
		if err := unix.SetsockoptInt(s.fd6, unix.IPPROTO_IPV6, unix.IPV6_HDRINCL, 1); err != nil {
			s.Warnings = append(s.Warnings, fmt.Sprintf("IPV6_HDRINCL: %v (IPv6 probes rely on IPPROTO_RAW implying it)", err))
		}
	}
	return s, nil
}

func (s *Sender) oob(v6 bool, ifindex int) []byte {
	if ifindex <= 0 {
		return nil
	}
	m := s.oob4
	if v6 {
		m = s.oob6
	}
	if b, ok := m[ifindex]; ok {
		return b
	}
	var b []byte
	if v6 {
		b = make([]byte, unix.CmsgSpace(unix.SizeofInet6Pktinfo))
		h := (*unix.Cmsghdr)(unsafe.Pointer(&b[0]))
		h.Level, h.Type = unix.IPPROTO_IPV6, unix.IPV6_PKTINFO
		h.SetLen(unix.CmsgLen(unix.SizeofInet6Pktinfo))
		pi := (*unix.Inet6Pktinfo)(unsafe.Pointer(&b[unix.CmsgLen(0)]))
		pi.Ifindex = uint32(ifindex)
	} else {
		b = make([]byte, unix.CmsgSpace(unix.SizeofInet4Pktinfo))
		h := (*unix.Cmsghdr)(unsafe.Pointer(&b[0]))
		h.Level, h.Type = unix.IPPROTO_IP, unix.IP_PKTINFO
		h.SetLen(unix.CmsgLen(unix.SizeofInet4Pktinfo))
		pi := (*unix.Inet4Pktinfo)(unsafe.Pointer(&b[unix.CmsgLen(0)]))
		pi.Ifindex = int32(ifindex)
	}
	m[ifindex] = b
	return b
}

// Send builds and transmits one SYN with the given seq, TTL and IP ID, on
// the egress interface determined by the flow's route lookup.
func (s *Sender) Send(t *wire.FlowTemplate, ifindex int, seq uint32, ttl uint8, ipid uint16) error {
	n, err := wire.BuildSYN(s.buf[:], t, seq, ttl, ipid)
	if err != nil {
		return err
	}
	if t.Dst.Is4() {
		if s.fd4 < 0 {
			return errors.New("IPv4 sender not open")
		}
		sa := &unix.SockaddrInet4{Addr: t.Dst.As4()}
		_, err = unix.SendmsgN(s.fd4, s.buf[:n], s.oob(false, ifindex), sa, 0)
	} else {
		if s.fd6 < 0 {
			return errors.New("IPv6 sender not open")
		}
		sa := &unix.SockaddrInet6{Addr: t.Dst.As16()}
		_, err = unix.SendmsgN(s.fd6, s.buf[:n], s.oob(true, ifindex), sa, 0)
	}
	if err != nil && errors.Is(err, syscall.EINTR) {
		return s.Send(t, ifindex, seq, ttl, ipid)
	}
	return err
}

// Close closes the sockets.
func (s *Sender) Close() {
	if s.fd4 >= 0 {
		unix.Close(s.fd4)
	}
	if s.fd6 >= 0 {
		unix.Close(s.fd6)
	}
}

func addrFamily(a netip.Addr) int {
	if a.Is4() {
		return unix.AF_INET
	}
	return unix.AF_INET6
}
