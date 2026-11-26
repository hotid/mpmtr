package sys

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"syscall"

	"github.com/hotid/mpmtr/internal/wire"

	"golang.org/x/sys/unix"
)

// Router performs per-flow route lookups through rtnetlink (RTM_GETROUTE)
// with the parameters a real TCP socket of that flow would present:
// destination, optional source, protocol TCP, source/destination ports,
// TOS, fwmark and optional output interface. This is what makes policy
// routing by port and local L4 multipath visible per flow (a UDP connect
// cannot do that).
type Router struct {
	mu    sync.Mutex
	fd    int
	seq   uint32
	Src   netip.Addr // --src
	Oif   int        // --interface
	Mark  uint32     // --fwmark
	TOS   uint8
	cache map[int]int
	buf   []byte
}

// NewRouter opens a netlink route socket.
func NewRouter() (*Router, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return nil, fmt.Errorf("netlink: %w", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		unix.Close(fd)
		return nil, err
	}
	tv := unix.NsecToTimeval(2e9)
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)
	return &Router{fd: fd, cache: map[int]int{}, buf: make([]byte, 1<<16)}, nil
}

// RouteResult of a lookup.
type RouteResult struct {
	Src     netip.Addr
	Oif     int
	Gateway netip.Addr
	Table   uint32
	MTU     int
}

func rta(b []byte, typ uint16, data []byte) []byte {
	l := 4 + len(data)
	h := make([]byte, 4)
	binary.LittleEndian.PutUint16(h[0:], uint16(l))
	binary.LittleEndian.PutUint16(h[2:], typ)
	b = append(b, h...)
	b = append(b, data...)
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	return b
}

func be16(v uint16) []byte { return []byte{byte(v >> 8), byte(v)} }
func le32(v uint32) []byte { b := make([]byte, 4); binary.LittleEndian.PutUint32(b, v); return b }

// Lookup returns the route for one flow.
func (r *Router) Lookup(dst netip.Addr, sport, dport wire.Port) (RouteResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	fam := uint8(unix.AF_INET)
	alen := uint8(32)
	if dst.Is6() && !dst.Is4In6() {
		fam, alen = unix.AF_INET6, 128
	}
	r.seq++
	// nlmsghdr(16) + rtmsg(12) + attrs
	msg := make([]byte, 16+12)
	binary.LittleEndian.PutUint16(msg[4:], unix.RTM_GETROUTE)
	binary.LittleEndian.PutUint16(msg[6:], unix.NLM_F_REQUEST)
	binary.LittleEndian.PutUint32(msg[8:], r.seq)
	rt := msg[16:]
	rt[0] = fam
	rt[1] = alen // dst_len
	if r.Src.IsValid() {
		rt[2] = alen
	}
	rt[3] = r.TOS
	msg = rta(msg, unix.RTA_DST, dst.AsSlice())
	if r.Src.IsValid() {
		msg = rta(msg, unix.RTA_SRC, r.Src.AsSlice())
	}
	if r.Oif > 0 {
		msg = rta(msg, unix.RTA_OIF, le32(uint32(r.Oif)))
	}
	if r.Mark != 0 {
		msg = rta(msg, unix.RTA_MARK, le32(r.Mark))
	}
	msg = rta(msg, unix.RTA_UID, le32(uint32(unix.Getuid())))
	msg = rta(msg, unix.RTA_IP_PROTO, []byte{unix.IPPROTO_TCP})
	msg = rta(msg, unix.RTA_SPORT, be16(uint16(sport)))
	msg = rta(msg, unix.RTA_DPORT, be16(uint16(dport)))
	binary.LittleEndian.PutUint32(msg[0:], uint32(len(msg)))
	if err := unix.Sendto(r.fd, msg, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return RouteResult{}, err
	}
	for {
		n, _, err := unix.Recvfrom(r.fd, r.buf, 0)
		if err != nil {
			if errors.Is(err, syscall.EINTR) {
				continue
			}
			return RouteResult{}, fmt.Errorf("netlink recv: %w", err)
		}
		b := r.buf[:n]
		for len(b) >= 16 {
			l := int(binary.LittleEndian.Uint32(b[0:]))
			typ := binary.LittleEndian.Uint16(b[4:])
			seq := binary.LittleEndian.Uint32(b[8:])
			if l < 16 || l > len(b) {
				return RouteResult{}, errors.New("netlink: malformed")
			}
			body := b[16:l]
			b = b[(l+3)&^3:]
			if seq != r.seq {
				continue
			}
			switch typ {
			case unix.NLMSG_ERROR:
				if len(body) >= 4 {
					if e := int32(binary.LittleEndian.Uint32(body)); e != 0 {
						return RouteResult{}, fmt.Errorf("route lookup %s: %w", dst, syscall.Errno(-e))
					}
				}
			case unix.RTM_NEWROUTE:
				return r.parse(body, fam)
			}
		}
	}
}

func (r *Router) parse(body []byte, fam uint8) (RouteResult, error) {
	var res RouteResult
	if len(body) < 12 {
		return res, errors.New("netlink: short rtmsg")
	}
	rtype := body[7]
	switch rtype {
	case unix.RTN_UNICAST, unix.RTN_LOCAL:
	case unix.RTN_UNREACHABLE, unix.RTN_PROHIBIT, unix.RTN_BLACKHOLE:
		return res, fmt.Errorf("route type %d (unreachable/prohibit/blackhole)", rtype)
	}
	a := body[12:]
	for len(a) >= 4 {
		l := int(binary.LittleEndian.Uint16(a[0:]))
		t := binary.LittleEndian.Uint16(a[2:])
		if l < 4 || l > len(a) {
			break
		}
		d := a[4:l]
		switch t {
		case unix.RTA_PREFSRC:
			res.Src, _ = netip.AddrFromSlice(d)
		case unix.RTA_OIF:
			if len(d) >= 4 {
				res.Oif = int(binary.LittleEndian.Uint32(d))
			}
		case unix.RTA_GATEWAY:
			res.Gateway, _ = netip.AddrFromSlice(d)
		case unix.RTA_TABLE:
			if len(d) >= 4 {
				res.Table = binary.LittleEndian.Uint32(d)
			}
		case unix.RTA_SRC:
			if !res.Src.IsValid() {
				res.Src, _ = netip.AddrFromSlice(d)
			}
		}
		a = a[(l+3)&^3:]
	}
	if r.Src.IsValid() {
		res.Src = r.Src
	}
	if !res.Src.IsValid() {
		return res, errors.New("route lookup returned no source address")
	}
	res.Src = res.Src.Unmap()
	if res.Oif > 0 {
		if mtu, ok := r.cache[res.Oif]; ok {
			res.MTU = mtu
		} else if ifc, err := net.InterfaceByIndex(res.Oif); err == nil {
			res.MTU = ifc.MTU
			r.cache[res.Oif] = ifc.MTU
		}
	}
	return res, nil
}

// Close closes the socket.
func (r *Router) Close() { unix.Close(r.fd) }

// WatchChanges subscribes to link/address/route/rule notifications and
// signals ch (non-blocking) on each batch. It returns when the socket
// fails; call stop() to end it.
func WatchChanges(ch chan<- struct{}) (stop func(), err error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return nil, err
	}
	groups := uint32(unix.RTMGRP_LINK | unix.RTMGRP_IPV4_IFADDR | unix.RTMGRP_IPV4_ROUTE |
		unix.RTMGRP_IPV6_IFADDR | unix.RTMGRP_IPV6_ROUTE | 0x80 /* RTMGRP_IPV4_RULE */)
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Groups: groups}); err != nil {
		unix.Close(fd)
		return nil, err
	}
	_ = unix.SetsockoptInt(fd, unix.SOL_NETLINK, unix.NETLINK_ADD_MEMBERSHIP, unix.RTNLGRP_IPV6_RULE)
	tv := unix.NsecToTimeval(2e8)
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)
	var mu sync.Mutex
	stopped := false
	go func() {
		buf := make([]byte, 1<<16)
		for {
			mu.Lock()
			s := stopped
			mu.Unlock()
			if s {
				unix.Close(fd)
				return
			}
			n, _, err := unix.Recvfrom(fd, buf, 0)
			if err != nil {
				continue
			}
			if n > 0 {
				select {
				case ch <- struct{}{}:
				default:
				}
			}
		}
	}()
	return func() { mu.Lock(); stopped = true; mu.Unlock() }, nil
}

// Nexthop of a matched FIB entry.
type Nexthop struct {
	Oif     int
	Gateway netip.Addr
}

// FIBNexthops returns the nexthops of the FIB entry matching dst
// (RTM_F_FIB_MATCH). More than one means a local multipath route. ok=false
// when the kernel answered with a nexthop object id that is not expanded.
func (r *Router) FIBNexthops(dst netip.Addr) (nhs []Nexthop, ok bool, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	fam := uint8(unix.AF_INET)
	alen := uint8(32)
	if dst.Is6() && !dst.Is4In6() {
		fam, alen = unix.AF_INET6, 128
	}
	r.seq++
	msg := make([]byte, 16+12)
	binary.LittleEndian.PutUint16(msg[4:], unix.RTM_GETROUTE)
	binary.LittleEndian.PutUint16(msg[6:], unix.NLM_F_REQUEST)
	binary.LittleEndian.PutUint32(msg[8:], r.seq)
	rt := msg[16:]
	rt[0], rt[1], rt[3] = fam, alen, r.TOS
	binary.LittleEndian.PutUint32(rt[8:], 0x2000) // RTM_F_FIB_MATCH
	msg = rta(msg, unix.RTA_DST, dst.AsSlice())
	if r.Mark != 0 {
		msg = rta(msg, unix.RTA_MARK, le32(r.Mark))
	}
	binary.LittleEndian.PutUint32(msg[0:], uint32(len(msg)))
	if err := unix.Sendto(r.fd, msg, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, false, err
	}
	for {
		n, _, err := unix.Recvfrom(r.fd, r.buf, 0)
		if err != nil {
			if errors.Is(err, syscall.EINTR) {
				continue
			}
			return nil, false, err
		}
		b := r.buf[:n]
		for len(b) >= 16 {
			l := int(binary.LittleEndian.Uint32(b[0:]))
			typ := binary.LittleEndian.Uint16(b[4:])
			seq := binary.LittleEndian.Uint32(b[8:])
			if l < 16 || l > len(b) {
				return nil, false, errors.New("netlink: malformed")
			}
			body := b[16:l]
			b = b[(l+3)&^3:]
			if seq != r.seq {
				continue
			}
			switch typ {
			case unix.NLMSG_ERROR:
				if len(body) >= 4 {
					if e := int32(binary.LittleEndian.Uint32(body)); e != 0 {
						return nil, false, syscall.Errno(-e)
					}
				}
			case unix.RTM_NEWROUTE:
				return parseNexthops(body)
			}
		}
	}
}

func parseNexthops(body []byte) ([]Nexthop, bool, error) {
	if len(body) < 12 {
		return nil, false, errors.New("short rtmsg")
	}
	var single Nexthop
	var multi []Nexthop
	nhObj := false
	a := body[12:]
	for len(a) >= 4 {
		l := int(binary.LittleEndian.Uint16(a[0:]))
		t := binary.LittleEndian.Uint16(a[2:])
		if l < 4 || l > len(a) {
			break
		}
		d := a[4:l]
		switch t {
		case unix.RTA_OIF:
			if len(d) >= 4 {
				single.Oif = int(binary.LittleEndian.Uint32(d))
			}
		case unix.RTA_GATEWAY:
			single.Gateway, _ = netip.AddrFromSlice(d)
		case 30: // RTA_NH_ID
			nhObj = true
		case unix.RTA_MULTIPATH:
			for len(d) >= 8 {
				nl := int(binary.LittleEndian.Uint16(d[0:]))
				if nl < 8 || nl > len(d) {
					break
				}
				nh := Nexthop{Oif: int(int32(binary.LittleEndian.Uint32(d[4:])))}
				at := d[8:nl]
				for len(at) >= 4 {
					al := int(binary.LittleEndian.Uint16(at[0:]))
					if al < 4 || al > len(at) {
						break
					}
					if binary.LittleEndian.Uint16(at[2:]) == unix.RTA_GATEWAY {
						nh.Gateway, _ = netip.AddrFromSlice(at[4:al])
					}
					at = at[(al+3)&^3:]
				}
				multi = append(multi, nh)
				d = d[(nl+3)&^3:]
			}
		}
		a = a[(l+3)&^3:]
	}
	if len(multi) > 0 {
		return multi, true, nil
	}
	if nhObj && single.Oif == 0 {
		return nil, false, nil
	}
	return []Nexthop{single}, true, nil
}
