package sys

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/hotid/mpmtr/internal/wire"

	"golang.org/x/sys/unix"
)

// PortRange reads net.ipv4.ip_local_port_range (also used for IPv6).
func PortRange() (lo, hi int, err error) {
	b, err := os.ReadFile("/proc/sys/net/ipv4/ip_local_port_range")
	if err != nil {
		return 0, 0, err
	}
	f := strings.Fields(string(b))
	if len(f) != 2 {
		return 0, 0, fmt.Errorf("unexpected ip_local_port_range %q", b)
	}
	lo, _ = strconv.Atoi(f[0])
	hi, _ = strconv.Atoi(f[1])
	return lo, hi, nil
}

// ReservedPorts parses net.ipv4.ip_local_reserved_ports ("a-b,c").
func ReservedPorts() (map[int]bool, error) {
	b, err := os.ReadFile("/proc/sys/net/ipv4/ip_local_reserved_ports")
	if err != nil {
		return nil, err
	}
	return ParsePortList(strings.TrimSpace(string(b)))
}

// ParsePortList parses "a-b,c,d-e".
func ParsePortList(s string) (map[int]bool, error) {
	out := map[int]bool{}
	if s == "" {
		return out, nil
	}
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		lo, hi := part, part
		if i := strings.IndexByte(part, '-'); i >= 0 {
			lo, hi = part[:i], part[i+1:]
		}
		a, err1 := strconv.Atoi(lo)
		b, err2 := strconv.Atoi(hi)
		if err1 != nil || err2 != nil || a > b || a < 0 || b > 65535 {
			return nil, fmt.Errorf("bad port list element %q", part)
		}
		for p := a; p <= b; p++ {
			out[p] = true
		}
	}
	return out, nil
}

// Socket is one entry from /proc/net/tcp{,6}.
type Socket struct {
	Local netip.Addr
	Port  int
	State int
}

// TCPSockets lists local TCP sockets (any state, incl. TIME_WAIT).
func TCPSockets() []Socket {
	var out []Socket
	for _, f := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		for i, line := range strings.Split(string(b), "\n") {
			fs := strings.Fields(line)
			if i == 0 || len(fs) < 4 {
				continue
			}
			j := strings.LastIndexByte(fs[1], ':')
			if j < 0 {
				continue
			}
			port, err := strconv.ParseUint(fs[1][j+1:], 16, 16)
			if err != nil {
				continue
			}
			st, _ := strconv.ParseUint(fs[3], 16, 8)
			out = append(out, Socket{Local: parseProcAddr(fs[1][:j]), Port: int(port), State: int(st)})
		}
	}
	return out
}

func parseProcAddr(h string) netip.Addr {
	b, err := hex.DecodeString(h)
	if err != nil {
		return netip.Addr{}
	}
	// /proc stores addresses as host-endian 32-bit words.
	for i := 0; i+4 <= len(b); i += 4 {
		b[i], b[i+1], b[i+2], b[i+3] = b[i+3], b[i+2], b[i+1], b[i]
	}
	a, _ := netip.AddrFromSlice(b)
	return a.Unmap()
}

// Reserver keeps a bound-but-not-listening TCP socket per (source IP,
// port). Such a socket owns the bind bucket, so the kernel will not hand
// the port to connect()/autobind and other explicit binds fail, while it
// is not in the listen/established hash: an incoming SYN/ACK for our raw
// SYN still finds no socket and the kernel answers with RST.
type Reserver struct {
	mu   sync.Mutex
	fds  map[netip.AddrPort]int
	warn string // the first SO_REUSEPORT failure
}

// NewReserver creates an empty reserver.
func NewReserver() *Reserver { return &Reserver{fds: map[netip.AddrPort]int{}} }

// ErrPortInUse means another socket holds the port.
var ErrPortInUse = errors.New("source port in use")

// Reserve binds (src, port) once; later calls are no-ops.
func (r *Reserver) Reserve(src netip.Addr, port wire.Port) error {
	k := netip.AddrPortFrom(src, uint16(port))
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.fds[k]; ok {
		return nil
	}
	fam := addrFamily(src)
	fd, err := unix.Socket(fam, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	// SO_REUSEPORT lets mpmtr itself open a real connection from this port
	// (application checks) while the reservation stays; other programs can
	// share it only as the same user AND with SO_REUSEPORT set.
	// Without it the port is still reserved; only those connections fail.
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEPORT, 1); err != nil && r.warn == "" {
		r.warn = fmt.Sprintf("SO_REUSEPORT on reserved source ports: %v (application checks cannot use them)", err)
	}
	var sa unix.Sockaddr
	if fam == unix.AF_INET {
		sa = &unix.SockaddrInet4{Addr: src.As4(), Port: int(port)}
	} else {
		if err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_V6ONLY, 1); err != nil {
			unix.Close(fd)
			return fmt.Errorf("reserve %s: IPV6_V6ONLY: %w", k, err)
		}
		sa = &unix.SockaddrInet6{Addr: src.As16(), Port: int(port)}
	}
	if err := unix.Bind(fd, sa); err != nil {
		unix.Close(fd)
		if errors.Is(err, unix.EADDRINUSE) {
			return fmt.Errorf("%w: %s", ErrPortInUse, k)
		}
		return fmt.Errorf("reserve %s: %w", k, err)
	}
	r.fds[k] = fd
	return nil
}

// Warning returns why reserved ports cannot be shared with mpmtr's own
// connections, or "".
func (r *Reserver) Warning() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.warn
}

// Count returns the number of held reservations.
func (r *Reserver) Count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.fds)
}

// Close releases all reservations.
func (r *Reserver) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for k, fd := range r.fds {
		unix.Close(fd)
		delete(r.fds, k)
	}
}

// RaiseNoFile raises RLIMIT_NOFILE to the hard limit.
func RaiseNoFile() {
	var l unix.Rlimit
	if unix.Getrlimit(unix.RLIMIT_NOFILE, &l) == nil && l.Cur < l.Max {
		l.Cur = l.Max
		_ = unix.Setrlimit(unix.RLIMIT_NOFILE, &l)
	}
}
