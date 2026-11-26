// Package plugin is the SDK for mpmtr plugins: application checks (Serve,
// below) and hop information (ServeHops, see hop.go).
//
// A plugin is a separate executable, mpmtr-app-NAME, started by
// `mpmtr --app NAME`. mpmtr opens a real TCP connection to every measured
// server from the very source port its TCP probes use (so a load balancer
// leads it to the same server), hands the connected socket to the plugin,
// and the plugin speaks its protocol over it. A failed check counts as a
// failure of that server.
//
// Wire protocol (if you do not use this package): fd 3 is a unix
// SOCK_SEQPACKET socket; every message is one JSON object in one packet.
//
//	plugin → mpmtr  {"type":"hello","name":"http","version":"1"}
//	mpmtr → plugin  {"type":"check","id":7,"src":"192.0.2.1","sport":20031,
//	                 "dst":"192.0.2.10","dport":443,"server":"S7","timeout_ms":5000}
//	                 + the connected TCP socket (SCM_RIGHTS)
//	plugin → mpmtr  {"type":"result","id":7,"ok":false,"stage":"handshake",
//	                 "error":"eof","ms":12.5}
//
// Checks may arrive concurrently. Close your copy of the socket before you
// answer; mpmtr closes the last copy with RST. Use stderr for diagnostics.
package plugin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// Request describes one check.
type Request struct {
	ID      uint64
	Src     netip.AddrPort
	Dst     netip.AddrPort
	Server  string // mpmtr's name of the server behind the address (anycast), may be ""
	Timeout time.Duration
}

// Result of a check. Stage names where it failed ("tcp", "handshake", ...).
type Result struct {
	OK    bool
	Stage string
	Err   error
}

// Check speaks the protocol over conn (already connected). It must return
// by ctx's deadline.
type Check func(ctx context.Context, conn net.Conn, req Request) Result

type msg struct {
	Type    string  `json:"type"`
	ID      uint64  `json:"id,omitempty"`
	Name    string  `json:"name,omitempty"`
	Version string  `json:"version,omitempty"`
	Src     string  `json:"src,omitempty"`
	SPort   uint16  `json:"sport,omitempty"`
	Dst     string  `json:"dst,omitempty"`
	DPort   uint16  `json:"dport,omitempty"`
	Server  string  `json:"server,omitempty"`
	Timeout int64   `json:"timeout_ms,omitempty"`
	OK      bool    `json:"ok,omitempty"`
	Stage   string  `json:"stage,omitempty"`
	Error   string  `json:"error,omitempty"`
	Ms      float64 `json:"ms,omitempty"`
}

// Serve runs the plugin until mpmtr closes the channel.
func Serve(name, version string, check Check) error {
	const fd = 3
	var wmu sync.Mutex
	send := func(m msg) error {
		b, _ := json.Marshal(m)
		wmu.Lock()
		defer wmu.Unlock()
		return unix.Sendmsg(fd, b, nil, nil, 0)
	}
	if err := send(msg{Type: "hello", Name: name, Version: version}); err != nil {
		return fmt.Errorf("fd 3 is not an mpmtr channel (run me via mpmtr --app): %w", err)
	}
	buf := make([]byte, 64<<10)
	oob := make([]byte, unix.CmsgSpace(4*4))
	for {
		n, oobn, _, _, err := unix.Recvmsg(fd, buf, oob, 0)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil || n == 0 {
			return err
		}
		conn := -1
		if cms, err := unix.ParseSocketControlMessage(oob[:oobn]); err == nil {
			for _, cm := range cms {
				if fds, err := unix.ParseUnixRights(&cm); err == nil && len(fds) > 0 {
					if conn >= 0 {
						unix.Close(conn)
					}
					conn = fds[0]
					for _, x := range fds[1:] {
						unix.Close(x)
					}
				}
			}
		}
		// The socket came with the message: it is closed here when the
		// message is not a check that will use it.
		var m msg
		if json.Unmarshal(buf[:n], &m) != nil || m.Type != "check" {
			if conn >= 0 {
				unix.Close(conn)
			}
			continue
		}
		go func(m msg, conn int) {
			start := time.Now()
			r := run(m, conn, check)
			out := msg{Type: "result", ID: m.ID, OK: r.OK, Stage: r.Stage, Ms: float64(time.Since(start).Microseconds()) / 1000}
			if r.Err != nil {
				out.Error = r.Err.Error()
			}
			send(out)
		}(m, conn)
	}
}

func run(m msg, conn int, check Check) Result {
	if conn < 0 {
		return Result{Stage: "plugin", Err: errors.New("no socket attached")}
	}
	f := os.NewFile(uintptr(conn), "conn")
	c, err := net.FileConn(f) // dups the descriptor
	f.Close()
	if err != nil {
		return Result{Stage: "plugin", Err: err}
	}
	defer c.Close() // our copy closes before the answer; mpmtr closes the last (RST)
	req := Request{ID: m.ID, Server: m.Server, Timeout: time.Duration(m.Timeout) * time.Millisecond}
	if a, err := netip.ParseAddr(m.Src); err == nil {
		req.Src = netip.AddrPortFrom(a, m.SPort)
	}
	if a, err := netip.ParseAddr(m.Dst); err == nil {
		req.Dst = netip.AddrPortFrom(a, m.DPort)
	}
	ctx, cancel := context.WithTimeout(context.Background(), req.Timeout)
	defer cancel()
	if dl, ok := ctx.Deadline(); ok {
		c.SetDeadline(dl)
	}
	return check(ctx, c, req)
}
