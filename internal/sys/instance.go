package sys

import (
	"errors"
	"fmt"
	"net"
	"syscall"
	"time"

	"github.com/hotid/mpmtr/internal/wire"

	"golang.org/x/sys/unix"
)

// PortBlockLock claims source ports for this mpmtr instance. The port space
// is cut into aligned granules of 16 ports; every granule intersecting the
// claimed range is held by a listening abstract unix socket
// "@mpmtr/ports16/<n>". Abstract sockets leave no files, vanish when the
// process exits and are scoped to the network namespace — exactly like the
// TCP ports they protect. Granules make overlapping claims of different
// sizes collide (20000-20255 vs 20000-21023). Bound-only reservation
// sockets of another instance are invisible in /proc/net/tcp, so without
// this a second instance would silently lose ports.
type PortBlockLock struct{ ls []*net.UnixListener }

// ErrBlockBusy means another mpmtr instance holds part of the range.
type ErrBlockBusy struct {
	Lo, Hi wire.Port
	PID    int32
}

func (e *ErrBlockBusy) Error() string {
	if e.PID > 0 {
		return fmt.Sprintf("source ports %d-%d are used by another mpmtr instance (pid %d)", e.Lo, e.Hi, e.PID)
	}
	return fmt.Sprintf("source ports %d-%d are used by another mpmtr instance", e.Lo, e.Hi)
}

const granule = 16

func granuleName(n int) string { return fmt.Sprintf("@mpmtr/ports16/%d", n) }

// LockPortBlock claims [lo, hi]: all granules or none.
func LockPortBlock(lo, hi wire.Port) (*PortBlockLock, error) {
	l := &PortBlockLock{}
	for n := int(lo) / granule; n <= int(hi)/granule; n++ {
		ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: granuleName(n), Net: "unix"})
		if err != nil {
			l.Release()
			if errors.Is(err, syscall.EADDRINUSE) {
				return nil, &ErrBlockBusy{Lo: lo, Hi: hi, PID: peerPID(granuleName(n))}
			}
			return nil, err
		}
		l.ls = append(l.ls, ln)
		// Accept and drop peers (they only read our credentials), so the
		// backlog never fills up. Netpoller-based: no thread per granule.
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				c.Close()
			}
		}()
	}
	return l, nil
}

// peerPID asks the holder's credentials (SO_PEERCRED) for the message.
// Bounded: a holder that does not accept (a stopped process) must never
// hang our startup; the PID is then unknown.
func peerPID(name string) int32 {
	c, err := net.DialTimeout("unix", name, 200*time.Millisecond)
	if err != nil {
		return 0
	}
	defer c.Close()
	rc, err := c.(*net.UnixConn).SyscallConn()
	if err != nil {
		return 0
	}
	var pid int32
	rc.Control(func(fd uintptr) {
		if cred, err := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED); err == nil {
			pid = cred.Pid
		}
	})
	return pid
}

// Release frees the claim.
func (l *PortBlockLock) Release() {
	if l == nil {
		return
	}
	for _, ln := range l.ls {
		ln.Close()
	}
	l.ls = nil
}
