package sys

import (
	"errors"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// The holder of a block answers any number of PID lookups: its backlog never
// fills, so a later start is told "busy" and does not block in connect.
func TestPortBlockLockManyLookups(t *testing.T) {
	l, err := LockPortBlock(61011, 61012)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 200; i++ {
			_, err := LockPortBlock(61011, 61012)
			var bb *ErrBlockBusy
			if !errors.As(err, &bb) || bb.PID != int32(os.Getpid()) {
				t.Errorf("lookup %d: %v", i, err)
				return
			}
		}
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("PID lookups hang")
	}
	rel := make(chan struct{})
	go func() { l.Release(); close(rel) }()
	select {
	case <-rel:
	case <-time.After(5 * time.Second):
		t.Fatal("Release hangs")
	}
	if l2, err := LockPortBlock(61011, 61012); err != nil {
		t.Fatalf("block not freed: %v", err)
	} else {
		l2.Release()
	}
}

// A holder that never accepts (a stopped process) must not hang
// startup: busy is reported, the PID may be unknown.
func TestPortBlockLockStuckHolder(t *testing.T) {
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrUnix{Name: granuleName(61021 / granule)}); err != nil {
		t.Fatal(err)
	}
	if err := unix.Listen(fd, 0); err != nil {
		t.Fatal(err)
	}
	done := make(chan error)
	go func() {
		for i := 0; i < 3; i++ {
			if _, err := LockPortBlock(61021, 61022); err == nil || !errors.As(err, new(*ErrBlockBusy)) {
				done <- err
				return
			}
		}
		done <- nil
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("startup hangs on a holder that does not accept")
	}
}

// Overlapping claims of different sizes collide (granules), adjacent ones
// do not.
func TestPortBlockLockOverlap(t *testing.T) {
	a, err := LockPortBlock(41000, 41255)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Release()
	if _, err := LockPortBlock(40990, 42013); err == nil {
		t.Fatal("overlapping bigger range was granted")
	}
	b, err := LockPortBlock(41264, 41519)
	if err != nil {
		t.Fatalf("adjacent range refused: %v", err)
	}
	b.Release()
}
