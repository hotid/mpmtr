package sys

import (
	"testing"

	"golang.org/x/sys/unix"
)

// A notification batch and a dropped-notifications error (ENOBUFS) both
// ask for a recheck of the routes; a receive timeout does not.
func TestWatchLoopSignals(t *testing.T) {
	type rx struct {
		n   int
		err error
	}
	for _, tc := range []struct {
		name string
		rx   rx
		want bool
	}{
		{"batch", rx{64, nil}, true},
		{"notifications dropped", rx{0, unix.ENOBUFS}, true},
		{"timeout", rx{0, unix.EAGAIN}, false},
		{"interrupted", rx{0, unix.EINTR}, false},
		{"empty", rx{0, nil}, false},
	} {
		ch := make(chan struct{}, 1)
		calls := 0
		watchLoop(func() (int, error) { calls++; return tc.rx.n, tc.rx.err }, ch, func() bool { return calls > 0 })
		got := len(ch) == 1
		if got != tc.want {
			t.Errorf("%s: signalled %v, want %v", tc.name, got, tc.want)
		}
	}
}
