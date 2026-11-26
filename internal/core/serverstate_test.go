package core

import "testing"

// A server's state follows its measured ports the way a route's does: a
// port still warming up does not turn a healthy server UNKNOWN.
func TestServerWord(t *testing.T) {
	for _, c := range []struct {
		ok, loss, down, warm, n int
		want                    RowState
	}{
		{0, 0, 0, 0, 0, RowNotMeasured},
		{30, 0, 0, 0, 30, RowOK},
		{30, 0, 0, 1, 31, RowOK}, // one newly added port
		{0, 0, 0, 3, 3, RowWarmup},
		{2, 0, 0, 1, 4, RowUnknown}, // one port unknown for another reason
		{0, 0, 0, 0, 2, RowUnknown},
		{5, 1, 0, 0, 6, RowLoss},
		{5, 0, 1, 2, 8, RowLoss},
		{0, 0, 4, 0, 4, RowDown},
	} {
		if got := serverWord(c.ok, c.loss, c.down, c.warm, c.n); got != c.want {
			t.Errorf("ok %d loss %d down %d warm %d of %d: %s, want %s", c.ok, c.loss, c.down, c.warm, c.n, got, c.want)
		}
	}
}
