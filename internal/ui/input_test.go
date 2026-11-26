package ui

import (
	"bytes"
	"slices"
	"testing"

	"github.com/hotid/mpmtr/internal/core"
)

// Terminal input is cut into keys whatever way the reads split it: several
// keys in one read are all there, a sequence cut by the end of a read is
// kept for the next one.
func TestSplitKeys(t *testing.T) {
	for _, tc := range []struct {
		in   string
		keys []string
		rest string
	}{
		{"q", []string{"q"}, ""},
		{"\x1b[B\x1b[B\x1b[B", []string{"\x1b[B", "\x1b[B", "\x1b[B"}, ""},
		{"j\x1b[5~k\x1b[6~", []string{"j", "\x1b[5~", "k", "\x1b[6~"}, ""},
		{"\x1bOA\x1bOB", []string{"\x1b[A", "\x1b[B"}, ""}, // application cursor keys
		{"\x1b[1;5B", []string{"\x1b[1;5B"}, ""},
		{"\r\t-+*", []string{"\r", "\t", "-", "+", "*"}, ""},
		{"\x1b", nil, "\x1b"},            // Esc, or the start of a sequence
		{"d\x1b", []string{"d"}, "\x1b"}, // the same after a key
		{"\x1b[", nil, "\x1b["},          // cut after the bracket
		{"\x1b[5", nil, "\x1b[5"},        // cut before the final byte
		{"\x1bO", nil, "\x1bO"},
		{"\x1bq", []string{"\x1b", "q"}, ""}, // Esc, then q
		{"й\xd0", []string{"й"}, "\xd0"},     // a character cut in the middle
		{"\x0c", []string{"\x0c"}, ""},
	} {
		keys, rest := splitKeys([]byte(tc.in))
		if !slices.Equal(keys, tc.keys) || string(rest) != tc.rest {
			t.Errorf("%q: keys %q rest %q, want %q and %q", tc.in, keys, rest, tc.keys, tc.rest)
		}
	}
	// a sequence delivered in two reads
	keys, rest := splitKeys([]byte("\x1b"))
	keys2, rest2 := splitKeys(append(rest, "[B"...))
	if len(keys) != 0 || !slices.Equal(keys2, []string{"\x1b[B"}) || len(rest2) != 0 {
		t.Errorf("split arrow: %q %q %q", keys, keys2, rest2)
	}
}

// Only the rows that differ are written, each addressed absolutely; a
// shorter frame erases what is below; an unknown screen is repainted whole.
func TestFrameDiff(t *testing.T) {
	a := []string{"one", "two", "three"}
	if out := frameDiff(a, []string{"one", "two", "three"}); len(out) != 0 {
		t.Errorf("same frame wrote %q", out)
	}
	if out := string(frameDiff(a, []string{"one", "TWO", "three"})); out != "\x1b[2;1HTWO\x1b[K" {
		t.Errorf("one changed row: %q", out)
	}
	if out := string(frameDiff(a, []string{"one", "two", "three", "four"})); out != "\x1b[4;1Hfour\x1b[K" {
		t.Errorf("a longer frame: %q", out)
	}
	if out := string(frameDiff(a, []string{"one"})); out != "\x1b[2;1H\x1b[J" {
		t.Errorf("a shorter frame: %q", out)
	}
	full := frameDiff(nil, a)
	if !bytes.HasPrefix(full, []byte("\x1b[H\x1b[2J")) || !bytes.Contains(full, []byte("\x1b[3;1Hthree\x1b[K")) {
		t.Errorf("repaint: %q", full)
	}
	// nothing beyond cursor position, erase line and erase below
	for _, out := range [][]byte{full, frameDiff(a, []string{"x"}), frameDiff(a, []string{"one", "2", "3", "4"})} {
		for i := 0; i < len(out); i++ {
			if out[i] != 0x1b {
				continue
			}
			j := i + 2
			for out[j] < 0x40 || out[j] > 0x7e {
				j++
			}
			if !bytes.ContainsRune([]byte("HJK"), rune(out[j])) {
				t.Errorf("sequence %q used", out[i:j+1])
			}
		}
	}
}

// Moving the selection, folding and switching between tree and flow table
// redraw the last snapshot; only a reset, another endpoint and the
// single-flow view (whose hops are built on demand) need fresh data.
func TestNeedsSnapshot(t *testing.T) {
	for _, tc := range []struct {
		name  string
		key   string
		ep0   core.EndpointID
		view0 int
		ep    core.EndpointID
		vw    int
		want  bool
	}{
		{"arrow", "\x1b[B", 0, viewTree, 0, viewTree, false},
		{"fold", "-", 0, viewTree, 0, viewTree, false},
		{"sort", "s", 0, viewFlows, 0, viewFlows, false},
		{"tree to flows", "d", 0, viewTree, 0, viewFlows, false},
		{"flow back to flows", "\r", 0, viewFlow, 0, viewFlows, false},
		{"another flow in the flow view", "\x1b[B", 0, viewFlow, 0, viewFlow, false},
		{"reset", "r", 0, viewTree, 0, viewTree, true},
		{"next endpoint", "\t", 0, viewTree, 1, viewTree, true},
		{"open a flow", "\r", 0, viewFlows, 0, viewFlow, true},
		{"open a flow from the tree", "\r", 0, viewTree, 0, viewFlow, true},
	} {
		if got := needsSnapshot(tc.key, tc.ep0, tc.view0, tc.ep, tc.vw); got != tc.want {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
	}
}
