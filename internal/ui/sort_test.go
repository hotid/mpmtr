package ui

import (
	"strings"
	"testing"

	"github.com/hotid/mpmtr/internal/core"
	"github.com/hotid/mpmtr/internal/report"
)

func rate(v float64) *float64 { return &v }

// The flow table sorts by any of its columns; left and right move to the
// neighbouring one, the selected flow stays selected, and the header marks
// the column.
func TestSortColumns(t *testing.T) {
	e := core.EPSnap{Flows: []core.FlowSnap{
		{Name: "F1", SPort: 20003, State: core.FOK, Executed: 10, RTT: core.RTTSnap{Median: 300, Max: 900}, W5: core.WinSnap{Valid: 10, FailureRate: rate(0)}},
		{Name: "F2", SPort: 20001, State: core.FLoss, Executed: 30, RTT: core.RTTSnap{Median: 100, Max: 950}, W5: core.WinSnap{Valid: 30, Timeout: 6, FailureRate: rate(0.2)}},
		{Name: "F3", SPort: 20002, State: core.FDown, Executed: 20, RTT: core.RTTSnap{Median: 200, Max: 100}, W5: core.WinSnap{Valid: 20, Timeout: 20, FailureRate: rate(1)}},
	}}
	order := func(u *UI) string {
		var n []string
		for _, f := range u.sorted(e) {
			n = append(n, f.Name)
		}
		return strings.Join(n, " ")
	}
	col := func(name string) int {
		for i, c := range sortCols {
			if c.name == name {
				return i
			}
		}
		t.Fatalf("no column %s", name)
		return 0
	}
	for name, want := range map[string]string{"SPORT": "F2 F3 F1", "STATE": "F3 F2 F1", "EXEC": "F2 F3 F1", "TMO": "F3 F2 F1",
		"FAIL5m": "F3 F2 F1", "MED": "F1 F3 F2", "MAX": "F2 F1 F3"} {
		if got := order(&UI{sortBy: col(name)}); got != want {
			t.Errorf("by %s: %s, want %s", name, got, want)
		}
	}
	// every sortable column is a word of the table's header
	for _, c := range sortCols {
		if strings.Count(report.FlowHeader, c.name) != 1 {
			t.Errorf("column %q is not a unique word of the header", c.name)
		}
	}

	u := &UI{view: viewFlows, last: &core.Snapshot{Endpoints: []core.EPSnap{e}}, folded: map[string]bool{}, backTo: -1}
	u.focusFor = 0 // no focus to sync: the core is not touched
	u.sel = 2      // F1, by source port
	u.key([]byte("\x1b[C"))
	if sortCols[u.sortBy].name != "STATE" || u.sorted(e)[u.sel].Name != "F1" {
		t.Errorf("right: column %s, selected %s", sortCols[u.sortBy].name, u.sorted(e)[u.sel].Name)
	}
	u.key([]byte("\x1b[D"))
	u.key([]byte("\x1b[D"))
	if sortCols[u.sortBy].name != "JIT" || u.sorted(e)[u.sel].Name != "F1" {
		t.Errorf("left twice wraps to the last column: %s, selected %s", sortCols[u.sortBy].name, u.sorted(e)[u.sel].Name)
	}
	// in the tree the arrows left and right do nothing
	u.view, u.sortBy = viewTree, 0
	u.key([]byte("\x1b[C"))
	if u.sortBy != 0 {
		t.Error("right arrow sorted outside the flow table")
	}
}

func TestKeyHints(t *testing.T) {
	got := keyHints("[q]uit ↑↓ Enter [-]/[+] all [?]help")
	for _, k := range []string{"q", "-", "+", "?"} {
		if !strings.Contains(got, "[\x1b[0;1m"+k+"\x1b[0;2m]") {
			t.Errorf("key %s not bright in %q", k, got)
		}
	}
	plain := strings.NewReplacer("\x1b[0;1m", "", "\x1b[0;2m", "", "\x1b[2m", "", "\x1b[0m", "").Replace(got)
	if plain != "[q]uit ↑↓ Enter [-]/[+] all [?]help" {
		t.Errorf("text changed: %q", plain)
	}
}

// Esc in the single-flow view goes back to where the flow was opened from:
// the flow table when it was chosen there (or reached with d), the tree
// when it was opened from a DST row.
func TestEscFromFlow(t *testing.T) {
	e := core.EPSnap{Flows: []core.FlowSnap{{Name: "F1", SPort: 20001}, {Name: "F2", SPort: 20002}}}
	u := &UI{view: viewFlows, last: &core.Snapshot{Endpoints: []core.EPSnap{e}}, folded: map[string]bool{}, backTo: -1}
	u.key([]byte("\r"))
	if u.view != viewFlow {
		t.Fatalf("Enter in the table: view %s", viewNames[u.view])
	}
	u.key([]byte("\x1b"))
	if u.view != viewFlows {
		t.Errorf("Esc: view %s, want flows", viewNames[u.view])
	}
	u.key([]byte("\r"))
	u.key([]byte("\r"))
	if u.view != viewFlows {
		t.Errorf("Enter twice: view %s, want flows", viewNames[u.view])
	}
	u.view, u.backTo = viewFlow, -1 // as after d
	u.key([]byte("\x1b"))
	if u.view != viewFlows {
		t.Errorf("Esc after d: view %s, want flows", viewNames[u.view])
	}
	u.view, u.backTo = viewFlow, viewTree // opened from a DST row
	u.key([]byte("\x1b"))
	if u.view != viewTree || u.backTo != -1 {
		t.Errorf("Esc after a DST row: view %s", viewNames[u.view])
	}
	// with the help open Esc only closes the help
	u.view, u.help = viewFlow, true
	u.key([]byte("\x1b"))
	if u.view != viewFlow || u.help {
		t.Errorf("Esc with the help open: view %s help %v", viewNames[u.view], u.help)
	}
}
