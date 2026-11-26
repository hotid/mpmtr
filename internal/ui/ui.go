// Package ui is the interactive terminal UI: plain ANSI escape sequences and
// golang.org/x/term raw mode, no TUI framework. Measurements continue on the
// core goroutine regardless of what the UI does.
package ui

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/hotid/mpmtr/internal/wire"

	"golang.org/x/term"

	"github.com/hotid/mpmtr/internal/app"
	"github.com/hotid/mpmtr/internal/core"
	"github.com/hotid/mpmtr/internal/report"
)

const (
	viewTree    = iota
	viewServers // --anycast: the servers behind the address
	viewFlows
	viewFlow
	numViews
)

var viewNames = []string{"tree", "servers", "flows", "flow"}

// sortCols are the columns of the flow table that it can be sorted by, in
// screen order, named as in its header. Numbers sort largest first; ties
// keep source-port order.
var sortCols = []struct {
	name string
	less func(a, b core.FlowSnap, rn map[string]string) bool
}{
	{"SPORT", func(a, b core.FlowSnap, _ map[string]string) bool { return a.SPort < b.SPort }},
	{"STATE", func(a, b core.FlowSnap, _ map[string]string) bool {
		if x, y := report.SeverityRank(a.State), report.SeverityRank(b.State); x != y {
			return x < y
		}
		return failRate(a) > failRate(b)
	}},
	{"ROUTE", func(a, b core.FlowSnap, rn map[string]string) bool {
		x, y := rn[a.Group], rn[b.Group]
		if (x == "") != (y == "") {
			return y == "" // ports without a route last
		}
		if len(x) != len(y) {
			return len(x) < len(y) // A … Z, then AA …
		}
		return x < y
	}},
	{"EXEC", func(a, b core.FlowSnap, _ map[string]string) bool { return a.Executed > b.Executed }},
	{"VALID", func(a, b core.FlowSnap, _ map[string]string) bool { return a.W5.Valid > b.W5.Valid }},
	{"TMO", func(a, b core.FlowSnap, _ map[string]string) bool { return a.W5.Timeout > b.W5.Timeout }},
	{"UNR", func(a, b core.FlowSnap, _ map[string]string) bool { return a.W5.Unreach > b.W5.Unreach }},
	{"FAIL5m", func(a, b core.FlowSnap, _ map[string]string) bool { return failRate(a) > failRate(b) }},
	{"LAST", func(a, b core.FlowSnap, _ map[string]string) bool { return a.RTT.Last > b.RTT.Last }},
	{"MIN", func(a, b core.FlowSnap, _ map[string]string) bool { return a.RTT.Min > b.RTT.Min }},
	{"MED", func(a, b core.FlowSnap, _ map[string]string) bool { return a.RTT.Median > b.RTT.Median }},
	{"P95", func(a, b core.FlowSnap, _ map[string]string) bool { return a.RTT.P95 > b.RTT.P95 }},
	{"MAX", func(a, b core.FlowSnap, _ map[string]string) bool { return a.RTT.Max > b.RTT.Max }},
	{"JIT", func(a, b core.FlowSnap, _ map[string]string) bool { return a.RTT.Jitter > b.RTT.Jitter }},
}

func failRate(f core.FlowSnap) float64 {
	if f.W5.FailureRate == nil {
		return -1
	}
	return *f.W5.FailureRate
}

// keyHints renders "[q]uit [p]ause …" dim with the keys themselves bright.
func keyHints(s string) string {
	var b strings.Builder
	b.WriteString("\x1b[2m")
	for i := 0; i < len(s); i++ {
		if j := strings.IndexByte(s[i:], ']'); s[i] == '[' && j > 1 && j <= 4 {
			b.WriteString("[\x1b[0;1m" + s[i+1:i+j] + "\x1b[0;2m]")
			i += j
			continue
		}
		b.WriteByte(s[i])
	}
	b.WriteString("\x1b[0m")
	return b.String()
}

// UI state.
type UI struct {
	rt      *app.Runtime
	out     *os.File
	shown   []string // the lines on the terminal now (nil: unknown, repaint all)
	shownW  int      // and the terminal size they were drawn for
	shownH  int
	view    int
	ep      core.EndpointID
	sel     int
	sortBy  int
	paused  bool
	help    bool
	last    *core.Snapshot
	msg     string
	msgAt   time.Time
	scroll  int
	selLine int // body line of the selection (-1: none)

	// Route tree folding (keys survive tree rebuilds: row paths are stable).
	folded   map[string]bool
	treeSel  int
	treePath string
	treeVis  []string             // visible row paths, last render
	treeKids []string             // paths of all rows that have children, last render
	treeAll  []string             // paths of all rows, last render
	treeUp   []int                // for each of them, the index of the row it hangs under (-1: the top)
	treeDst  map[string]wire.Port // DST row path -> measured sport of its route
	backTo   int                  // the flow view was opened from this view (Esc returns); -1: none
	focusOn  bool                 // the flow shown in the flow view is traced in full every interval
	focusFor wire.Port            // the port the core was last told to focus on (0: none)
	srvSel   int                  // selected server
	srvLine  int                  // its body line, last render
}

// Run runs the interactive UI until q or ctx is done.
//
// Fresh data is asked of the measuring loop once a second and when a key
// needs what the last snapshot does not hold; the request runs on its own
// goroutine, so a key never waits for the measuring loop. Everything else —
// moving the selection, folding, sorting, switching views — redraws the
// last snapshot. All keys already typed are applied before one redraw.
func Run(ctx context.Context, rt *app.Runtime, out *os.File) error {
	u := &UI{rt: rt, out: out, folded: map[string]bool{}, backTo: -1} // sorted by source port
	in := int(os.Stdin.Fd())
	var old *term.State
	if term.IsTerminal(in) {
		var err error
		if old, err = term.MakeRaw(in); err != nil {
			return err
		}
	}
	restore := func() {
		fmt.Fprint(out, "\x1b[?25h\x1b[?1049l")
		if old != nil {
			term.Restore(in, old)
		}
	}
	defer restore()
	fmt.Fprint(out, "\x1b[?1049h\x1b[?25l\x1b[2J")
	input := make(chan []byte, 64)
	go func() {
		buf := make([]byte, 256)
		for {
			n, err := os.Stdin.Read(buf)
			if err != nil {
				close(input)
				return
			}
			input <- append([]byte(nil), buf[:n]...)
		}
	}()
	snaps := make(chan *core.Snapshot, 1)
	loading := false
	fetch := func() {
		if loading {
			return
		}
		loading = true
		ep, view := u.ep, u.view
		go func() {
			var snap *core.Snapshot
			rt.Do(func(c *core.Core) {
				// The tree is always built: route letters follow it in every view.
				snap = c.Snapshot(core.SnapOpts{Hops: view == viewFlow, Tree: true, Only: ep})
			})
			snaps <- snap
		}()
	}
	draw := func() {
		if u.last != nil {
			u.render(u.last)
		}
	}
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	fetch()
	// apply runs the keys; quit reports q.
	apply := func(keys []string) (quit bool) {
		need := false
		for _, k := range keys {
			if k == "\x0c" { // Ctrl-L: repaint everything
				u.shown = nil
				continue
			}
			ep, view := u.ep, u.view
			if u.key([]byte(k)) {
				return true
			}
			need = need || needsSnapshot(k, ep, view, u.ep, u.view)
		}
		if need {
			fetch()
		}
		draw()
		return false
	}
	// pend is an escape sequence cut by the end of a read. A lone ESC may
	// be the Esc key or the start of an arrow that the network delivered
	// in two pieces: it is the Esc key if nothing follows shortly.
	var pend []byte
	var escWait <-chan time.Time
	for {
		select {
		case <-escWait:
			escWait = nil
			lone := len(pend) == 1
			pend = nil
			if lone && apply([]string{"\x1b"}) {
				return nil
			}
		case <-ctx.Done():
			return nil
		case s := <-snaps:
			loading = false
			u.last = s
			draw()
		case <-tick.C:
			if u.paused {
				draw() // the flash message still times out
			} else {
				fetch()
			}
		case b, ok := <-input:
			if !ok {
				<-ctx.Done()
				return nil
			}
			// everything typed so far, then one redraw
			for more := true; more; {
				select {
				case nb, ok := <-input:
					if !ok {
						more = false
						break
					}
					b = append(b, nb...)
				default:
					more = false
				}
			}
			keys, rest := splitKeys(append(pend, b...))
			pend, escWait = rest, nil
			if len(pend) > 0 {
				escWait = time.After(50 * time.Millisecond)
			}
			if apply(keys) {
				return nil
			}
		}
	}
}

// needsSnapshot: the key changed what must be asked of the measuring loop —
// a reset, focus, another endpoint (a snapshot holds one), or the single-flow
// view (its hops are built only for it).
func needsSnapshot(key string, ep0 core.EndpointID, view0 int, ep core.EndpointID, view int) bool {
	return key == "r" || key == "f" || ep != ep0 || (view == viewFlow && view0 != viewFlow)
}

// splitKeys cuts terminal input into keys: an escape sequence (CSI "ESC [
// … final", or SS3 "ESC O x", which is given as the CSI form), a lone ESC,
// or one character. rest is what the input ends in the middle of — a lone
// ESC included, which may be the Esc key or the start of a sequence; the
// caller prepends it to the next read.
func splitKeys(b []byte) (keys []string, rest []byte) {
	for i := 0; i < len(b); {
		if b[i] != 0x1b {
			_, n := utf8.DecodeRune(b[i:])
			if !utf8.FullRune(b[i:]) {
				return keys, b[i:] // a character cut in the middle
			}
			keys = append(keys, string(b[i:i+n]))
			i += n
			continue
		}
		if i+1 >= len(b) {
			return keys, b[i:]
		}
		switch b[i+1] {
		case '[':
			j := i + 2
			for j < len(b) && (b[j] < 0x40 || b[j] > 0x7e) {
				j++
			}
			if j >= len(b) {
				return keys, b[i:]
			}
			keys = append(keys, string(b[i:j+1]))
			i = j + 1
		case 'O':
			if i+2 >= len(b) {
				return keys, b[i:]
			}
			keys = append(keys, "\x1b["+string(b[i+2]))
			i += 3
		default:
			keys = append(keys, "\x1b") // Esc, then whatever follows
			i++
		}
	}
	return keys, nil
}

// frameDiff returns what to write to turn the lines shown on the terminal
// into next: only the rows that differ, each addressed absolutely and
// erased to its end. It uses nothing but cursor position, erase line and
// erase below, which every terminal has. prev == nil repaints everything.
func frameDiff(prev, next []string) []byte {
	var b bytes.Buffer
	if prev == nil {
		b.WriteString("\x1b[H\x1b[2J")
	}
	for i, l := range next {
		if prev != nil && i < len(prev) && prev[i] == l {
			continue
		}
		fmt.Fprintf(&b, "\x1b[%d;1H%s\x1b[K", i+1, l)
	}
	if prev != nil && len(next) < len(prev) {
		fmt.Fprintf(&b, "\x1b[%d;1H\x1b[J", len(next)+1)
	}
	return b.Bytes()
}

// openFlow shows the single-flow view of the measured port sp (Enter on a
// route's DST row or a server); Esc returns to the view it came from.
func (u *UI) openFlow(sp wire.Port) {
	if u.last == nil || int(u.ep) >= len(u.last.Endpoints) {
		return
	}
	for i, f := range u.sorted(u.last.Endpoints[u.ep]) {
		if f.SPort == sp && sp != 0 {
			u.sel, u.backTo, u.view = i, u.view, viewFlow
			return
		}
	}
	u.flash("no measured port here yet")
}

// hasServers: the current endpoint has a server list (--anycast).
func (u *UI) hasServers() bool {
	return u.last != nil && int(u.ep) < len(u.last.Endpoints) && u.last.Endpoints[u.ep].Anycast != nil
}

// moveTree moves the tree selection by d visible rows.
func (u *UI) moveTree(d int) {
	if len(u.treeVis) == 0 {
		return
	}
	u.treeSel = min(max(u.treeSel+d, 0), len(u.treeVis)-1)
	u.treePath = u.treeVis[u.treeSel]
}

// syncFocus keeps the core's focus on the flow shown in the flow view while
// focus is on, and takes it off when that view is left.
func (u *UI) syncFocus() {
	if u.view != viewFlow {
		u.focusOn = false
	}
	var want wire.Port
	if u.focusOn && u.last != nil && int(u.ep) < len(u.last.Endpoints) {
		if fl := u.sorted(u.last.Endpoints[u.ep]); u.sel < len(fl) {
			want = fl[u.sel].SPort
		}
	}
	if want == u.focusFor {
		return
	}
	u.focusFor = want
	ep := u.ep
	u.rt.Do(func(c *core.Core) { c.SetFocus(ep, want) })
}

func (u *UI) key(k []byte) (quit bool) {
	defer u.syncFocus()
	s := string(k)
	switch {
	case u.help && s == "\x1b":
		u.help, u.scroll = false, 0
	case u.help && (s == "\x1b[A" || s == "k"):
		u.scroll = max(0, u.scroll-1)
	case u.help && (s == "\x1b[B" || s == "j"):
		u.scroll++
	case u.help && s == "\x1b[5~":
		u.scroll = max(0, u.scroll-10)
	case u.help && s == "\x1b[6~":
		u.scroll += 10
	case s == "f" && u.view == viewFlow:
		u.focusOn = !u.focusOn
		u.flash(map[bool]string{true: "focus: this port is traced in full every interval; hop refresh of the other ports is paused",
			false: "focus off"}[u.focusOn])
	case s == "q" || s == "Q" || s == "\x03":
		return true
	case s == "p":
		u.paused = !u.paused
		u.flash(map[bool]string{true: "screen paused (measurements continue)", false: "resumed"}[u.paused])
	case s == "r":
		u.rt.Do(func(c *core.Core) { c.ResetStats() })
		u.flash("statistics reset: new measurement epoch, warmup restarted")
	case s == "d":
		u.view = (u.view + 1) % numViews
		if u.view == viewServers && !u.hasServers() {
			u.view++
		}
		u.scroll, u.backTo = 0, -1
	case s == "s" || (u.view == viewFlows && (s == "\x1b[C" || s == "\x1b[D")):
		step := 1
		if s == "\x1b[D" {
			step = len(sortCols) - 1
		}
		var keep wire.Port // the selected flow stays selected
		if u.last != nil && int(u.ep) < len(u.last.Endpoints) {
			if fl := u.sorted(u.last.Endpoints[u.ep]); u.sel < len(fl) {
				keep = fl[u.sel].SPort
			}
		}
		u.sortBy = (u.sortBy + step) % len(sortCols)
		if u.last != nil && int(u.ep) < len(u.last.Endpoints) {
			for i, f := range u.sorted(u.last.Endpoints[u.ep]) {
				if f.SPort == keep {
					u.sel = i
				}
			}
		}
		u.flash("sorted by " + sortCols[u.sortBy].name)
	case s == "\t" || s == "n":
		if u.last != nil && len(u.last.Endpoints) > 0 {
			u.ep = (u.ep + 1) % core.EndpointID(len(u.last.Endpoints))
			u.sel = 0
		}
	case s == "\x1b[A" || s == "k":
		switch {
		case u.view == viewTree:
			u.moveTree(-1)
		case u.view == viewServers:
			u.srvSel = max(0, u.srvSel-1)
		case u.sel > 0:
			u.sel--
		}
	case s == "\x1b[B" || s == "j":
		switch u.view {
		case viewTree:
			u.moveTree(1)
		case viewServers:
			u.srvSel++
		default:
			u.sel++
		}
	case s == "\x1b[5~":
		switch u.view {
		case viewTree:
			u.moveTree(-10)
		case viewServers:
			u.srvSel = max(0, u.srvSel-10)
		}
		u.scroll = max(0, u.scroll-10)
		u.sel = max(0, u.sel-10)
	case s == "\x1b[6~":
		switch u.view {
		case viewTree:
			u.moveTree(10)
		case viewServers:
			u.srvSel += 10
		}
		u.scroll += 10
		u.sel += 10
	case u.view == viewTree && (s == "-" || s == "_"):
		for _, p := range u.treeKids {
			u.folded[p] = true
		}
		u.flash("tree folded (Enter opens a node, + opens all)")
	case u.view == viewTree && (s == "+" || s == "="):
		clear(u.folded)
		u.flash("tree unfolded")
	case u.view == viewTree && s == "*":
		u.foldToRoutes()
		u.flash("one line per route (Enter opens a node, + opens all)")
	case u.view == viewTree && (s == "\r" || s == "\n"):
		if slices.Contains(u.treeKids, u.treePath) {
			if u.folded[u.treePath] {
				u.unfoldChain(u.treePath)
			} else {
				u.folded[u.treePath] = true
			}
		} else if sp, ok := u.treeDst[u.treePath]; ok {
			u.openFlow(sp)
		}
	case u.view == viewServers && (s == "\r" || s == "\n"):
		if sv := u.serverList(); u.srvSel < len(sv) && len(sv[u.srvSel].Measured) > 0 {
			u.openFlow(sv[u.srvSel].Measured[0])
		} else {
			u.flash("this server has no measured port")
		}
	case u.view == viewFlow && u.backTo >= 0 && (s == "\x1b" || s == "\r" || s == "\n"):
		u.view, u.backTo = u.backTo, -1
	case s == "\r" || s == "\n":
		if u.view == viewFlows {
			u.view, u.backTo = viewFlow, viewFlows // Esc (or Enter) returns to the table
		} else if u.view == viewFlow {
			u.view = viewFlows
		}
	case s == "?" || s == "h":
		u.help, u.scroll = !u.help, 0
	case s == "\x1b":
		if u.help {
			u.help, u.scroll = false, 0
		} else if u.view == viewFlow {
			u.view = viewFlows // reached with d: the table is where a flow is chosen
		}
	}
	return false
}

func (u *UI) flash(m string) { u.msg, u.msgAt = m, time.Now() }

func (u *UI) sorted(e core.EPSnap) []core.FlowSnap {
	fl := append([]core.FlowSnap(nil), e.Flows...)
	sort.SliceStable(fl, func(i, j int) bool { return fl[i].SPort < fl[j].SPort })
	if less := sortCols[u.sortBy%len(sortCols)].less; u.sortBy != 0 {
		rn := report.RouteNames(e)
		sort.SliceStable(fl, func(i, j int) bool { return less(fl[i], fl[j], rn) })
	}
	return fl
}

// color is the colour of a state word.
func color(s core.RowState) string {
	switch s {
	case core.RowDown:
		return "\x1b[1;31m"
	case core.RowLoss:
		return "\x1b[1;33m"
	case core.RowOK:
		return "\x1b[32m"
	}
	return "\x1b[2m"
}

// flowColor is color for a flow: one whose measurement cannot be trusted
// stands out.
func flowColor(s core.FState) string {
	if s == core.FInvalid {
		return "\x1b[35m"
	}
	return color(s.Row())
}

const reset = "\x1b[0m"

func dashName(s string) string {
	if s == "" {
		return "not known yet"
	}
	return s
}

// dim greys a line out (ICMP rate-limited hop: its loss is not real loss).
func dim(l string) string { return "\x1b[2m" + l + reset }

// visTrunc truncates s to w visible columns, keeping ANSI sequences.
func visTrunc(s string, w int) string {
	if w <= 0 {
		return s
	}
	var b strings.Builder
	n := 0
	esc := false
	for _, r := range s {
		if esc {
			b.WriteRune(r)
			if (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') {
				esc = false
			}
			continue
		}
		if r == 0x1b {
			esc = true
			b.WriteRune(r)
			continue
		}
		if n >= w {
			continue
		}
		b.WriteRune(r)
		n++
	}
	if n >= w {
		b.WriteString(reset)
	}
	return b.String()
}

func (u *UI) render(s *core.Snapshot) {
	w, h, err := term.GetSize(int(u.out.Fd()))
	if err != nil || w <= 0 {
		w, h = 160, 50
	}
	var top, body, bottom []string
	add := func(dst *[]string, format string, a ...any) { *dst = append(*dst, fmt.Sprintf(format, a...)) }

	status := ""
	if u.paused {
		status = "  \x1b[7m PAUSED \x1b[0m"
	}
	if s.Impaired {
		status += "  \x1b[1;35mMONITORING_IMPAIRED: " + strings.Join(s.ImpairedReasons, ",") + "\x1b[0m"
	}
	add(&top, "\x1b[1mmpmtr\x1b[0m %s  view: %s%s   %s",
		s.Time.Format("15:04:05"), viewNames[u.view], status, keyHints("[q]uit [p]ause [r]eset [d]view [s]ort ↑↓ Enter fold [-]/[+] all [*] routes Tab [?]help"))
	for _, wn := range u.rt.Warnings() {
		add(&top, "\x1b[33m! %s\x1b[0m", wn)
	}
	if u.msg != "" && time.Since(u.msgAt) < 4*time.Second {
		add(&top, "\x1b[7m %s \x1b[0m", u.msg)
	}
	if u.help {
		for _, l := range helpText {
			if l != "" && l[0] != ' ' {
				l = "\x1b[1m" + l + "\x1b[0m" // a section title
			}
			add(&body, "%s", l)
		}
		add(&body, "")
		add(&body, "\x1b[1mTCPDUMP FILTER FOR THIS RUN\x1b[0m  (to record the same packets)")
		for _, l := range wrapWords(u.rt.PcapFilter(), max(20, w-4)) {
			add(&body, "  %s", l) // libpcap takes the line breaks as spaces
		}
		u.flush(top, body, nil, w, h)
		return
	}
	if len(s.Endpoints) == 0 {
		u.flush(top, nil, nil, w, h)
		return
	}
	if int(u.ep) >= len(s.Endpoints) {
		u.ep = 0
	}
	if len(s.Endpoints) > 1 {
		var parts []string
		for i, e := range s.Endpoints {
			mark := " "
			if core.EndpointID(i) == u.ep {
				mark = "▶"
			}
			parts = append(parts, fmt.Sprintf("%s%s %s%s%s", mark, e.Target, color(e.State.Row()), e.State, reset))
		}
		add(&top, "%s", strings.Join(parts, "  "))
	}
	e := s.Endpoints[u.ep]
	rn := report.RouteNames(e)
	kind, verdict := report.Verdict(e, s.Impaired)
	vc := map[string]string{"ok": "\x1b[1;32m✔ ", "bad": "\x1b[1;31m✘ ", "warn": "\x1b[1;33m⚠ ", "wait": "\x1b[1;36m… "}[kind]
	add(&top, "%s%s\x1b[0m", vc, verdict)
	for i, l := range report.EndpointSummary(e) {
		if i == 0 {
			l = strings.Replace(l, "  "+e.State.String(), "  "+color(e.State.Row())+e.State.String(), 1)
			l = strings.Replace(l, "  │", reset+"  │", 1)
		}
		add(&top, "%s", l)
	}
	names := u.rt.Names
	flows := u.sorted(e)
	if u.sel >= len(flows) {
		u.sel = max(0, len(flows)-1)
	}
	// Bottom: localization (if any), problem flows (tree view), status.
	if L := e.Localization; L.Level != core.LocNone {
		seg := ""
		if len(L.SuspectedSegments) > 0 {
			seg = ": " + strings.Join(L.SuspectedSegments, "; ")
		}
		add(&bottom, "\x1b[1mlocalization\x1b[0m %s%s  (%s)", L.Level, seg, strings.Join(L.BadFlows, ","))
	}
	if u.view == viewTree {
		var bad []core.FlowSnap
		for _, f := range flows {
			if f.State == core.FDown || f.State == core.FLoss || f.State == core.FInvalid {
				bad = append(bad, f)
			}
		}
		for i, f := range bad {
			if i == 3 {
				add(&bottom, "  … %d more failing flows (press d)", len(bad)-3)
				break
			}
			where := "route " + dashName(rn[f.Group])
			if f.ACServer != "" {
				where = "server " + f.ACServer
			}
			if why := report.InvalidWhy(f.Invalid); f.State == core.FInvalid && why != "" {
				add(&bottom, "  %s%-5s INVALID%s sport %d %s: %s", flowColor(f.State), f.Name, reset, f.SPort, where, why)
				continue
			}
			add(&bottom, "  %s%-5s %s%s sport %d %s  fail %s n=%d  %s", flowColor(f.State), f.Name, f.State, reset, f.SPort, where,
				report.Pct(f.W5.FailureRate), f.W5.Valid, f.Flags.Join(","))
		}
	}
	if p := u.rt.Plugin(); p != nil {
		if err := p.Dead(); err != nil {
			add(&bottom, "\x1b[1;31mapp plugin %s stopped: %v\x1b[0m", p.Name, err)
		}
	}
	m := s.M
	add(&bottom, "\x1b[2mmeasurer: e2e %.0f/s hop %.1f/s · capture drops %d · skipped slots %d · late %d · unexpected %d · local errors %d\x1b[0m",
		s.E2EPPS, s.HopPPS, m.CaptureDrops+m.UserDrops, m.SchedSkips, m.Late, m.Unexpected, m.LocalErrors)
	if n := len(s.Events); n > 0 {
		x := s.Events[n-1]
		add(&bottom, "\x1b[2mlast event %s %s %s %s\x1b[0m", x.Time.Format("15:04:05"), x.Type, x.Group, x.State)
	}

	switch u.view {
	case viewTree:
		if len(e.Tree) == 0 {
			add(&body, "  (no observed topology yet — see flow table, press d)")
		} else {
			add(&body, "\x1b[2m%s\x1b[0m", report.HopHeaderFor(names))
			u.renderTree(&body, e.Tree, rn, names)
			if l := report.UnresolvedLine(e); l != "" {
				add(&body, "\x1b[2m%s\x1b[0m", l)
			}
			if l := report.StoppedLine(e); l != "" {
				add(&body, "\x1b[2m%s\x1b[0m", l)
			}
		}
	case viewServers:
		sv := u.serverList()
		if u.srvSel >= len(sv) {
			u.srvSel = max(0, len(sv)-1)
		}
		add(&body, "\x1b[2m%s\x1b[0m", report.ServerHeader)
		u.srvLine = len(body)
		for i, sv := range sv {
			pre := ""
			if i == u.srvSel {
				pre = "\x1b[7m"
				u.srvLine = len(body)
			}
			add(&body, "%s%s%s%s", pre, color(sv.State), report.ServerLine(sv, routeNames(rn, sv.Groups)), reset)
		}
		add(&body, "\x1b[2m  ↑↓ select · Enter: the route to the server (its measured port) · Esc there returns here\x1b[0m")
	case viewFlows:
		// the column the table is sorted by stands out in the header
		col := sortCols[u.sortBy%len(sortCols)].name
		add(&body, "\x1b[2m%s\x1b[0m", strings.Replace(report.FlowHeader, col, "\x1b[0;7m"+col+"\x1b[0;2m", 1))
		for i, f := range flows {
			pre := ""
			if i == u.sel {
				pre = "\x1b[7m"
			}
			add(&body, "%s%s%s%s", pre, flowColor(f.State), report.FlowLineNamed(f, rn[f.Group]), reset)
		}
		for _, l := range report.FlowLegend {
			add(&body, "\x1b[2m%s\x1b[0m", l)
		}
	case viewFlow:
		if len(flows) > 0 {
			f := flows[u.sel]
			reason := ""
			if f.Reason != core.ReasonNone {
				reason = " (" + report.ReasonText(f) + ")"
			}
			back := "[↑↓ other flow, Esc back]"
			if u.backTo >= 0 {
				back = "[Esc back to the " + viewNames[u.backTo] + "]"
			}
			if f.Focus {
				back = "\x1b[7m FOCUS \x1b[0m [f off] " + back
			} else {
				back = "[f]ocus " + back
			}
			srv := ""
			if f.ACServer != "" {
				srv = "  → server " + f.ACServer
			}
			add(&body, "%s%s%s sport %d%s  %s%s  availability %s  route %s (%s, %s)  distance %s  %d route version(s)   %s",
				flowColor(f.State), f.Name, reset, f.SPort, srv, f.State, reason, f.Avail, rn[f.Group], f.Group, f.Level, dist(f.Distance), f.RouteVers, back)
			for _, r := range f.RouteHist {
				rtt := "-"
				if r.MeanRTTUs != nil {
					rtt = report.Ms(uint32(*r.MeanRTTUs))
				}
				add(&body, "  earlier route v%d (%s, ended by %s): %d of %d probes failed · mean rtt %s ms",
					r.Ver, (time.Duration(r.EndMs-r.StartMs) * time.Millisecond).Round(time.Second), r.EndedBy, r.Failed, r.Valid, rtt)
			}
			c := f.C
			add(&body, "probes: sent %d · syn/ack %d · rst %d · tcp timeout %d · icmp unreach %d · skipped %d · late %d · weak %d · unexpected %d · local %d · impaired %d",
				c.Sent, c.SynAck, c.Rst, c.Timeout, c.Unreach, c.Skipped, c.Late, c.Weak, c.Unexpected, c.LocalErr, c.Impaired)
			tv, tf := c.Valid(), c.Failures()
			tot := "-"
			if tv > 0 {
				tot = fmt.Sprintf("%.1f%%", 100*float64(tf)/float64(tv))
			}
			add(&body, "failure: total %s (%d of %d, = DST row) · 60s %s n=%d [%s] · 5m %s n=%d [%s] · last success %s ago · in a row: %d fail / %d ok%s · loss episodes %d (max %d)",
				tot, tf, tv, report.Pct(f.W60.FailureRate), f.W60.Valid, report.CI(f.W60), report.Pct(f.W5.FailureRate), f.W5.Valid, report.CI(f.W5),
				report.Age(f.SinceOKMs), f.ConsecFail, f.ConsecPos, report.DownNote(f), f.Episodes, f.MaxRun)
			base := "unknown"
			if f.RTT.BaselineKnown {
				base = report.Ms(f.RTT.Baseline)
			}
			if c.AppSent > 0 {
				last := ""
				if f.AppStage != "" || f.AppErr != "" {
					last = fmt.Sprintf(" · last failure: %s: %s", f.AppStage, f.AppErr)
				}
				add(&body, "app checks (%s): %d · ok %d · failed %d · local errors %d%s", u.appName(), c.AppSent, c.AppOK, c.AppFail, c.AppLocal, last)
			}
			add(&body, "rtt ms: last %s · min %s · median %s · p95 %s · max %s · jitter %s · baseline %s",
				report.Ms(f.RTT.Last), report.Ms(f.RTT.Min), report.Ms(f.RTT.Median), report.Ms(f.RTT.P95), report.Ms(f.RTT.Max), report.Ms(uint32(f.RTT.Jitter)), base)
			if len(f.Flags) > 0 {
				add(&body, "flags: %s", f.Flags.Join(" "))
			}
			add(&body, "\x1b[2m%s\x1b[0m", report.HopHeaderFor(names))
			notes := report.PathNotes(f.Hops, names)
			for i, hs := range f.Hops {
				l := report.HopLineNote(hs, names, "", notes[i])
				if hs.RateLimit {
					l = dim(l)
				}
				add(&body, "%s", l)
			}
		}
	}
	u.flush(top, body, bottom, w, h)
}

// routeNames maps route IDs to their display names (A, B, ...).
func routeNames(rn map[string]string, ids []string) []string {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if n := rn[id]; n != "" {
			out = append(out, n)
		}
	}
	return out
}

func dist(d core.TTL) string {
	if d == 0 {
		return "UNKNOWN"
	}
	return fmt.Sprint(d)
}

func (u *UI) flush(top, body, bottom []string, w, h int) {
	avail := h - len(top) - len(bottom)
	if avail < 3 {
		bottom = nil
		avail = h - len(top)
	}
	if u.scroll > max(0, len(body)-avail) {
		u.scroll = max(0, len(body)-avail)
	}
	sl := -1
	if !u.help { // the help is just scrolled
		switch u.view {
		case viewFlows:
			sl = u.sel + 1
		case viewTree:
			sl = u.selLine
		case viewServers:
			sl = u.srvLine
		}
	}
	if sl >= 0 {
		// keep the selection visible
		if sl < u.scroll+1 {
			u.scroll = max(0, sl-1)
		} else if sl >= u.scroll+avail-1 {
			u.scroll = sl + 2 - avail
		}
	}
	vis := body
	more := ""
	if len(body) > avail && avail > 0 {
		end := min(len(body), u.scroll+avail-1)
		vis = body[u.scroll:end]
		more = fmt.Sprintf("\x1b[2m-- lines %d-%d of %d (↑↓ PgUp PgDn) --\x1b[0m", u.scroll+1, end, len(body))
	}
	var lines []string
	lines = append(lines, top...)
	lines = append(lines, vis...)
	if more != "" {
		lines = append(lines, more)
	}
	lines = append(lines, bottom...)
	if len(lines) > h {
		lines = lines[:h]
	}
	// The last column is left alone: a character written there leaves the
	// cursor in a pending wrap, and what "erase to end of line" does then
	// differs between terminals.
	for i, l := range lines {
		lines[i] = visTrunc(l, w-1)
	}
	if w != u.shownW || h != u.shownH {
		u.shown, u.shownW, u.shownH = nil, w, h // resized: what is there is not known
	}
	if out := frameDiff(u.shown, lines); len(out) > 0 {
		u.out.Write(out)
	}
	u.shown = lines
}

// helpText is the help overlay. A line that starts at the margin is a
// section title; the rest is indented under it.
var helpText = []string{
	"KEYS",
	"  q              quit (the terminal is restored)",
	"  ?  h           this help; Esc closes it; ↑ ↓ PgUp PgDn scroll it",
	"  d              next view: route tree → servers (--anycast) → flow table → one flow",
	"  p              pause the screen; measuring goes on",
	"  r              reset the statistics: a new measurement epoch, warm-up starts again",
	"  Tab  n         next endpoint (several targets)",
	"  Ctrl-L         redraw the whole screen",
	"",
	"  Route tree",
	"  ↑ ↓  j k       select a row;  PgUp PgDn  ten rows",
	"  Enter          fold or unfold the hop (a folded hop names the routes below it);",
	"                 on a DST row: open that route's measured flow (Esc returns)",
	"  -  +           fold all, unfold all",
	"  *              one line per route: forks stay open, each part that no longer branches is folded",
	"",
	"  Flow table",
	"  ↑ ↓  j k       select a flow;  Enter  open it (Esc or Enter returns)",
	"  ← →  s         sort by the previous / next column; the header marks it; numbers largest first",
	"",
	"  One flow",
	"  ↑ ↓            the previous / next flow",
	"  f              focus: trace this port's whole route every interval, so its hop rows are fresh.",
	"                 The hop refresh of the other ports waits meanwhile (their TCP measurements do not).",
	"                 Leaving the view turns focus off",
	"",
	"WHAT IT DOES",
	"  Sends TCP SYNs from many source ports. Routers that balance by port (ECMP) put the ports on",
	"  different routes. Each port is traced once (TTL-limited SYNs) to find the routes; then one port",
	"  of every route (--flows N: N ports) is measured end to end continuously. A problem on one route",
	"  shows up as some ports failing while the others are fine.",
	"",
	"ROUTE TREE",
	"  A hop shared by several routes is shown once; the tree forks where ports take different routes.",
	"  Each branch ends in a DST row: the TCP result of the ports measured on that route",
	"  (route A, B, …; its state; the measured source port; how many ports took the route).",
	"",
	"  Columns",
	"  Loss%          share of this hop's probes that got no ICMP answer. Not traffic loss: many routers",
	"                 answer only some probes. Shown from 3 probes on",
	"  Snt            probes sent to this hop",
	"  Last Med P95   round-trip time, ms: the last one, the median, the 95th percentile,",
	"  Best Wrst Jttr the best, the worst, the jitter",
	"  PLUGIN         what the --hop-info plugins say (e.g. the interface that owns the address);",
	"                 on DST and server rows what the --app plugin notes (e.g. the HTTP status)",
	"",
	"  The HOST column",
	"  name (address) the name comes from a plugin or from reverse DNS (--dns)",
	"  * no reply     the hop has answered none of the probes sent to it",
	"  ? no reply yet too few probes to tell",
	"  ? … (unconfirmed)        one answer so far",
	"  ? only later hops answer only routers of later TTLs answered here: who is here is not known",
	"  ~ a | b        several routers answer at this TTL (balancing per packet)",
	"",
	"  FLAGS",
	"  stale          no fresh probe lately (the hop budget is shared; see focus)",
	"  icmp-limit?    a later hop loses much less: this points to the router limiting its ICMP",
	"                 answers, not to loss of forwarded traffic (the row is dimmed)",
	"  also answered by later hop X   X answered probes sent with this TTL too; X is placed where it",
	"                 answers last. Not another route and not a route change",
	"  unstable       the answering router keeps changing",
	"  unreach        an ICMP unreachable came from here",
	"  mpls:N         MPLS label the router reported (a/b: a stack, outermost first;",
	"                 a,b: different labels for different ports)",
	"  qseq:N         answers matched without the sequence number (weaker match)",
	"  AS… / IX:… / (CC, City)  the hop's network (--asn, --ix, --geoip), shown where it changes",
	"",
	"FLOW TABLE",
	"  One row per source port.",
	"  STATE          OK · LOSS (it loses probes) · DOWN (a run of failures in a row) · WARMUP (fewer than",
	"                 30 results) · UNKNOWN (not enough trustworthy data) · INVALID (the port cannot be used)",
	"  ROUTE          the route the port takes (the letters of the tree)",
	"  TRACED         is its route known: yes · partly (incomplete, but provably a different route) ·",
	"                 probably (fits one route) · ambiguous (fits several) · not yet",
	"  EXEC VALID     probes sent; probes with a usable result (5 min)",
	"  TMO UNR        no answer; ICMP unreachable (5 min)",
	"  FAIL5m CI95    share of failures over 5 min and its 95 % interval",
	"  LAST … JIT     round-trip time, ms",
	"  FLAGS          RTT-UP: slower than its own baseline or than the other ports · IMPAIRED: the",
	"                 measuring itself was disturbed (the measuring host, or the server still holds",
	"                 an earlier probe's connection) · app-failed:N/M: TCP answered, N of M --app",
	"                 checks failed",
	"",
	"THE LINES BELOW",
	"  measurer       probe rates; capture drops and skipped slots are the measuring host's own problems;",
	"                 late = answers after the deadline (counted as lost, then noted);",
	"                 unexpected = packets on our ports that answer none of our probes (another program",
	"                 on the same source port; a port flooded by them turns INVALID)",
	"  localization   where the failing ports' routes differ from the healthy ones: an observation, not a proven link",
}

// renderTree adds the route tree with folding and the row selection.
func (u *UI) renderTree(body *[]string, rows []core.TreeRow, rn map[string]string, names report.Names) {
	// The rows are in the order of a walk from the top: a row with
	// children is followed by its first child.
	kids := func(i int) bool { return i+1 < len(rows) && rows[i+1].Parent == i }
	notes := report.TreeNotes(rows, names)
	u.treeKids, u.treeAll, u.treeUp = u.treeKids[:0], u.treeAll[:0], u.treeUp[:0]
	for i := range rows {
		u.treeAll = append(u.treeAll, rows[i].Path)
		u.treeUp = append(u.treeUp, rows[i].Parent)
		if kids(i) {
			u.treeKids = append(u.treeKids, rows[i].Path)
		}
	}
	type vr struct {
		i       int
		summary string
	}
	var vis []vr
	hide := -1 // a folded row: everything below it is not shown
	for i := 0; i < len(rows); i++ {
		r := rows[i]
		if hide >= 0 && core.Below(rows, i, hide) {
			continue
		}
		hide = -1
		v := vr{i: i}
		if kids(i) && u.folded[r.Path] {
			hide = i
			var rs []string
			for j := i + 1; j < len(rows) && core.Below(rows, j, i); j++ {
				if rows[j].Group != nil {
					g := rows[j].Group
					rs = append(rs, rn[g.ID]+" "+color(g.State.Row())+report.RouteState(*g).String()+reset)
				}
			}
			if len(rs) > 0 {
				v.summary = "▸ route " + strings.Join(rs, ", ")
				if len(rs) > 1 {
					v.summary = "▸ routes " + strings.Join(rs, ", ")
				}
			}
		}
		vis = append(vis, v)
	}
	u.treeVis = u.treeVis[:0]
	for _, v := range vis {
		u.treeVis = append(u.treeVis, rows[v.i].Path)
	}
	if k := slices.Index(u.treeVis, u.treePath); k >= 0 {
		u.treeSel = k
	}
	u.treeSel = min(max(u.treeSel, 0), max(0, len(vis)-1))
	if len(vis) > 0 {
		u.treePath = u.treeVis[u.treeSel]
	}
	u.selLine = -1
	u.treeDst = map[string]wire.Port{}
	for _, r := range rows {
		if r.SPort != 0 {
			u.treeDst[r.Path] = r.SPort
		} else if r.Group != nil {
			if len(r.Group.Measured) > 0 {
				u.treeDst[r.Path] = r.Group.Measured[0]
			} else {
				u.treeDst[r.Path] = 0
			}
		}
	}
	for k, v := range vis {
		r := rows[v.i]
		// ▾ only where the tree branches (children drawn with connectors);
		// any row with children can still be folded, then it shows ▸.
		mark := " "
		if kids(v.i) {
			if u.folded[r.Path] {
				mark = "▸"
			} else if rows[v.i+1].Branch {
				mark = "▾"
			}
		}
		l := report.HopLineNote(r.Hop, names, mark+r.Prefix, notes[v.i])
		if r.Hop.RateLimit {
			l = dim(l)
		}
		if r.Group != nil {
			head, word, tail := report.RouteTagParts(*r.Group, rn[r.Group.ID])
			l += " " + head + color(r.Group.State.Row()) + word + reset + tail
		}
		if r.Hop.Kind == core.KindServer {
			word, tail := report.ServerTagParts(r)
			l += " " + color(r.State) + word + reset + tail
		}
		if v.summary != "" {
			l += " " + v.summary
		}
		if k == u.treeSel {
			u.selLine = len(*body)
			l = "\x1b[7m" + strings.ReplaceAll(l, reset, reset+"\x1b[7m") + reset
		}
		*body = append(*body, l)
	}
}

func (u *UI) appName() string {
	if p := u.rt.Plugin(); p != nil {
		return p.Name
	}
	return "-"
}

// unfoldChain opens a node and, while the opened part does not branch (one
// child below), the nodes under it too: opening a hop shows the route down
// to the next fork (or its end) instead of one folded row at a time.
func (u *UI) unfoldChain(p string) {
	for {
		delete(u.folded, p)
		at := slices.Index(u.treeAll, p)
		var kids []string
		for j, up := range u.treeUp {
			if at >= 0 && up == at {
				kids = append(kids, u.treeAll[j])
			}
		}
		if len(kids) != 1 || !slices.Contains(u.treeKids, kids[0]) {
			return
		}
		p = kids[0]
	}
}

// foldToRoutes shows the smallest tree that still has every fork: each part
// that no longer branches (one route) is folded into one line at its top.
func (u *UI) foldToRoutes() {
	kids := make([]int, len(u.treeAll))
	for _, up := range u.treeUp {
		if up >= 0 {
			kids[up]++
		}
	}
	// forks[i]: row i or something below it has more than one child
	forks := make([]bool, len(u.treeAll))
	for i, n := range kids {
		if n > 1 {
			for j := i; j >= 0 && !forks[j]; j = u.treeUp[j] {
				forks[j] = true
			}
		}
	}
	clear(u.folded)
	for i, p := range u.treeAll {
		if kids[i] == 0 || forks[i] {
			continue
		}
		if up := u.treeUp[i]; up < 0 || forks[up] {
			u.folded[p] = true
		}
	}
}

// serverList: the current endpoint's servers in name order (S1, S2, …).
func (u *UI) serverList() []core.ServerSnap {
	if !u.hasServers() {
		return nil
	}
	sv := append([]core.ServerSnap(nil), u.last.Endpoints[u.ep].Anycast.Servers...)
	num := func(n string) int {
		v := 0
		for _, ch := range n {
			if ch >= '0' && ch <= '9' {
				v = v*10 + int(ch-'0')
			}
		}
		return v
	}
	slices.SortFunc(sv, func(a, b core.ServerSnap) int { return num(a.Name) - num(b.Name) })
	return sv
}

// wrapWords breaks s at spaces into lines of at most width runes (a longer
// word stays whole).
func wrapWords(s string, width int) []string {
	var out []string
	line := ""
	for _, wd := range strings.Fields(s) {
		if line != "" && len([]rune(line))+1+len([]rune(wd)) > width {
			out = append(out, line)
			line = ""
		}
		if line != "" {
			line += " "
		}
		line += wd
	}
	if line != "" {
		out = append(out, line)
	}
	return out
}
