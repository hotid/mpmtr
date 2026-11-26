package app

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/netip"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/hotid/mpmtr/internal/report"
)

// Hop-information plugins. See docs/PLUGINS.md.
//
// A plugin is a separate executable (--hop-info NAME runs mpmtr-hop-NAME)
// that says what it knows about a hop address: a name and a short note.
// mpmtr itself sends nothing anywhere for it; where a plugin looks the
// address up, and whether it does at all, is the plugin's business and its
// own configuration. Messages are JSON objects, one per line: the plugin
// reads them on stdin and writes on stdout, and speaks first ("hello").
// Several plugins run side by side. A plugin that fails never affects the
// measurement: its annotations just stop.

type hopMsg struct {
	Type    string `json:"type"`
	ID      uint64 `json:"id,omitempty"`
	Name    string `json:"name,omitempty"`
	Version string `json:"version,omitempty"`
	Addr    string `json:"addr,omitempty"`
	Note    string `json:"note,omitempty"`
}

// HopPluginSpec is one --hop-info: the executable and its own arguments.
type HopPluginSpec struct {
	Path string
	Args []string
}

// HopNote is what the plugins said about one address.
type HopNote = report.HopNote

const hopAnswerTimeout = 30 * time.Second

type hopPlugin struct {
	label   string
	cmd     *exec.Cmd
	out     chan hopMsg
	wait    map[uint64]netip.Addr // request id → address
	next    uint64
	dead    bool
	errTail *tail
}

// HopInfo runs the hop-information plugins and caches their answers. The
// nil *HopInfo knows nothing.
type HopInfo struct {
	mu      sync.Mutex
	plugins []*hopPlugin
	got     map[netip.Addr]*hopEntry
	every   time.Duration // > 0: an answer older than this is asked for again
	pending int
	// colW: the widest text seen in each column of each plugin's notes. A
	// plugin separates the columns of its note with tabs; they are padded
	// to these widths so that they line up down the screen.
	colW   [][]int
	closed bool
	warn   func(string)
}

// hopEntry is what is known about one address, per plugin (in order).
type hopEntry struct {
	notes []HopNote
	asked []time.Time // when the plugin was last asked
	busy  []bool      // a request is in flight
}

// FindHopPlugin resolves --hop-info NAME to an executable: a path as given,
// else "mpmtr-hop-NAME" next to the mpmtr binary, else in PATH.
func FindHopPlugin(name string) (string, error) { return findExe("mpmtr-hop-", "--hop-info", name) }

// StartHopInfo starts the plugins and waits for the hello of each. With
// every > 0 an address still shown is asked again when its answer is older
// than that; otherwise each address is asked once.
func StartHopInfo(specs []HopPluginSpec, every time.Duration, warn func(string)) (*HopInfo, error) {
	if len(specs) == 0 {
		return nil, nil
	}
	h := &HopInfo{got: map[netip.Addr]*hopEntry{}, every: every, warn: warn}
	for i, s := range specs {
		p, err := h.start(i, s)
		if err != nil {
			h.Close()
			return nil, err
		}
		h.plugins = append(h.plugins, p)
	}
	return h, nil
}

func (h *HopInfo) start(idx int, s HopPluginSpec) (*hopPlugin, error) {
	p := &hopPlugin{out: make(chan hopMsg, 4096), wait: map[uint64]netip.Addr{}, errTail: &tail{max: 20}}
	p.cmd = exec.Command(s.Path, s.Args...)
	stdin, err := p.cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := p.cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stderr, _ := p.cmd.StderrPipe()
	if err := p.cmd.Start(); err != nil {
		return nil, fmt.Errorf("plugin %s: %w", s.Path, err)
	}
	go p.errTail.read(stderr)
	lines := make(chan hopMsg, 64)
	go func() {
		defer close(lines)
		sc := bufio.NewScanner(stdout)
		sc.Buffer(make([]byte, 0, 4096), 64<<10)
		for sc.Scan() {
			var m hopMsg
			if json.Unmarshal(sc.Bytes(), &m) == nil {
				lines <- m
			}
		}
	}()
	select {
	case m, ok := <-lines:
		if !ok || m.Type != "hello" {
			p.cmd.Process.Kill()
			p.cmd.Wait()
			return nil, fmt.Errorf("plugin %s did not say hello %s", s.Path, p.errTail.String())
		}
		p.label = clean(m.Name, 32)
	case <-time.After(5 * time.Second):
		p.cmd.Process.Kill()
		p.cmd.Wait()
		return nil, fmt.Errorf("plugin %s did not say hello within 5s %s", s.Path, p.errTail.String())
	}
	if p.label == "" {
		p.label = s.Path
	}
	go func() { // writer: a stuck plugin never blocks the screen
		enc := json.NewEncoder(stdin)
		for m := range p.out {
			if enc.Encode(m) != nil {
				return
			}
		}
		stdin.Close()
	}()
	go func() {
		for m := range lines {
			if m.Type == "info" {
				h.answer(idx, p, m)
			}
		}
		err := p.cmd.Wait()
		h.mu.Lock()
		was := p.dead
		p.dead = true
		for id := range p.wait {
			h.done(idx, p, id)
		}
		h.mu.Unlock()
		if !was && h.warn != nil {
			h.warn(fmt.Sprintf("hop-info plugin %s stopped: %v %s", p.label, err, p.errTail.String()))
		}
	}()
	return p, nil
}

// done ends the request id of plugin idx and returns its entry.
func (h *HopInfo) done(idx int, p *hopPlugin, id uint64) *hopEntry {
	addr, ok := p.wait[id]
	if !ok {
		return nil
	}
	delete(p.wait, id)
	h.pending--
	e := h.got[addr]
	e.busy[idx] = false
	return e
}

func (h *HopInfo) answer(idx int, p *hopPlugin, m hopMsg) {
	h.mu.Lock()
	defer h.mu.Unlock()
	e := h.done(idx, p, m.ID)
	if e == nil {
		return
	}
	n := HopNote{Name: clean(m.Name, 64), Note: cleanNote(m.Note, 120)}
	if n == (HopNote{}) && e.notes[idx] != (HopNote{}) {
		return // a refresh that got nothing: what was known stays on the screen
	}
	e.notes[idx] = n
	for len(h.colW) <= idx {
		h.colW = append(h.colW, nil)
	}
	for j, col := range strings.Split(n.Note, "\t") {
		if j >= len(h.colW[idx]) {
			h.colW[idx] = append(h.colW[idx], 0)
		}
		h.colW[idx][j] = max(h.colW[idx][j], len([]rune(col)))
	}
}

// width is the width of the plugins' column: all columns of all plugins
// side by side, between the column title and 40 characters; 0 without
// plugins.
func (h *HopInfo) width() int {
	if h == nil {
		return 0
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	w := -1
	for _, cols := range h.colW {
		for _, c := range cols {
			w += 1 + c
		}
	}
	return min(max(w, len("PLUGIN")), 40)
}

// aligned lays the notes of one address out in columns: every column of
// every plugin padded to its width, so that the same column of different
// rows starts at the same place.
func (h *HopInfo) aligned(notes []HopNote) string {
	var b strings.Builder
	for i, cols := range h.colW {
		var have []string
		if i < len(notes) && notes[i].Note != "" {
			have = strings.Split(notes[i].Note, "\t")
		}
		for j, w := range cols {
			if b.Len() > 0 {
				b.WriteByte(' ')
			}
			t := ""
			if j < len(have) {
				t = have[j]
			}
			b.WriteString(t)
			b.WriteString(strings.Repeat(" ", w-len([]rune(t))))
		}
	}
	return strings.TrimRight(b.String(), " ")
}

// ask returns what is known about ip and queues it for every plugin that
// was never asked or (with a refresh interval) was asked too long ago. It
// runs every time a row is drawn, so only addresses still shown refresh.
func (h *HopInfo) ask(ip netip.Addr) []HopNote {
	h.mu.Lock()
	defer h.mu.Unlock()
	e := h.got[ip]
	if e == nil {
		n := len(h.plugins)
		e = &hopEntry{notes: make([]HopNote, n), asked: make([]time.Time, n), busy: make([]bool, n)}
		h.got[ip] = e
	}
	now := time.Now()
	for i, p := range h.plugins {
		if p.dead || e.busy[i] || h.closed {
			continue
		}
		if !e.asked[i].IsZero() && (h.every <= 0 || now.Sub(e.asked[i]) < h.every) {
			continue
		}
		e.asked[i] = now
		p.next++
		id := p.next
		select {
		case p.out <- hopMsg{Type: "hop", ID: id, Addr: ip.String()}:
			p.wait[id] = ip
			e.busy[i] = true
			h.pending++
			time.AfterFunc(hopAnswerTimeout, func() {
				h.mu.Lock()
				h.done(i, p, id)
				h.mu.Unlock()
			})
		default: // the plugin does not read: this address goes without
		}
	}
	return e.notes
}

// Name is the first name a plugin gave for ip ("" = none, or not yet).
func (h *HopInfo) Name(ip netip.Addr) string {
	if h == nil || !ip.IsValid() {
		return ""
	}
	for _, n := range h.ask(ip) {
		if n.Name != "" {
			return n.Name
		}
	}
	return ""
}

// Note is what the plugins say about ip, laid out in columns.
func (h *HopInfo) Note(ip netip.Addr) string {
	if h == nil || !ip.IsValid() {
		return ""
	}
	notes := h.ask(ip)
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.aligned(notes)
}

// All returns what the plugins said about every address asked, for the
// JSON report: address → plugin name → answer.
func (h *HopInfo) All() map[netip.Addr]map[string]HopNote {
	if h == nil {
		return nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	out := map[netip.Addr]map[string]HopNote{}
	for ip, e := range h.got {
		for i, n := range e.notes {
			if n == (HopNote{}) {
				continue
			}
			if out[ip] == nil {
				out[ip] = map[string]HopNote{}
			}
			n.Note = strings.ReplaceAll(n.Note, "\t", " ") // columns are for the screen
			out[ip][h.plugins[i].label] = n
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func (h *HopInfo) idle() bool {
	if h == nil {
		return true
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.pending <= 0
}

// Close stops the plugins.
func (h *HopInfo) Close() {
	if h == nil {
		return
	}
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return
	}
	h.closed = true
	ps := append([]*hopPlugin(nil), h.plugins...)
	for _, p := range ps {
		p.dead = true
	}
	h.mu.Unlock()
	for _, p := range ps {
		close(p.out) // stdin closes: the plugin exits
		t := time.AfterFunc(time.Second, func() { p.cmd.Process.Kill() })
		defer t.Stop()
	}
}

// cleanNote is clean for a note: tabs stay, they separate its columns.
func cleanNote(s string, n int) string {
	cols := strings.Split(s, "\t")
	for i := range cols {
		cols[i] = clean(cols[i], n)
	}
	for len(cols) > 0 && cols[len(cols)-1] == "" {
		cols = cols[:len(cols)-1]
	}
	if len(cols) > 6 {
		cols = cols[:6]
	}
	return strings.Join(cols, "\t")
}

// clean makes a plugin's text fit for a terminal: no control characters,
// at most n characters.
func clean(s string, n int) string {
	s = strings.TrimSpace(strings.Map(func(r rune) rune {
		if r < 0x20 || (r >= 0x7f && r < 0xa0) {
			return -1
		}
		return r
	}, s))
	if r := []rune(s); len(r) > n {
		s = string(r[:n-1]) + "…"
	}
	return s
}
