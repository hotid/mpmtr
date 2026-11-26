package app

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/hotid/mpmtr/internal/core"
	"github.com/hotid/mpmtr/internal/enrich"
)

// eventWriter writes JSONL events to a file or stdout.
type eventWriter struct {
	mu sync.Mutex
	w  *bufio.Writer
	f  *os.File
}

func newEventWriter(path string, toStdout bool, stdout io.Writer) (*eventWriter, error) {
	ew := &eventWriter{}
	if toStdout {
		ew.w = bufio.NewWriter(stdout)
		return ew, nil
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, err
	}
	ew.f, ew.w = f, bufio.NewWriter(f)
	return ew, nil
}

func (e *eventWriter) write(ev core.Event) {
	e.mu.Lock()
	defer e.mu.Unlock()
	b, err := json.Marshal(ev)
	if err != nil {
		return
	}
	e.w.Write(b)
	e.w.WriteByte('\n')
	e.w.Flush()
}

func (e *eventWriter) close() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.w.Flush()
	if e.f != nil {
		e.f.Close()
	}
}

// Resolver is an asynchronous, cached reverse-DNS resolver (disabled by
// default, MTR -n semantics) plus the optional network annotations of hop
// addresses (AS, IX, location).
type Resolver struct {
	on      bool
	mu      sync.Mutex
	cache   map[netip.Addr]string
	pending int
	q       chan netip.Addr
	Info    *enrich.Enricher // nil = no annotations
	Hops    *HopInfo         // nil = no hop-information plugins
	warns   []string
}

// NewResolver creates a resolver; when on is false Name returns "".
func NewResolver(on bool) *Resolver {
	r := &Resolver{on: on, cache: map[netip.Addr]string{}, q: make(chan netip.Addr, 256)}
	if on {
		for i := 0; i < 4; i++ {
			go r.worker()
		}
	}
	return r
}

func (r *Resolver) worker() {
	res := &net.Resolver{PreferGo: true}
	for ip := range r.q {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		names, err := res.LookupAddr(ctx, ip.String())
		cancel()
		name := ""
		if err == nil && len(names) > 0 {
			// A PTR record is somebody else's text on its way to a terminal.
			name = strings.Map(func(r rune) rune {
				if r <= 0x20 || r >= 0x7f {
					return -1
				}
				return r
			}, strings.TrimSuffix(names[0], "."))
		}
		r.mu.Lock()
		r.cache[ip] = name
		r.pending--
		r.mu.Unlock()
	}
}

// Name returns the cached name of ip (possibly "" while pending).
func (r *Resolver) Name(ip netip.Addr) string {
	if n := r.Hops.Name(ip); n != "" {
		return n // what a plugin was told by the device itself
	}
	if !r.on || !ip.IsValid() {
		return ""
	}
	r.mu.Lock()
	n, ok := r.cache[ip]
	if !ok {
		r.cache[ip] = ""
		r.pending++
	}
	r.mu.Unlock()
	if !ok {
		select {
		case r.q <- ip:
		default:
			r.mu.Lock()
			delete(r.cache, ip)
			r.pending--
			r.mu.Unlock()
		}
	}
	return n
}

// Note returns the network annotation of ip ("" = none or not yet known).
func (r *Resolver) Note(ip netip.Addr) string { return r.Info.Note(ip) }

// PluginNote is what the hop-information plugins say about ip.
func (r *Resolver) PluginNote(ip netip.Addr) string { return r.Hops.Note(ip) }

// PluginWidth is the width of the plugins' column (0 = no plugins).
func (r *Resolver) PluginWidth() int { return r.Hops.width() }

// Settle waits (at most d) for the lookups already asked for, so that a
// final report shows the answers.
func (r *Resolver) Settle(d time.Duration) {
	end := time.Now().Add(d)
	r.Info.Settle(d)
	for time.Now().Before(end) {
		r.mu.Lock()
		p := r.pending
		r.mu.Unlock()
		if p <= 0 && r.Hops.idle() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func (r *Resolver) warn(s string) {
	r.mu.Lock()
	r.warns = append(r.warns, s)
	r.mu.Unlock()
}

// Warnings are the problems of the annotation sources so far.
func (r *Resolver) Warnings() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.warns...)
}

// Close stops the annotation sources.
func (r *Resolver) Close() {
	r.Info.Close()
	r.Hops.Close()
}
