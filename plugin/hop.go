package plugin

import (
	"bufio"
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"sync"
	"time"
)

// Hop-information plugins.
//
// A hop-information plugin is a separate executable, mpmtr-hop-NAME,
// started by `mpmtr --hop-info NAME`. mpmtr gives it the address of every
// hop it shows, once, and the plugin answers with what it knows: a name
// (shown as the host name) and a short note (shown in the PLUGIN column).
// Several plugins may run at once.
//
// Wire protocol (if you do not use this package): JSON objects, one per
// line; requests on stdin, answers on stdout.
//
//	plugin → mpmtr  {"type":"hello","name":"snmp","version":"1"}
//	mpmtr → plugin  {"type":"hop","id":4,"addr":"192.0.2.1"}
//	plugin → mpmtr  {"type":"info","id":4,"name":"core1","note":"Eth1/2"}
//
// Answer every request, with empty name and note when nothing is known.
// mpmtr closes stdin when it is done. Use stderr for diagnostics.

// HopInfo is what a plugin knows about one address; the zero value means
// nothing.
type HopInfo struct {
	Name string // the device's own name
	Note string // short free text: an interface, a site, a role
}

// HopLookup answers for one address. It must return by ctx's deadline.
type HopLookup func(ctx context.Context, addr netip.Addr) HopInfo

type hopMsg struct {
	Type    string `json:"type"`
	ID      uint64 `json:"id,omitempty"`
	Name    string `json:"name,omitempty"`
	Version string `json:"version,omitempty"`
	Addr    string `json:"addr,omitempty"`
	Note    string `json:"note,omitempty"`
}

// ServeHops runs the hop-information protocol on stdin/stdout until mpmtr
// closes stdin. At most workers lookups run at once (8 if workers <= 0);
// each gets 20 seconds.
func ServeHops(name, version string, workers int, look HopLookup) error {
	if workers <= 0 {
		workers = 8
	}
	var mu sync.Mutex
	enc := json.NewEncoder(os.Stdout)
	send := func(m hopMsg) error {
		mu.Lock()
		defer mu.Unlock()
		return enc.Encode(m)
	}
	if err := send(hopMsg{Type: "hello", Name: name, Version: version}); err != nil {
		return err
	}
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	sc := bufio.NewScanner(os.Stdin)
	for sc.Scan() {
		var m hopMsg
		if json.Unmarshal(sc.Bytes(), &m) != nil || m.Type != "hop" {
			continue
		}
		sem <- struct{}{}
		wg.Add(1)
		go func(m hopMsg) {
			defer func() { <-sem; wg.Done() }()
			var in HopInfo
			if a, err := netip.ParseAddr(m.Addr); err == nil {
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				in = look(ctx, a.Unmap())
				cancel()
			}
			send(hopMsg{Type: "info", ID: m.ID, Name: in.Name, Note: in.Note})
		}(m)
	}
	wg.Wait()
	return sc.Err()
}
