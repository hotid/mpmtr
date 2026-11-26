package app

import (
	"golang.org/x/sys/unix"

	"bufio"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// The test binary is its own plugin: MPMTR_TEST_HOP_PLUGIN selects a role.
func TestMain(m *testing.M) {
	switch role := os.Getenv("MPMTR_TEST_HOP_PLUGIN"); role {
	case "":
		os.Exit(m.Run())
	case "mute":
		time.Sleep(time.Minute) // never says hello
	case "app-hang":
		// An application plugin that says hello, takes every socket it is
		// handed and never answers.
		unix.Write(3, []byte(`{"type":"hello","name":"hang","version":"1"}`))
		buf, oob := make([]byte, 64<<10), make([]byte, 256)
		for {
			if n, _, _, _, err := unix.Recvmsg(3, buf, oob, 0); err != nil && err != unix.EINTR || n == 0 && err == nil {
				os.Exit(0)
			}
		}
	default:
		enc := json.NewEncoder(os.Stdout)
		enc.Encode(hopMsg{Type: "hello", Name: role, Version: "1"})
		seen := map[string]int{}
		sc := bufio.NewScanner(os.Stdin)
		for sc.Scan() {
			var q hopMsg
			if json.Unmarshal(sc.Bytes(), &q) != nil || q.Type != "hop" {
				continue
			}
			a := hopMsg{Type: "info", ID: q.ID}
			switch role {
			case "names":
				if q.Addr == "192.0.2.1" {
					a.Name, a.Note = "core1\x1b[31m", "Eth1/2"
				}
			case "sites":
				a.Note = "site " + q.Addr[strings.LastIndexByte(q.Addr, '.')+1:]
			case "dies":
				os.Exit(3)
			case "cols": // an interface and a counter, tab-separated
				a.Note = map[string]string{"192.0.2.1": "Port-Channel37\terr:0", "192.0.2.2": "Vlan754\terr:12 +3",
					"192.0.2.3": "Ethernet1/1", "192.0.2.4": "\tcrc:5"}[q.Addr]
			case "count", "slowcount": // how many times this address was asked
				if role == "slowcount" {
					time.Sleep(300 * time.Millisecond)
				}
				seen[q.Addr]++
				a.Note = fmt.Sprint("n", seen[q.Addr])
			case "fade": // knows the address the first time only
				if seen[q.Addr]++; seen[q.Addr] == 1 {
					a.Name, a.Note = "first", "once"
				}
			}
			enc.Encode(a)
		}
	}
	os.Exit(0)
}

// hopEvery is the refresh interval of the next hopPlugins call.
var hopEvery time.Duration

func hopPlugins(t *testing.T, roles ...string) (*HopInfo, func() []string) {
	t.Helper()
	var specs []HopPluginSpec
	for _, r := range roles {
		specs = append(specs, HopPluginSpec{Path: "/usr/bin/env", Args: []string{"MPMTR_TEST_HOP_PLUGIN=" + r, os.Args[0]}})
	}
	var mu sync.Mutex
	var got []string
	warns := func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), got...)
	}
	h, err := StartHopInfo(specs, hopEvery, func(s string) { mu.Lock(); got = append(got, s); mu.Unlock() })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(h.Close)
	return h, warns
}

func settle(t *testing.T, h *HopInfo) {
	t.Helper()
	for end := time.Now().Add(5 * time.Second); !h.idle(); time.Sleep(5 * time.Millisecond) {
		if time.Now().After(end) {
			t.Fatal("plugins did not answer")
		}
	}
}

// Several plugins at once: the first name wins, the notes are joined, an
// address nobody knows stays bare, and a plugin's text cannot carry
// terminal control characters.
func TestHopInfoPlugins(t *testing.T) {
	h, _ := hopPlugins(t, "names", "sites")
	h.Name(netip.MustParseAddr("192.0.2.1"))
	h.Note(netip.MustParseAddr("192.0.2.7"))
	settle(t, h)
	if got := h.Name(netip.MustParseAddr("192.0.2.1")); got != "core1[31m" {
		t.Errorf("name %q", got)
	}
	if got := h.Note(netip.MustParseAddr("192.0.2.1")); got != "Eth1/2 site 1" {
		t.Errorf("note %q", got)
	}
	// the second plugin's note stays in its own column
	if n, note := h.Name(netip.MustParseAddr("192.0.2.7")), h.Note(netip.MustParseAddr("192.0.2.7")); n != "" || note != "       site 7" {
		t.Errorf("unknown to the first plugin: %q %q", n, note)
	}
	all := h.All()
	if all[netip.MustParseAddr("192.0.2.1")]["names"].Name != "core1[31m" || all[netip.MustParseAddr("192.0.2.1")]["sites"].Note != "site 1" || len(all) != 2 {
		t.Errorf("all: %v", all)
	}
	var nilInfo *HopInfo
	if nilInfo.Name(netip.MustParseAddr("192.0.2.1")) != "" || nilInfo.Note(netip.MustParseAddr("192.0.2.1")) != "" || !nilInfo.idle() || nilInfo.All() != nil {
		t.Error("nil HopInfo knows something")
	}
	nilInfo.Close()
}

// A plugin that dies is a warning; the other one keeps answering, and
// nothing waits for the dead one.
func TestHopInfoPluginDies(t *testing.T) {
	h, warns := hopPlugins(t, "dies", "sites")
	h.Note(netip.MustParseAddr("192.0.2.9"))
	settle(t, h)
	if got := h.Note(netip.MustParseAddr("192.0.2.9")); got != "site 9" {
		t.Errorf("note %q", got)
	}
	for end := time.Now().Add(2 * time.Second); len(warns()) == 0 && time.Now().Before(end); {
		time.Sleep(10 * time.Millisecond)
	}
	if w := warns(); len(w) != 1 || !strings.Contains(w[0], "dies") {
		t.Errorf("warnings: %v", w)
	}
	if got := h.Note(netip.MustParseAddr("192.0.2.10")); got != "" {
		t.Errorf("first call %q", got)
	}
	settle(t, h)
	if got := h.Note(netip.MustParseAddr("192.0.2.10")); got != "site 10" {
		t.Errorf("after a plugin died: %q", got)
	}
}

func TestHopInfoNoHello(t *testing.T) {
	if testing.Short() {
		t.Skip("waits 5 s for the hello")
	}
	_, err := StartHopInfo([]HopPluginSpec{{Path: "/usr/bin/env", Args: []string{"MPMTR_TEST_HOP_PLUGIN=mute", os.Args[0]}}}, 0, nil)
	if err == nil || !strings.Contains(err.Error(), "hello") {
		t.Fatalf("err %v", err)
	}
}

// Without an interval an address is asked once, however often its row is
// drawn. With one, it is asked again when the answer is that old: the old
// answer stays until the new one is in, a new one replaces it, a refresh
// that brings nothing does not blank what was known, and a slow plugin gets
// one request at a time.
func TestHopInfoRefresh(t *testing.T) {
	hopEvery = 0
	h, _ := hopPlugins(t, "count")
	for i := 0; i < 5; i++ {
		h.Note(netip.MustParseAddr("192.0.2.1"))
		settle(t, h)
		time.Sleep(30 * time.Millisecond)
	}
	if got := h.Note(netip.MustParseAddr("192.0.2.1")); got != "n1" {
		t.Errorf("no interval: %q, want n1", got)
	}

	hopEvery = 150 * time.Millisecond
	defer func() { hopEvery = 0 }()
	h, _ = hopPlugins(t, "count", "fade")
	h.Note(netip.MustParseAddr("192.0.2.1"))
	settle(t, h)
	if n, note := h.Name(netip.MustParseAddr("192.0.2.1")), h.Note(netip.MustParseAddr("192.0.2.1")); n != "first" || note != "n1 once" {
		t.Fatalf("first answers: %q %q", n, note)
	}
	time.Sleep(200 * time.Millisecond)
	if got := h.Note(netip.MustParseAddr("192.0.2.1")); got != "n1 once" { // this draw starts the refresh
		t.Errorf("while refreshing: %q", got)
	}
	settle(t, h)
	if n, note := h.Name(netip.MustParseAddr("192.0.2.1")), h.Note(netip.MustParseAddr("192.0.2.1")); n != "first" || note != "n2 once" {
		t.Errorf("after the refresh: %q %q, want first and n2 once", n, note)
	}
	// an address nobody draws is not asked again
	h.Note(netip.MustParseAddr("192.0.2.2"))
	settle(t, h)
	time.Sleep(400 * time.Millisecond)
	h.mu.Lock()
	last := h.got[netip.MustParseAddr("192.0.2.2")].notes[0].Note
	h.mu.Unlock()
	if last != "n1" {
		t.Errorf("an address not drawn was refreshed: %q", last)
	}

	hopEvery = 10 * time.Millisecond
	h, _ = hopPlugins(t, "slowcount")
	for end := time.Now().Add(200 * time.Millisecond); time.Now().Before(end); time.Sleep(5 * time.Millisecond) {
		h.Note(netip.MustParseAddr("192.0.2.3"))
	}
	settle(t, h)
	h.mu.Lock()
	last = h.got[netip.MustParseAddr("192.0.2.3")].notes[0].Note
	h.mu.Unlock()
	if last != "n1" {
		t.Errorf("slow plugin: %q, want one request in flight (n1)", last)
	}
}

// A plugin separates the columns of its note with tabs, and they line up
// down the screen whatever the lengths; the JSON report has plain spaces.
func TestHopInfoColumns(t *testing.T) {
	h, _ := hopPlugins(t, "cols", "sites")
	addrs := []string{"192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4"}
	for _, a := range addrs {
		h.Note(netip.MustParseAddr(a))
	}
	settle(t, h)
	want := map[string]string{
		"192.0.2.1": "Port-Channel37 err:0     site 1",
		"192.0.2.2": "Vlan754        err:12 +3 site 2",
		"192.0.2.3": "Ethernet1/1              site 3",
		"192.0.2.4": "               crc:5     site 4",
	}
	for _, a := range addrs {
		if got := h.Note(netip.MustParseAddr(a)); got != want[a] {
			t.Errorf("%s:\n got %q\nwant %q", a, got, want[a])
		}
	}
	if w := h.width(); w != len(want["192.0.2.1"]) {
		t.Errorf("column width %d, want %d", w, len(want["192.0.2.1"]))
	}
	if got := h.All()[netip.MustParseAddr("192.0.2.2")]["cols"].Note; got != "Vlan754 err:12 +3" {
		t.Errorf("JSON note %q", got)
	}
}
