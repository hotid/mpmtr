package main

import (
	"context"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"
)

// agent is a minimal SNMPv2c agent on addr: it answers GETs for the OIDs in
// vals when the community matches, and counts every packet it receives.
// asked collects every OID any test agent was asked for.
var asked sync.Map

func agent(t *testing.T, addr, community string, vals map[string]any) (port uint16, packets *atomic.Int64) {
	t.Helper()
	c, err := net.ListenPacket("udp", addr+":0")
	if err != nil {
		t.Skipf("cannot listen on %s: %v", addr, err)
	}
	t.Cleanup(func() { c.Close() })
	packets = new(atomic.Int64)
	go func() {
		dec := &gosnmp.GoSNMP{Version: gosnmp.Version2c, Logger: gosnmp.Logger{}}
		buf := make([]byte, 65535)
		for {
			n, from, err := c.ReadFrom(buf)
			if err != nil {
				return
			}
			packets.Add(1)
			req, err := dec.SnmpDecodePacket(buf[:n])
			if err == nil {
				for _, v := range req.Variables {
					asked.Store(v.Name, true)
				}
			}
			if err != nil || req.Community != community || req.PDUType != gosnmp.GetRequest {
				continue
			}
			resp := &gosnmp.SnmpPacket{Version: gosnmp.Version2c, Community: community, PDUType: gosnmp.GetResponse,
				RequestID: req.RequestID}
			for _, v := range req.Variables {
				switch x := vals[v.Name].(type) {
				case string:
					resp.Variables = append(resp.Variables, gosnmp.SnmpPDU{Name: v.Name, Type: gosnmp.OctetString, Value: x})
				case int:
					resp.Variables = append(resp.Variables, gosnmp.SnmpPDU{Name: v.Name, Type: gosnmp.Integer, Value: x})
				case *atomic.Uint32: // a counter the test changes between requests
					resp.Variables = append(resp.Variables, gosnmp.SnmpPDU{Name: v.Name, Type: gosnmp.Counter32, Value: uint(x.Load())})
				default:
					resp.Variables = append(resp.Variables, gosnmp.SnmpPDU{Name: v.Name, Type: gosnmp.NoSuchInstance})
				}
			}
			if b, err := resp.MarshalMsg(); err == nil {
				c.WriteTo(b, from)
			}
		}
	}()
	return uint16(c.LocalAddr().(*net.UDPAddr).Port), packets
}

func rulesFor(t *testing.T, conf string) []rule {
	t.Helper()
	r, err := parseConfig(conf)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// The device's name and the interface that owns the asked address, from the
// IPv4-only table and from the version-neutral one.
func TestLookup(t *testing.T) {
	for _, tc := range []struct {
		name string
		oid  string
	}{
		{"ipAddrTable", oidIPAdEntIf + ".127.0.0.1"},
		{"ipAddressTable", oidIPAddressIf + ".1.4.127.0.0.1"},
	} {
		port, _ := agent(t, "127.0.0.1", "s3cret", map[string]any{
			oidSysName: "core1.example", tc.oid: 436207616,
			oidIfName + ".436207616": "Ethernet1/2", oidIfAlias + ".436207616": "to spine 3",
		})
		rules := rulesFor(t, "127.0.0.1/32 community=s3cret timeout=500ms retries=0 port="+strconv.Itoa(int(port)))
		got := (&snmp{rules: rules, descr: false}).lookup(context.Background(), netip.MustParseAddr("127.0.0.1"))
		if got.Name != "core1.example" || got.Note != "Ethernet1/2" {
			t.Errorf("%s: got %+v", tc.name, got)
		}
		got = (&snmp{rules: rules, descr: true}).lookup(context.Background(), netip.MustParseAddr("127.0.0.1"))
		if got.Name != "core1.example" || got.Note != "Ethernet1/2\t«to spine 3»" {
			t.Errorf("%s with the description: got %+v", tc.name, got)
		}
	}
	// the name alone, when the device does not tell the interface
	port, _ := agent(t, "127.0.0.1", "s3cret", map[string]any{oidSysName: "edge7"})
	rules := rulesFor(t, "127.0.0.1 community=s3cret timeout=500ms retries=0 port="+strconv.Itoa(int(port)))
	if got := (&snmp{rules: rules, descr: true}).lookup(context.Background(), netip.MustParseAddr("127.0.0.1")); got.Name != "edge7" || got.Note != "" {
		t.Errorf("name only: got %+v", got)
	}
}

// The safety property: an address that no prefix allows never gets a
// packet, although a device is listening there on the same port.
func TestAddressOutsidePrefixesIsNeverAsked(t *testing.T) {
	port, packets := agent(t, "127.0.0.2", "s3cret", map[string]any{oidSysName: "not-yours"})
	rules := rulesFor(t, "127.0.0.1/32 community=s3cret timeout=300ms retries=0 port="+strconv.Itoa(int(port))+
		"\n192.0.2.0/24 community=other")
	if got := (&snmp{rules: rules, descr: true}).lookup(context.Background(), netip.MustParseAddr("127.0.0.2")); got.Name != "" || got.Note != "" {
		t.Errorf("answer for an address outside the prefixes: %+v", got)
	}
	time.Sleep(100 * time.Millisecond)
	if n := packets.Load(); n != 0 {
		t.Fatalf("%d packets sent to an address outside the prefixes", n)
	}
	// the control: the same agent is asked once its address is allowed
	rules = rulesFor(t, "127.0.0.0/8 community=s3cret timeout=300ms retries=0 port="+strconv.Itoa(int(port)))
	if got := (&snmp{rules: rules, descr: true}).lookup(context.Background(), netip.MustParseAddr("127.0.0.2")); got.Name != "not-yours" {
		t.Fatalf("allowed address: got %+v", got)
	}
}

// A wrong community gets no answer: nothing is shown, and nothing hangs.
func TestNoAnswer(t *testing.T) {
	port, _ := agent(t, "127.0.0.1", "right", map[string]any{oidSysName: "core1"})
	rules := rulesFor(t, "127.0.0.1 community=wrong timeout=200ms retries=1 port="+strconv.Itoa(int(port)))
	start := time.Now()
	if got := (&snmp{rules: rules, descr: true}).lookup(context.Background(), netip.MustParseAddr("127.0.0.1")); got.Name != "" {
		t.Errorf("got %+v", got)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("took %v", d)
	}
}

func TestConfig(t *testing.T) {
	rules := rulesFor(t, `
# comment
10.0.0.0/8      community=public
10.1.0.0/16     user=mon auth=sha256:authpass1 priv=aes:privpass1 port=1161
2001:db8::/32   user=ro
`)
	for addr, want := range map[string]string{"10.2.3.4": "public", "10.1.2.3": "mon", "2001:db8::1": "ro", "192.0.2.1": ""} {
		r, ok := match(rules, netip.MustParseAddr(addr))
		if got := r.community + r.user; got != want || ok != (want != "") {
			t.Errorf("%s: matched %q (%v), want %q", addr, got, ok, want)
		}
	}
	if r, _ := match(rules, netip.MustParseAddr("10.1.2.3")); r.port != 1161 || r.authProto != gosnmp.SHA256 || r.privProto != gosnmp.AES {
		t.Errorf("v3 rule: %+v", r)
	}
	for _, bad := range []string{
		"", "# only a comment", "10.0.0.0/8", "nonsense community=x", "10.0.0.0/8 community=x user=y",
		"10.0.0.0/8 user=y priv=aes:privpass1", "10.0.0.0/8 user=y auth=sha:short", "10.0.0.0/8 user=y auth=rot13:password1",
		"10.0.0.0/8 community=x colour=blue", "10.0.0.0/8 community=x timeout=1h", "10.0.0.0/8 community",
	} {
		if _, err := parseConfig(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

// A file that others can read holds no secret: refuse it.
func TestConfigFileMode(t *testing.T) {
	p := filepath.Join(t.TempDir(), "snmp.conf")
	if err := os.WriteFile(p, []byte("10.0.0.0/8 community=public\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(p); err == nil || !strings.Contains(err.Error(), "chmod 600") {
		t.Fatalf("world-readable file: %v", err)
	}
	os.Chmod(p, 0o600)
	if _, err := loadConfig(p); err != nil {
		t.Fatal(err)
	}
}

func TestAddrIndex(t *testing.T) {
	if got := addrIndex(netip.MustParseAddr("10.1.2.3"), false); got != "10.1.2.3" {
		t.Error(got)
	}
	if got := addrIndex(netip.MustParseAddr("10.1.2.3"), true); got != "1.4.10.1.2.3" {
		t.Error(got)
	}
	if got := addrIndex(netip.MustParseAddr("2001:db8::1"), true); got != "2.16.32.1.13.184.0.0.0.0.0.0.0.0.0.0.0.1" {
		t.Error(got)
	}
}

// --errors: the checksum errors of the interface, or all its input errors
// where it has no such counter, with the growth since the first look; a
// counter that went back restarts the count. Without the flag the counters
// are not asked at all.
func TestErrors(t *testing.T) {
	const idx = ".77"
	asked.Clear()
	addr := netip.MustParseAddr("127.0.0.1")
	fcs, in := new(atomic.Uint32), new(atomic.Uint32)
	fcs.Store(1532)
	in.Store(40)
	base := map[string]any{oidSysName: "core1", oidIPAdEntIf + ".127.0.0.1": 77, oidIfName + idx: "Ethernet51/1", oidIfAlias + idx: "to spine"}
	with := func(extra map[string]any) []rule {
		vals := map[string]any{}
		for k, v := range base {
			vals[k] = v
		}
		for k, v := range extra {
			vals[k] = v
		}
		port, _ := agent(t, "127.0.0.1", "s3cret", vals)
		return rulesFor(t, "127.0.0.1 community=s3cret timeout=500ms retries=0 port="+strconv.Itoa(int(port)))
	}
	note := func(s *snmp) string { return s.lookup(context.Background(), addr).Note }

	// off: not asked
	off := &snmp{rules: with(map[string]any{oidFCSErrors + idx: fcs, oidIfInErrors + idx: in})}
	if got := note(off); got != "Ethernet51/1" {
		t.Errorf("without --errors: %q", got)
	}
	for _, oid := range []string{oidFCSErrors + idx, oidIfInErrors + idx} {
		if _, was := asked.Load(oid); was {
			t.Errorf("%s asked without --errors", oid)
		}
	}

	// the checksum counter, then its growth, then a restart
	s := &snmp{rules: off.rules, errors: true, descr: true}
	if got := note(s); got != "Ethernet51/1\t«to spine»\tcrc:1532" {
		t.Errorf("first look: %q", got)
	}
	if got := note(s); got != "Ethernet51/1\t«to spine»\tcrc:1532" {
		t.Errorf("unchanged: %q", got)
	}
	fcs.Store(1544)
	if got := note(s); got != "Ethernet51/1\t«to spine»\tcrc:1544 +12" {
		t.Errorf("grown: %q", got)
	}
	fcs.Store(3)
	if got := note(s); got != "Ethernet51/1\t«to spine»\tcrc:3" {
		t.Errorf("counter went back: %q", got)
	}
	fcs.Store(5)
	if got := note(s); got != "Ethernet51/1\t«to spine»\tcrc:5 +2" {
		t.Errorf("after the restart: %q", got)
	}

	// no checksum counter on this interface: all input errors
	s = &snmp{rules: with(map[string]any{oidIfInErrors + idx: in}), errors: true}
	if got := note(s); got != "Ethernet51/1\terr:40" {
		t.Errorf("no FCS counter: %q", got)
	}
	in.Store(41)
	if got := note(s); got != "Ethernet51/1\terr:41 +1" {
		t.Errorf("no FCS counter, grown: %q", got)
	}

	// neither: the name alone
	s = &snmp{rules: with(nil), errors: true}
	if got := note(s); got != "Ethernet51/1" {
		t.Errorf("no counters: %q", got)
	}
}
