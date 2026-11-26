package enrich

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeWhois answers like whois.cymru.com in bulk verbose mode and records
// the addresses it was asked about.
func fakeWhois(t *testing.T, db map[string]string) (string, func() []string) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	var mu sync.Mutex
	var asked []string
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				sc := bufio.NewScanner(c)
				fmt.Fprintln(c, "Bulk mode; whois.cymru.com [2026-11-24 10:17:51 +0000]")
				for sc.Scan() {
					q := strings.TrimSpace(sc.Text())
					if q == "begin" || q == "verbose" {
						continue
					}
					if q == "end" {
						return
					}
					mu.Lock()
					asked = append(asked, q)
					mu.Unlock()
					if line, ok := db[q]; ok {
						fmt.Fprintln(c, line)
					} else {
						fmt.Fprintf(c, "NA      | %-16s | NA                  |    | other    |            | NA\n", q)
					}
				}
			}(c)
		}
	}()
	return l.Addr().String(), func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), asked...)
	}
}

func TestASNWhoisBulk(t *testing.T) {
	srv, asked := fakeWhois(t, map[string]string{
		"8.8.8.8":              "15169   | 8.8.8.8          | 8.8.8.0/24          | US | arin     | 2023-12-28 | GOOGLE - Google LLC, US",
		"2001:4860:4860::8888": "15169   | 2001:4860:4860::8888                     | 2001:4860::/32      | US | arin     | 2005-03-14 | GOOGLE - Google LLC, US",
	})
	e, err := New(Options{ASN: true, Whois: srv})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	for _, ip := range []string{"8.8.8.8", "2001:4860:4860::8888", "1.1.1.1", "10.1.2.3", "100.64.0.1", "192.168.10.1", "fe80::1", "198.51.100.7"} {
		e.Note(netip.MustParseAddr(ip))
	}
	e.Settle(5 * time.Second)
	if n := e.Note(netip.MustParseAddr("8.8.8.8")); n != "AS15169 GOOGLE" {
		t.Fatalf("note %q", n)
	}
	if n := e.Note(netip.MustParseAddr("2001:4860:4860::8888")); n != "AS15169 GOOGLE" {
		t.Fatalf("v6 note %q", n)
	}
	if n := e.Note(netip.MustParseAddr("1.1.1.1")); n != "" {
		t.Fatalf("unannounced address noted %q", n)
	}
	got := strings.Join(asked(), ",")
	if got != "8.8.8.8,2001:4860:4860::8888,1.1.1.1" {
		t.Fatalf("whois was asked about %s (private/shared/documentation addresses must never be sent)", got)
	}
	if in := e.All()[netip.MustParseAddr("8.8.8.8")]; in.Prefix != "8.8.8.0/24" || in.ASName != "GOOGLE - Google LLC, US" {
		t.Fatalf("info %+v", in)
	}
	e.Note(netip.MustParseAddr("8.8.8.8"))
	e.Settle(time.Second)
	if len(asked()) != 3 {
		t.Fatal("an address was looked up twice")
	}
}

func TestShortASName(t *testing.T) {
	for in, want := range map[string]string{
		"GOOGLE - Google LLC, US":               "GOOGLE",
		"CLOUDFLARENET, US":                     "CLOUDFLARENET",
		"Google LLC":                            "Google LLC",
		"TATA COMMUNICATIONS (AMERICA) INC, US": "TATA COMMUNICATIONS (AM…",
		"":                                      "",
	} {
		if got := shortASName(in); got != want {
			t.Errorf("%q -> %q, want %q", in, got, want)
		}
	}
}

func TestIXPeeringDB(t *testing.T) {
	var hits atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		switch r.URL.Path {
		case "/ix":
			fmt.Fprint(w, `{"data":[{"id":31,"name":"DE-CIX Frankfurt"},{"id":7,"name":"MSK-IX Moscow"}]}`)
		case "/ixlan":
			fmt.Fprint(w, `{"data":[{"id":31,"ix_id":31},{"id":8,"ix_id":7}]}`)
		case "/ixpfx":
			fmt.Fprint(w, `{"data":[{"prefix":"80.81.192.0/21","ixlan_id":31},{"prefix":"2001:7f8::/64","ixlan_id":31},{"prefix":"195.208.208.0/21","ixlan_id":8}]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()
	dir := t.TempDir()
	e, err := New(Options{IX: true, PDB: ts.URL, CacheDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	e.Settle(5 * time.Second)
	if n := e.Note(netip.MustParseAddr("80.81.194.12")); n != "IX:DE-CIX Frankfurt" {
		t.Fatalf("note %q", n)
	}
	if n := e.Note(netip.MustParseAddr("2001:7f8::1b1b:0:1")); n != "IX:DE-CIX Frankfurt" {
		t.Fatalf("v6 note %q", n)
	}
	if n := e.Note(netip.MustParseAddr("195.208.210.1")); n != "IX:MSK-IX Moscow" {
		t.Fatalf("note %q", n)
	}
	if n := e.Note(netip.MustParseAddr("8.8.8.8")); n != "" {
		t.Fatalf("non-IX address noted %q", n)
	}
	e.Close()
	if _, err := os.Stat(filepath.Join(dir, "peeringdb-ix.json")); err != nil {
		t.Fatal("no cache written")
	}
	// A fresh cache is used without asking PeeringDB again.
	before := hits.Load()
	e2, _ := New(Options{IX: true, PDB: ts.URL, CacheDir: dir})
	defer e2.Close()
	e2.Settle(5 * time.Second)
	if hits.Load() != before {
		t.Fatal("fresh cache ignored")
	}
	if n := e2.Note(netip.MustParseAddr("80.81.194.12")); n != "IX:DE-CIX Frankfurt" {
		t.Fatalf("from cache: %q", n)
	}
}

func TestPublic(t *testing.T) {
	for s, want := range map[string]bool{
		"8.8.8.8": true, "2a00:1450::1": true, "::ffff:8.8.8.8": true,
		"10.0.0.1": false, "172.16.100.1": false, "192.168.1.1": false, "100.100.1.1": false,
		"127.0.0.1": false, "169.254.1.1": false, "192.0.2.1": false, "198.18.0.1": false,
		"fd00::1": false, "fe80::1": false, "2001:db8::1": false, "224.0.0.1": false,
	} {
		if got := Public(netip.MustParseAddr(s)); got != want {
			t.Errorf("Public(%s) = %v", s, got)
		}
	}
}

// The nil Enricher (no source enabled) knows nothing and never panics.
func TestNilEnricher(t *testing.T) {
	var e *Enricher
	if e.Note(netip.MustParseAddr("8.8.8.8")) != "" || e.All() != nil {
		t.Fatal("nil enricher answered")
	}
	e.Settle(time.Second)
	e.Close()
}

// Offline GeoIP/ASN from real .mmdb files (MaxMind GeoLite2, DB-IP lite):
// MPMTR_TEST_MMDB=country.mmdb,asn.mmdb go test ./internal/enrich
func TestMMDBFiles(t *testing.T) {
	files := os.Getenv("MPMTR_TEST_MMDB")
	if files == "" {
		t.Skip("MPMTR_TEST_MMDB not set")
	}
	e, err := New(Options{MMDB: strings.Split(files, ",")})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	for _, ip := range []string{"8.8.8.8", "2001:4860:4860::8888", "209.85.241.201", "77.88.8.8", "10.1.1.1"} {
		in, _ := e.Lookup(netip.MustParseAddr(ip))
		t.Logf("%-22s %q %+v", ip, e.Note(netip.MustParseAddr(ip)), in)
	}
	if in, _ := e.Lookup(netip.MustParseAddr("8.8.8.8")); in.Country == "" && in.ASN == 0 {
		t.Fatal("8.8.8.8 not found in the databases")
	}
	if n := e.Note(netip.MustParseAddr("10.1.1.1")); n != "" {
		t.Fatalf("private address noted %q", n)
	}
}
