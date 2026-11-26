// Package enrich annotates hop addresses with the network they belong to:
// the origin AS (Team Cymru whois, or an offline ASN .mmdb), the Internet
// exchange whose peering LAN the address is on (PeeringDB, cached) and the
// country/city (an offline GeoIP .mmdb such as MaxMind GeoLite2 or DB-IP
// lite). Every source is off unless asked for. Lookups run in the
// background; Note returns "" until an answer is in. Private, shared and
// documentation addresses are never sent anywhere.
package enrich

import (
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/oschwald/maxminddb-golang/v2"
)

// Info is what is known about one address.
type Info struct {
	ASN     uint32 `json:"asn,omitempty"`
	ASName  string `json:"as_name,omitempty"`
	Prefix  string `json:"prefix,omitempty"`
	IX      string `json:"ix,omitempty"`
	Country string `json:"country,omitempty"`
	City    string `json:"city,omitempty"`
}

func (i Info) empty() bool { return i == Info{} }

// Options selects the sources.
type Options struct {
	ASN      bool     // Team Cymru whois (sends public hop addresses to it)
	IX       bool     // PeeringDB IX peering LAN prefixes
	MMDB     []string // offline .mmdb files: GeoIP (country/city) and/or ASN
	CacheDir string   // for the PeeringDB data ("" = no cache)
	Whois    string   // whois server (default whois.cymru.com:43)
	PDB      string   // PeeringDB API base (default https://www.peeringdb.com/api)
	Warn     func(string)
}

// Enricher looks addresses up. The zero of *Enricher (nil) knows nothing.
type Enricher struct {
	opt  Options
	dbs  []*maxminddb.Reader
	mu   sync.Mutex
	info map[netip.Addr]Info
	seen map[netip.Addr]bool
	asnQ []netip.Addr
	busy int // whois batches in flight
	kick chan struct{}
	ix   *ixTable
	stop chan struct{}
	warn sync.Map // warnings already given
}

// New opens the .mmdb files and starts the background sources.
func New(o Options) (*Enricher, error) {
	if o.Whois == "" {
		o.Whois = "whois.cymru.com:43"
	}
	if o.PDB == "" {
		o.PDB = "https://www.peeringdb.com/api"
	}
	e := &Enricher{opt: o, info: map[netip.Addr]Info{}, seen: map[netip.Addr]bool{},
		kick: make(chan struct{}, 1), stop: make(chan struct{})}
	for _, f := range o.MMDB {
		db, err := maxminddb.Open(f)
		if err != nil {
			e.Close()
			return nil, err
		}
		e.dbs = append(e.dbs, db)
	}
	if o.ASN {
		go e.asnWorker()
	}
	if o.IX {
		e.ix = &ixTable{}
		go e.loadIX()
	}
	return e, nil
}

// Close stops the workers and closes the databases.
func (e *Enricher) Close() {
	if e == nil {
		return
	}
	select {
	case <-e.stop:
	default:
		close(e.stop)
	}
	for _, db := range e.dbs {
		db.Close()
	}
}

func (e *Enricher) warnOnce(key, msg string) {
	if _, dup := e.warn.LoadOrStore(key, true); !dup && e.opt.Warn != nil {
		e.opt.Warn(msg)
	}
}

// Public reports whether an address may be looked up externally: global
// unicast, not private, shared (CGNAT), benchmarking, documentation or
// reserved space.
func Public(a netip.Addr) bool {
	a = a.Unmap()
	if !a.IsGlobalUnicast() || a.IsPrivate() {
		return false
	}
	for _, p := range special {
		if p.Contains(a) {
			return false
		}
	}
	return true
}

var special = func() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range []string{"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24",
		"198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4",
		"2001:db8::/32", "3fff::/20", "2001::/23", "64:ff9b:1::/48", "100::/64"} {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()

// Lookup returns what is known about ip so far and queues the lookups not
// yet made.
func (e *Enricher) Lookup(a netip.Addr) (Info, bool) {
	if e == nil || !a.IsValid() {
		return Info{}, false
	}
	a = a.Unmap()
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.seen[a] {
		e.seen[a] = true
		e.info[a] = e.offline(a)
		if e.opt.ASN && Public(a) && e.info[a].ASN == 0 {
			e.asnQ = append(e.asnQ, a)
			select {
			case e.kick <- struct{}{}:
			default:
			}
		}
	}
	in := e.info[a]
	if e.ix != nil && in.IX == "" {
		in.IX = e.ix.find(a)
	}
	return in, !in.empty()
}

// offline answers from the .mmdb files.
func (e *Enricher) offline(a netip.Addr) Info {
	var in Info
	for _, db := range e.dbs {
		var r struct {
			ASN     uint32 `maxminddb:"autonomous_system_number"`
			ASOrg   string `maxminddb:"autonomous_system_organization"`
			Country struct {
				ISO string `maxminddb:"iso_code"`
			} `maxminddb:"country"`
			City struct {
				Names map[string]string `maxminddb:"names"`
			} `maxminddb:"city"`
		}
		res := db.Lookup(a)
		if !res.Found() || res.Decode(&r) != nil {
			continue
		}
		if in.ASN == 0 && r.ASN != 0 {
			in.ASN, in.ASName = r.ASN, r.ASOrg
			if p := res.Prefix(); p.IsValid() {
				in.Prefix = p.String()
			}
		}
		if in.Country == "" {
			in.Country = r.Country.ISO
		}
		if in.City == "" {
			in.City = r.City.Names["en"]
		}
	}
	return in
}

// Note is the short annotation of ip for a hop row: "AS15169 GOOGLE
// IX:DE-CIX Frankfurt (DE, Frankfurt am Main)"; "" if nothing is known
// (yet).
func (e *Enricher) Note(ip netip.Addr) string {
	in, ok := e.Lookup(ip)
	if !ok {
		return ""
	}
	var p []string
	if in.ASN != 0 {
		s := "AS" + strconv.FormatUint(uint64(in.ASN), 10)
		if n := shortASName(in.ASName); n != "" {
			s += " " + n
		}
		p = append(p, s)
	}
	if in.IX != "" {
		p = append(p, "IX:"+in.IX)
	}
	if in.Country != "" {
		g := in.Country
		if in.City != "" {
			g += ", " + in.City
		}
		p = append(p, "("+g+")")
	}
	return printable(strings.Join(p, " "))
}

// printable drops control characters: the names come from whois servers,
// PeeringDB and database files, and go to a terminal.
func printable(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || (r >= 0x7f && r < 0xa0) {
			return -1
		}
		return r
	}, s)
}

// shortASName keeps the handle of a registry AS name: "GOOGLE - Google
// LLC, US" -> "GOOGLE", "Google LLC" stays, at most 24 characters.
func shortASName(s string) string {
	if i := strings.Index(s, " - "); i > 0 {
		s = s[:i]
	} else if i := strings.LastIndex(s, ", "); i > 0 && len(s)-i == 4 {
		s = s[:i] // trailing ", CC"
	}
	s = strings.TrimSpace(s)
	if r := []rune(s); len(r) > 24 {
		s = string(r[:23]) + "…"
	}
	return s
}

// All returns every address with something known, for the JSON report.
func (e *Enricher) All() map[netip.Addr]Info {
	if e == nil {
		return nil
	}
	e.mu.Lock()
	addrs := make([]netip.Addr, 0, len(e.info))
	for a := range e.info {
		addrs = append(addrs, a)
	}
	e.mu.Unlock()
	out := map[netip.Addr]Info{}
	for _, a := range addrs {
		if in, ok := e.Lookup(a); ok {
			out[a] = in
		}
	}
	return out
}

// Settle waits until the queued lookups are answered (or failed), at most d.
func (e *Enricher) Settle(d time.Duration) {
	if e == nil {
		return
	}
	end := time.Now().Add(d)
	for time.Now().Before(end) {
		e.mu.Lock()
		idle := len(e.asnQ) == 0 && e.busy == 0
		e.mu.Unlock()
		if idle && (e.ix == nil || e.ix.ready()) {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
}
