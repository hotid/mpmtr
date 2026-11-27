package enrich

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// asnWorker sends the queued addresses to the Team Cymru whois in bulk:
// one TCP connection per batch, "begin / verbose / addresses / end".
func (e *Enricher) asnWorker() {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	tries := map[netip.Addr]int{}
	for {
		select {
		case <-e.stop:
			return
		case <-e.kick:
			time.Sleep(200 * time.Millisecond) // let a trace's hops gather into one batch
		case <-t.C:
		}
		e.mu.Lock()
		n := min(len(e.asnQ), 500)
		batch := append([]netip.Addr(nil), e.asnQ[:n]...)
		e.asnQ = e.asnQ[n:]
		if n > 0 {
			e.busy++
		}
		e.mu.Unlock()
		if n == 0 {
			continue
		}
		got, err := whoisBulk(e.opt.Whois, batch)
		e.mu.Lock()
		e.busy--
		for _, a := range batch {
			if r, ok := got[a]; ok {
				in := e.info[a]
				in.ASN, in.ASName, in.Prefix = r.ASN, r.ASName, r.Prefix
				e.info[a] = in
				delete(tries, a)
			} else if err != nil {
				if tries[a]++; tries[a] < 3 {
					e.asnQ = append(e.asnQ, a) // retried on a later tick
				}
			}
		}
		e.mu.Unlock()
		if err != nil {
			e.warnOnce("whois", "asn: "+e.opt.Whois+": "+err.Error())
		}
	}
}

// whoisBulk queries a Team Cymru style bulk whois. Answer lines are
// "AS | IP | BGP prefix | CC | registry | allocated | AS name"; "NA" in the
// AS column means the address is not announced.
func whoisBulk(server string, addrs []netip.Addr) (map[netip.Addr]Info, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var d net.Dialer
	c, err := d.DialContext(ctx, "tcp", server)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	dl, _ := ctx.Deadline()
	c.SetDeadline(dl)
	var b strings.Builder
	b.WriteString("begin\nverbose\n")
	for _, a := range addrs {
		b.WriteString(a.String() + "\n")
	}
	b.WriteString("end\n")
	if _, err := c.Write([]byte(b.String())); err != nil {
		return nil, err
	}
	out := map[netip.Addr]Info{}
	sc := bufio.NewScanner(c)
	for sc.Scan() {
		f := strings.Split(sc.Text(), "|")
		if len(f) < 7 {
			continue // the "Bulk mode; ..." banner
		}
		for i := range f {
			f[i] = strings.TrimSpace(f[i])
		}
		a, err := netip.ParseAddr(f[1])
		if err != nil {
			continue
		}
		var in Info
		if asn, err := strconv.ParseUint(f[0], 10, 32); err == nil {
			in.ASN, in.Prefix, in.ASName = uint32(asn), f[2], f[6]
		}
		out[a.Unmap()] = in // NA: answered, nothing announced
	}
	if err := sc.Err(); err != nil && len(out) == 0 {
		return nil, err
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no answer")
	}
	return out, nil
}

// ixTable holds the IX peering LAN prefixes, longest first, and the
// addresses the IX members have on those LANs.
type ixTable struct {
	mu      sync.Mutex
	done    bool
	pfx     []ixPrefix
	members map[netip.Addr]ixMember
}

type ixPrefix struct {
	P  netip.Prefix `json:"p"`
	IX string       `json:"ix"`
}

// ixMember is one address of an IX member on a peering LAN (PeeringDB
// netixlan): the router there belongs to that network, not to the IX.
type ixMember struct {
	IP   netip.Addr `json:"ip"`
	ASN  uint32     `json:"asn"`
	Name string     `json:"name,omitempty"`
}

// ixHit is what the IX data says about one address.
type ixHit struct {
	IX     string
	Member ixMember // zero when the address is not a known member's
}

func (t *ixTable) ready() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.done
}

func (t *ixTable) set(p []ixPrefix, members []ixMember) {
	sort.Slice(p, func(i, j int) bool { return p[i].P.Bits() > p[j].P.Bits() })
	m := make(map[netip.Addr]ixMember, len(members))
	for _, x := range members {
		m[x.IP] = x
	}
	t.mu.Lock()
	t.pfx, t.members, t.done = p, m, true
	t.mu.Unlock()
}

func (t *ixTable) find(a netip.Addr) ixHit {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, p := range t.pfx {
		if p.P.Contains(a) {
			return ixHit{IX: p.IX, Member: t.members[a]}
		}
	}
	return ixHit{}
}

// ixCache is the file kept in the cache dir. Version is checked before the
// age: a cache written by another format is rebuilt (version 1, prefixes
// only, is read as a cache without members).
//
// Each list keeps when it was fetched and when a download of it last
// failed: PeeringDB throttles clients that ask often without an account
// (HTTP 429 for up to an hour), so a refused list is not asked again for
// ixRetry, and a list that came is kept for ixFresh even when the other
// one failed.
type ixCache struct {
	Version        int        `json:"version"`
	Source         string     `json:"source"`
	Fetched        time.Time  `json:"fetched"`        // the prefixes
	Tried          time.Time  `json:"tried,omitzero"` // last failed prefix download
	Err            string     `json:"err,omitempty"`  // and why
	Prefixes       []ixPrefix `json:"prefixes"`
	Members        []ixMember `json:"members,omitempty"`
	MembersFetched time.Time  `json:"members_fetched,omitzero"`
	MembersTried   time.Time  `json:"members_tried,omitzero"` // last failed member download
	MembersErr     string     `json:"members_err,omitempty"`
}

// Version 3: the member addresses (netixlan) and the failed attempts are
// kept as well.
const ixCacheVersion = 3

const (
	ixFresh = 24 * time.Hour // a list is downloaded again after this
	ixRetry = time.Hour      // a list PeeringDB refused is asked again after this
)

func (e *Enricher) ixCachePath() string {
	if e.opt.CacheDir == "" {
		return ""
	}
	return filepath.Join(e.opt.CacheDir, "peeringdb-ix.json")
}

// readIXCache returns the cache for this source, or an empty one.
func (e *Enricher) readIXCache() ixCache {
	empty := ixCache{Version: ixCacheVersion, Source: e.opt.PDB}
	p := e.ixCachePath()
	if p == "" {
		return empty
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return empty
	}
	var c ixCache
	if json.Unmarshal(b, &c) != nil || c.Source != e.opt.PDB {
		return empty
	}
	switch c.Version {
	case ixCacheVersion:
	case 1:
		c.Version, c.Members, c.MembersFetched, c.MembersTried, c.MembersErr = ixCacheVersion, nil, time.Time{}, time.Time{}, ""
	default:
		return empty
	}
	return c
}

func (e *Enricher) writeIXCache(c ixCache) {
	path := e.ixCachePath()
	if path == "" {
		return
	}
	b, _ := json.Marshal(c)
	if os.MkdirAll(filepath.Dir(path), 0o755) == nil {
		tmp := path + ".tmp"
		if os.WriteFile(tmp, b, 0o644) == nil {
			os.Rename(tmp, path)
		}
	}
}

// loadIX uses the cached lists younger than ixFresh and downloads the
// others from PeeringDB, unless a download of that list failed less than
// ixRetry ago. A list that cannot be had falls back to an older copy; IX
// hops are marked as long as the prefixes are known, with the member
// network only when the member list is too.
func (e *Enricher) loadIX() {
	c := e.readIXCache()
	now := time.Now()
	cl := &http.Client{Timeout: 30 * time.Second}
	changed := false
	due := func(fetched, tried time.Time) (ask, refused bool) {
		if now.Sub(fetched) < ixFresh {
			return false, false
		}
		if now.Sub(tried) < ixRetry {
			return false, true
		}
		return true, false
	}
	// What is used instead, and when PeeringDB is asked again.
	instead := func(fetched, tried time.Time, without string) string {
		s := "; asked again after " + tried.Add(ixRetry).Format("15:04")
		if fetched.IsZero() {
			return s + ": " + without
		}
		return s + "; using data from " + fetched.Format("2006-01-02")
	}
	const noIX, noMember = "IX hops are not marked", "IX hops are shown without the member network"

	switch ask, refused := due(c.Fetched, c.Tried); {
	case ask:
		changed = true
		if p, err := fetchIX(cl, e.opt.PDB); err == nil {
			c.Prefixes, c.Fetched, c.Tried, c.Err = p, now, time.Time{}, ""
		} else {
			c.Tried, c.Err = now, err.Error()
			e.warnOnce("ix", "ix: PeeringDB download failed ("+c.Err+")"+instead(c.Fetched, c.Tried, noIX))
		}
	case refused:
		e.warnOnce("ix", "ix: PeeringDB download failed at "+c.Tried.Format("15:04")+" ("+c.Err+")"+instead(c.Fetched, c.Tried, noIX))
	}
	if len(c.Prefixes) > 0 {
		switch ask, refused := due(c.MembersFetched, c.MembersTried); {
		case ask:
			changed = true
			if m, err := fetchIXMembers(cl, e.opt.PDB); err == nil {
				c.Members, c.MembersFetched, c.MembersTried, c.MembersErr = m, now, time.Time{}, ""
			} else {
				c.MembersTried, c.MembersErr = now, err.Error()
				e.warnOnce("ix-members", "ix: PeeringDB member list failed ("+c.MembersErr+")"+
					instead(c.MembersFetched, c.MembersTried, noMember))
			}
		case refused:
			e.warnOnce("ix-members", "ix: PeeringDB member list failed at "+c.MembersTried.Format("15:04")+" ("+c.MembersErr+")"+
				instead(c.MembersFetched, c.MembersTried, noMember))
		}
	}
	e.ix.set(c.Prefixes, c.Members)
	if changed {
		e.writeIXCache(c)
	}
}

// pdbGet fetches one PeeringDB API list into v.
func pdbGet(cl *http.Client, base, path string, v any) error {
	req, err := http.NewRequest("GET", base+"/"+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "mpmtr")
	r, err := cl.Do(req)
	if err != nil {
		return err
	}
	defer r.Body.Close()
	if r.StatusCode != 200 {
		// PeeringDB says why in a JSON "message" (HTTP 429: "Request was
		// throttled. Expected available in 55 minutes. …").
		var m struct {
			Message string `json:"message"`
		}
		why := ""
		if json.NewDecoder(io.LimitReader(r.Body, 4<<10)).Decode(&m) == nil && m.Message != "" {
			why = ": " + firstSentences(m.Message, 2)
		}
		name, _, _ := strings.Cut(path, "?")
		return fmt.Errorf("%s: HTTP %d%s", name, r.StatusCode, why)
	}
	return json.NewDecoder(io.LimitReader(r.Body, 64<<20)).Decode(v) // the lists are a few MB
}

// firstSentences is the first n sentences of s.
func firstSentences(s string, n int) string {
	for i, c := range s {
		if c == '.' && (i+1 == len(s) || s[i+1] == ' ') {
			if n--; n == 0 {
				return s[:i+1]
			}
		}
	}
	return s
}

// fetchIX joins PeeringDB's ixpfx (prefix -> ixlan), ixlan (-> ix) and ix
// (-> name) lists.
func fetchIX(cl *http.Client, base string) ([]ixPrefix, error) {
	var ixs struct {
		Data []struct {
			ID   int    `json:"id"`
			Name string `json:"name"`
		} `json:"data"`
	}
	var lans struct {
		Data []struct {
			ID   int `json:"id"`
			IXID int `json:"ix_id"`
		} `json:"data"`
	}
	var pfx struct {
		Data []struct {
			Prefix string `json:"prefix"`
			LAN    int    `json:"ixlan_id"`
		} `json:"data"`
	}
	if err := pdbGet(cl, base, "ix?fields=id,name", &ixs); err != nil {
		return nil, err
	}
	if err := pdbGet(cl, base, "ixlan?fields=id,ix_id", &lans); err != nil {
		return nil, err
	}
	if err := pdbGet(cl, base, "ixpfx?fields=prefix,ixlan_id", &pfx); err != nil {
		return nil, err
	}
	name := map[int]string{}
	for _, x := range ixs.Data {
		name[x.ID] = x.Name
	}
	lan := map[int]string{}
	for _, l := range lans.Data {
		lan[l.ID] = name[l.IXID]
	}
	var out []ixPrefix
	for _, p := range pfx.Data {
		pp, err := netip.ParsePrefix(p.Prefix)
		if err != nil || lan[p.LAN] == "" {
			continue
		}
		out = append(out, ixPrefix{P: pp.Masked(), IX: lan[p.LAN]})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no IX prefixes in the answer")
	}
	return out, nil
}

// fetchIXMembers joins PeeringDB's netixlan (member address on a peering
// LAN -> ASN) and net (ASN -> network name) lists.
func fetchIXMembers(cl *http.Client, base string) ([]ixMember, error) {
	var nixl struct {
		Data []struct {
			ASN uint32  `json:"asn"`
			IP4 *string `json:"ipaddr4"`
			IP6 *string `json:"ipaddr6"`
		} `json:"data"`
	}
	var nets struct {
		Data []struct {
			ASN  uint32 `json:"asn"`
			Name string `json:"name"`
		} `json:"data"`
	}
	if err := pdbGet(cl, base, "netixlan?fields=asn,ipaddr4,ipaddr6", &nixl); err != nil {
		return nil, err
	}
	if err := pdbGet(cl, base, "net?fields=asn,name", &nets); err != nil {
		return nil, err
	}
	name := make(map[uint32]string, len(nets.Data))
	for _, n := range nets.Data {
		name[n.ASN] = n.Name
	}
	var out []ixMember
	for _, x := range nixl.Data {
		if x.ASN == 0 {
			continue
		}
		for _, s := range []*string{x.IP4, x.IP6} {
			if s == nil {
				continue
			}
			if a, err := netip.ParseAddr(*s); err == nil {
				out = append(out, ixMember{IP: a.Unmap(), ASN: x.ASN, Name: name[x.ASN]})
			}
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no member addresses in the answer")
	}
	return out, nil
}
