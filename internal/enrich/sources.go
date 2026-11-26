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

// ixTable holds the IX peering LAN prefixes, longest first.
type ixTable struct {
	mu   sync.Mutex
	done bool
	pfx  []ixPrefix
}

type ixPrefix struct {
	P  netip.Prefix `json:"p"`
	IX string       `json:"ix"`
}

func (t *ixTable) ready() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.done
}

func (t *ixTable) set(p []ixPrefix) {
	sort.Slice(p, func(i, j int) bool { return p[i].P.Bits() > p[j].P.Bits() })
	t.mu.Lock()
	t.pfx, t.done = p, true
	t.mu.Unlock()
}

func (t *ixTable) find(a netip.Addr) string {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, p := range t.pfx {
		if p.P.Contains(a) {
			return p.IX
		}
	}
	return ""
}

// ixCache is the file kept in the cache dir. Version is checked before the
// age: a cache written by another format is rebuilt.
type ixCache struct {
	Version  int        `json:"version"`
	Source   string     `json:"source"`
	Fetched  time.Time  `json:"fetched"`
	Prefixes []ixPrefix `json:"prefixes"`
}

const ixCacheVersion = 1

func (e *Enricher) ixCachePath() string {
	if e.opt.CacheDir == "" {
		return ""
	}
	return filepath.Join(e.opt.CacheDir, "peeringdb-ix.json")
}

// loadIX uses a cached copy younger than a day, otherwise downloads the
// PeeringDB lists; a failed download falls back to an older cache.
func (e *Enricher) loadIX() {
	var cached *ixCache
	if p := e.ixCachePath(); p != "" {
		if b, err := os.ReadFile(p); err == nil {
			var c ixCache
			if json.Unmarshal(b, &c) == nil && c.Version == ixCacheVersion && c.Source == e.opt.PDB {
				cached = &c
			}
		}
	}
	if cached != nil && time.Since(cached.Fetched) < 24*time.Hour {
		e.ix.set(cached.Prefixes)
		return
	}
	p, err := fetchIX(e.opt.PDB)
	if err != nil {
		if cached != nil {
			e.ix.set(cached.Prefixes)
			e.warnOnce("ix", fmt.Sprintf("ix: PeeringDB download failed (%v); using data from %s", err, cached.Fetched.Format("2006-01-02")))
			return
		}
		e.ix.set(nil)
		e.warnOnce("ix", "ix: PeeringDB download failed: "+err.Error())
		return
	}
	e.ix.set(p)
	if path := e.ixCachePath(); path != "" {
		b, _ := json.Marshal(ixCache{Version: ixCacheVersion, Source: e.opt.PDB, Fetched: time.Now(), Prefixes: p})
		if os.MkdirAll(filepath.Dir(path), 0o755) == nil {
			tmp := path + ".tmp"
			if os.WriteFile(tmp, b, 0o644) == nil {
				os.Rename(tmp, path)
			}
		}
	}
}

// fetchIX joins PeeringDB's ixpfx (prefix -> ixlan), ixlan (-> ix) and ix
// (-> name) lists.
func fetchIX(base string) ([]ixPrefix, error) {
	cl := &http.Client{Timeout: 30 * time.Second}
	get := func(path string, v any) error {
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
			return fmt.Errorf("%s: HTTP %d", path, r.StatusCode)
		}
		return json.NewDecoder(io.LimitReader(r.Body, 64<<20)).Decode(v) // the lists are a few MB
	}
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
	if err := get("ix?fields=id,name", &ixs); err != nil {
		return nil, err
	}
	if err := get("ixlan?fields=id,ix_id", &lans); err != nil {
		return nil, err
	}
	if err := get("ixpfx?fields=prefix,ixlan_id", &pfx); err != nil {
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
