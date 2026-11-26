package core

import (
	"cmp"
	"fmt"
	"hash/fnv"
	"net/netip"
	"slices"
	"strings"
)

// Level of confidence of a PathGroup / a flow's membership.
type Level uint8

const (
	LevelUnresolved Level = iota
	LevelAmbiguous
	LevelTentative
	LevelPartialDistinct
	LevelConfirmed
)

type elemKind uint8

const (
	eUnknown  elemKind = iota // not enough observations
	eKnown                    // stable responder, >= 2 replies
	eSilent                   // >= 3 probes, no reply
	eUnstable                 // several responders (per-packet LB / flapping)
)

type hopElem struct {
	kind elemKind
	addr netip.Addr
}

func (e hopElem) String() string {
	switch e.kind {
	case eKnown:
		return e.addr.String()
	case eSilent:
		return "*"
	case eUnstable:
		return "~"
	}
	return "?"
}

// signature is the observed route signature of one flow.
type signature struct {
	hops      []hopElem // TTL 1..len
	distKnown bool      // destination confirmed at TTL len(hops)+1
	complete  bool
	known     int
	// assumed: TTLs whose router this port did not see itself. Its probe
	// there was not answered (or not sent, --shared-hops) and the router is
	// the one every other port saw there.
	assumed []TTL
	// elems is the canonical form of hops (finish): a hop that answers on
	// no route of the endpoint is silent whatever this flow saw there. canon
	// is elems as text ("a>b>*>DST"), for JSON and as a key; nothing reads
	// the route back out of it.
	elems []hopElem
	canon string
}

// elemOf classifies one hop observation.
func elemOf(h *HopStat) hopElem {
	if h == nil {
		return hopElem{}
	}
	if h.Unstable || h.multi() >= 2 {
		return hopElem{kind: eUnstable}
	}
	if h.cur.IsValid() && !h.isThrough(h.cur) && h.count(h.cur) >= 2 {
		return hopElem{kind: eKnown, addr: h.cur}
	}
	// One reply from the only responder seen: strict correlation (the quote
	// carries our SYN) makes it real evidence of that router at this TTL.
	// Waiting for a second reply costs a lot under ICMP rate limiting.
	var only netip.Addr
	n := 0
	h.responders(func(a netip.Addr, _ uint32) {
		only = a
		n++
	})
	if n == 1 {
		return hopElem{kind: eKnown, addr: only}
	}
	if n == 0 && h.through[0].IsValid() {
		return hopElem{} // only the next hop answered: who is here is not known
	}
	if h.onlyInferred() {
		return hopElem{kind: eKnown, addr: h.inferred}
	}
	if h.Replies == 0 && h.Timeouts >= 3 {
		return hopElem{kind: eSilent}
	}
	return hopElem{}
}

// onlyInferred: nothing answered this port at the hop, and the router there
// is known from the other ports alone (--shared-hops).
func (h *HopStat) onlyInferred() bool {
	if h.Unstable || !h.inferred.IsValid() || h.through[0].IsValid() {
		return false
	}
	n := 0
	h.responders(func(netip.Addr, uint32) { n++ })
	return n == 0
}

func computeSig(r *RouteObs) signature {
	var s signature
	L := r.maxReplied
	if r.distance > 0 {
		L = r.distance - 1
		s.distKnown = true
	} else if r.top() > L {
		L = r.top()
	}
	s.hops = make([]hopElem, L)
	for t := L; t >= 1; t-- {
		h := r.hopIf(t)
		s.hops[t-1] = elemOf(h)
		if s.hops[t-1].kind == eKnown {
			s.known++
			if h.onlyInferred() {
				s.assumed = append(s.assumed, t)
			}
		}
	}
	// Trailing silent/unknown hops after the last reply carry no topology
	// information when the destination was not reached.
	if !s.distKnown {
		for len(s.hops) > 0 && s.hops[len(s.hops)-1].kind != eKnown && s.hops[len(s.hops)-1].kind != eUnstable {
			s.hops = s.hops[:len(s.hops)-1]
		}
	}
	return s
}

func (s *signature) finish(universalSilent map[TTL]bool) {
	s.complete = s.distKnown
	s.elems = make([]hopElem, len(s.hops))
	var b strings.Builder
	for i, e := range s.hops {
		if i > 0 {
			b.WriteByte('>')
		}
		silentHere := (e.kind == eSilent || e.kind == eUnknown) && universalSilent[TTL(i+1)]
		if silentHere {
			e = hopElem{kind: eSilent}
		}
		s.elems[i] = e
		b.WriteString(e.String())
		switch {
		case e.kind == eKnown, silentHere:
		default:
			s.complete = false
		}
	}
	if s.distKnown {
		b.WriteString(">DST")
	} else {
		b.WriteString(">…")
	}
	s.canon = b.String()
}

// provenDifferent: a stable responder mismatch at one TTL, or confirmed
// different distances. Wildcards never prove anything.
func provenDifferent(a, b *signature) bool {
	n := min(len(a.hops), len(b.hops))
	for i := 0; i < n; i++ {
		x, y := a.hops[i], b.hops[i]
		if x.kind == eKnown && y.kind == eKnown && x.addr != y.addr {
			return true
		}
	}
	if a.distKnown && b.distKnown && len(a.hops) != len(b.hops) {
		return true
	}
	// One reached the destination at a TTL where the other has a stable
	// transit responder.
	if a.distKnown && len(b.hops) > len(a.hops) && b.hops[len(a.hops)].kind == eKnown {
		return true
	}
	if b.distKnown && len(a.hops) > len(b.hops) && a.hops[len(b.hops)].kind == eKnown {
		return true
	}
	return false
}

// GState is the aggregate state of a PathGroup.
type GState uint8

const (
	GUnknown GState = iota
	GOK
	GLoss
	GDown
)

// Group is a PathGroup: flows sharing an observed topology at a level.
type Group struct {
	ID             string
	Level          Level
	Sig            signature
	Members        []*Flow // full members (same canonical signature)
	Tentative      []*Flow // compatible with exactly this confirmed group
	State          GState
	Partial        bool // some, not all, monitored members failing
	Hetero         bool // INTRAGROUP_HETEROGENEITY
	emitted        GState
	incSeq         int
	problemEmitted bool
	Since          Mono
}

// measured returns the route's measured ports, full and tentative members
// alike: a tentative member fits only this route, and its end-to-end
// probes are as real as a full member's.
func (g *Group) measured() []*Flow {
	var out []*Flow
	for _, l := range [2][]*Flow{g.Members, g.Tentative} {
		for _, f := range l {
			if f.Role.Monitored() {
				out = append(out, f)
			}
		}
	}
	return out
}

// groupKey is what makes a route itself: how sure it is and its canonical
// signature. Routes are found by this, never by their short identifier.
type groupKey struct {
	level Level
	canon string
}

// groupID is the short identifier of a route for people and for JSON: 20
// bits of a hash of its key. Two routes can share it (with a few hundred
// routes some pair does every now and then), so it names a route only
// through uniqueGroupID.
func groupID(level Level, canon string) string {
	return fmt.Sprintf("G%05x", groupHash(level, canon)&0xfffff)
}

func groupHash(level Level, canon string) uint32 {
	h := fnv.New32a()
	fmt.Fprintf(h, "%d|%s", level, canon)
	return h.Sum32()
}

// uniqueGroupID is the identifier of a route: the short one, or, when
// another route of the endpoint was already given it, a longer one. used
// keeps every identifier given so far, so a route always gets the same.
func uniqueGroupID(k groupKey, used map[string]groupKey) string {
	free := func(id string) bool {
		o, taken := used[id]
		return !taken || o == k
	}
	id := groupID(k.level, k.canon)
	if !free(id) {
		id = fmt.Sprintf("G%08x", groupHash(k.level, k.canon))
	}
	for n := 2; !free(id); n++ {
		id = fmt.Sprintf("G%08x-%d", groupHash(k.level, k.canon), n)
	}
	used[id] = k
	return id
}

// regroup recomputes signatures and PathGroups of an endpoint. The result
// depends only on the set of observations, never on processing order.
func (c *Core) regroup(ep *Endpoint) {
	flows := make([]*Flow, 0, len(ep.Flows))
	for _, f := range ep.Flows {
		f.sig = signature{}
		f.group, f.level, f.fits = nil, LevelUnresolved, nil
		if f.invalid != ValidFlow {
			continue
		}
		f.sig = computeSig(f.route)
		if f.sig.known == 0 && !f.sig.distKnown {
			continue
		}
		flows = append(flows, f)
	}
	// The same rule (see HopStat.through) with the evidence of the other
	// ports, for a port that lost answers: it shows, at some TTL, a router
	// that other ports know at a later TTL, and has no router of its own at
	// that later TTL to tell otherwise. The position stays open.
	farthest := map[netip.Addr]int{}
	for _, f := range flows {
		for i, e := range f.sig.hops {
			if e.kind == eKnown && i > farthest[e.addr] {
				farthest[e.addr] = i
			}
		}
	}
	for _, f := range flows {
		h := f.sig.hops
		for i := len(h) - 1; i >= 0; i-- { // far end first: a position opened here opens the earlier ones
			j := farthest[h[i].addr]
			if h[i].kind != eKnown || j <= i {
				continue
			}
			if (j < len(h) && h[j].kind == eKnown) || (j >= len(h) && f.sig.distKnown) {
				continue // this port's own path says who is there
			}
			h[i] = hopElem{}
			f.sig.known--
		}
		if !f.sig.distKnown {
			for len(h) > 0 && h[len(h)-1].kind != eKnown && h[len(h)-1].kind != eUnstable {
				h = h[:len(h)-1]
			}
			f.sig.hops = h
		}
	}
	// TTLs at which nobody has a responder: silence there is shared by all
	// observed routes and does not make a signature incomplete (with one
	// try per such TTL a port may have a single timeout there).
	maxL := TTL(0)
	for _, f := range flows {
		maxL = max(maxL, TTL(len(f.sig.hops)))
	}
	universal := map[TTL]bool{}
	for t := TTL(1); t <= maxL; t++ {
		anyKnown, anySilent := false, false
		for _, f := range flows {
			if t <= TTL(len(f.sig.hops)) {
				switch f.sig.hops[t-1].kind {
				case eKnown, eUnstable:
					anyKnown = true
				case eSilent, eUnknown:
					anySilent = true
				}
			}
		}
		if anySilent && !anyKnown {
			universal[t] = true
		}
	}
	// TTLs where every port that got an answer saw the same single router
	// (>= 3 ports): a port whose probe there was not answered (ICMP rate
	// limiting) is taken to pass the same router. A TTL with two different
	// routers is never filled.
	sole := map[int]netip.Addr{}
	soleN := map[int]int{}
	multi := map[int]bool{}
	for _, f := range flows {
		for i, e := range f.sig.hops {
			if e.kind != eKnown {
				continue
			}
			if a, ok := sole[i]; ok && a != e.addr {
				multi[i] = true
			}
			sole[i] = e.addr
			soleN[i]++
		}
	}
	for _, f := range flows {
		for i, e := range f.sig.hops {
			if (e.kind == eUnknown || e.kind == eSilent) && !multi[i] && soleN[i] >= 3 {
				f.sig.hops[i] = hopElem{kind: eKnown, addr: sole[i]}
				f.sig.known++
				f.sig.assumed = append(f.sig.assumed, TTL(i+1))
			}
		}
	}
	for _, f := range flows {
		slices.Sort(f.sig.assumed)
		f.sig.finish(universal)
	}

	old := ep.groupMap
	newMap := map[groupKey]*Group{}
	get := func(level Level, s signature) *Group {
		k := groupKey{level, s.canon}
		g := newMap[k]
		if g == nil {
			g = old[k]
			if g == nil {
				g = &Group{ID: uniqueGroupID(k, ep.groupIDs), Level: level, Since: c.now, emitted: GUnknown}
			}
			g.Sig = s
			g.Members, g.Tentative = g.Members[:0], g.Tentative[:0]
			newMap[k] = g
		}
		return g
	}
	// Routes are clusters of mutually compatible signatures (a wildcard —
	// silent or not-yet-answered hop — matches any responder; a responder
	// mismatch or a different confirmed length proves different routes).
	// Signatures are taken best-first (complete, then most known hops), so
	// the result does not depend on processing order. A signature joins the
	// one route it is compatible with and fills that route's wildcards; it
	// founds a new route only when proven different from every route; if it
	// fits several, it waits (ambiguous) until a hop answers.
	order := append([]*Flow(nil), flows...)
	slices.SortFunc(order, func(a, b *Flow) int {
		if a.sig.complete != b.sig.complete {
			if a.sig.complete {
				return -1
			}
			return 1
		}
		if a.sig.known != b.sig.known {
			return b.sig.known - a.sig.known
		}
		if c := strings.Compare(a.sig.canon, b.sig.canon); c != 0 {
			return c
		}
		return cmp.Compare(a.ID, b.ID)
	})
	type cluster struct {
		sig      signature
		complete bool
		members  []*Flow
	}
	var cls []*cluster
	for _, f := range order {
		var compat []*cluster
		for _, k := range cls {
			if !provenDifferent(&f.sig, &k.sig) {
				compat = append(compat, k)
			}
		}
		switch len(compat) {
		case 0:
			cls = append(cls, &cluster{sig: f.sig, complete: f.sig.complete, members: []*Flow{f}})
		case 1:
			k := compat[0]
			k.members = append(k.members, f)
			if !k.complete {
				k.sig = mergeSig(k.sig, f.sig)
			}
		default:
			f.level = LevelAmbiguous
		}
	}
	// Routes only get more specific while filling: re-check the waiting
	// (ambiguous) signatures against the final routes until nothing changes.
	for changed := true; changed; {
		changed = false
		for _, f := range order {
			if f.level != LevelAmbiguous {
				continue
			}
			var compat []*cluster
			for _, k := range cls {
				if !provenDifferent(&f.sig, &k.sig) {
					compat = append(compat, k)
				}
			}
			switch len(compat) {
			case 0:
				cls = append(cls, &cluster{sig: f.sig, complete: f.sig.complete, members: []*Flow{f}})
			case 1:
				k := compat[0]
				k.members = append(k.members, f)
				if !k.complete {
					k.sig = mergeSig(k.sig, f.sig)
				}
			default:
				continue
			}
			f.level = LevelUnresolved
			changed = true
		}
	}
	for _, k := range cls {
		k.sig.finish(universal)
		lvl := LevelPartialDistinct
		if k.complete {
			lvl = LevelConfirmed
		}
		if len(cls) == 1 && !k.complete {
			lvl = LevelUnresolved // nothing to be distinct from yet
		}
		g := get(lvl, k.sig)
		for _, f := range k.members {
			if k.complete && !f.sig.complete {
				g.Tentative = append(g.Tentative, f)
				f.group, f.level = g, LevelTentative
			} else {
				g.Members = append(g.Members, f)
				f.group, f.level = g, lvl
			}
		}
	}
	// Ambiguous flows: remember which routes they fit (shown as such).
	for _, f := range order {
		if f.level != LevelAmbiguous {
			continue
		}
		for _, k := range cls {
			if !provenDifferent(&f.sig, &k.sig) && len(k.members) > 0 && k.members[0].group != nil {
				f.fits = append(f.fits, k.members[0].group)
			}
		}
	}
	ep.groupMap = newMap
	ep.groups = ep.groups[:0]
	for _, g := range newMap {
		slices.SortFunc(g.Members, byFlowID)
		slices.SortFunc(g.Tentative, byFlowID)
		ep.groups = append(ep.groups, g)
	}
	slices.SortFunc(ep.groups, func(a, b *Group) int {
		if a.Level != b.Level {
			return int(b.Level) - int(a.Level)
		}
		if len(a.Members) != len(b.Members) {
			return len(b.Members) - len(a.Members)
		}
		return strings.Compare(a.ID, b.ID)
	})
}

func byFlowID(a, b *Flow) int { return cmp.Compare(a.ID, b.ID) }

// branches counts observed routes that are proven distinguishable.
func (ep *Endpoint) branches() int {
	n := 0
	for _, g := range ep.groups {
		if g.Level == LevelConfirmed || g.Level == LevelPartialDistinct {
			n++
		}
	}
	return n
}

// segEnd is one end of a segment: the source host, a router, or the
// destination.
type segEnd struct {
	kind segEndKind
	addr netip.Addr
}

type segEndKind uint8

const (
	segSrc segEndKind = iota
	segRouter
	segDst
)

func (e segEnd) String() string {
	switch e.kind {
	case segSrc:
		return "SRC"
	case segDst:
		return "DST"
	}
	return e.addr.String()
}

// segKey is what makes a segment itself: its two ends. The TTLs are where
// one signature has it, not part of what it is.
type segKey struct{ from, to segEnd }

func (k segKey) String() string { return k.from.String() + "→" + k.to.String() }

// Segment is an observed segment between consecutive TTLs with stable
// responders. It is a topological feature, not a proven physical link.
type Segment struct {
	FromTTL       TTL      `json:"from_ttl"` // 0 = source host
	ToTTL         TTL      `json:"to_ttl"`
	Responders    []string `json:"responder_addrs"`
	DirectionHint string   `json:"direction_hint"`
	key           segKey
}

// String renders "A→B".
func (g Segment) String() string { return g.Responders[0] + "→" + g.Responders[1] }

// segmentInfo returns the known observed segments of a signature: links
// between consecutive TTLs with stable responders (wildcards break them).
func segmentInfo(s *signature) []Segment {
	var out []Segment
	add := func(from, to segEnd, fromTTL, toTTL TTL) {
		k := segKey{from, to}
		out = append(out, Segment{FromTTL: fromTTL, ToTTL: toTTL, Responders: []string{from.String(), to.String()},
			DirectionHint: "forward_path_responders", key: k})
	}
	prev, prevTTL := segEnd{kind: segSrc}, TTL(0)
	prevKnown := true
	for i, e := range s.hops {
		if e.kind == eKnown {
			here := segEnd{kind: segRouter, addr: e.addr}
			if prevKnown {
				add(prev, here, prevTTL, TTL(i+1))
			}
			prev, prevTTL, prevKnown = here, TTL(i+1), true
		} else {
			prevKnown = false
		}
	}
	if s.distKnown && prevKnown {
		add(prev, segEnd{kind: segDst}, prevTTL, TTL(len(s.hops)+1))
	}
	return out
}

// mergeSig fills the wildcards of a with what b knows (b is compatible).
func mergeSig(a, b signature) signature {
	out := a
	out.hops = append([]hopElem(nil), a.hops...)
	if len(b.hops) > len(out.hops) && !out.distKnown {
		out.hops = append(out.hops, b.hops[len(out.hops):]...)
	}
	for i := range out.hops {
		if i < len(b.hops) && out.hops[i].kind != eKnown && b.hops[i].kind == eKnown {
			out.hops[i] = b.hops[i]
		}
	}
	if b.distKnown && !out.distKnown {
		out.distKnown = true
		out.hops = out.hops[:min(len(out.hops), len(b.hops))]
	}
	out.known = 0
	for _, e := range out.hops {
		if e.kind == eKnown {
			out.known++
		}
	}
	return out
}
