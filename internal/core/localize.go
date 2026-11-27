package core

import (
	"fmt"
	"slices"
	"strings"

	"github.com/hotid/mpmtr/internal/stats"
)

// Localization is the result of comparing failing and healthy flows. Sets
// of segments are observed topological features, not proven physical links.
type Localization struct {
	Level                 LocLevel  `json:"level"`
	BadFlows              []string  `json:"bad_flows"`
	BadGroups             []string  `json:"bad_groups"`
	GoodGroups            []string  `json:"good_groups"`
	SuspectedSegments     []string  `json:"suspected_segments"`
	Segments              []Segment `json:"suspected_segment_details,omitempty"`
	AffectedGroups        []string  `json:"affected_groups,omitempty"`
	Quality               []string  `json:"quality,omitempty"`
	SuspectedLossStartTTL TTL       `json:"suspected_loss_start_ttl"`
	Supporting            []string  `json:"supporting"`
	Contradicting         []string  `json:"contradicting"`
	Limitations           []string  `json:"limitations"`
	key                   string
}

func (c *Core) localize(ep *Endpoint) {
	var bad, good, appOnly []*Flow
	for _, f := range ep.Flows {
		if !f.Role.Monitored() || f.invalid != ValidFlow {
			continue
		}
		// A flow whose TCP answers and whose application checks fail is a
		// healthy control for the path: its trouble is at the server.
		switch st := f.State(); {
		case f.appFailing():
			appOnly = append(appOnly, f)
			good = append(good, f)
		case st == FDown || st == FLoss:
			bad = append(bad, f)
		case st == FOK:
			if !f.sm.rttRel && !f.sm.rttAbs {
				good = append(good, f)
			}
		}
	}
	L := Localization{Level: LocNone}
	var appNotes []string
	for _, f := range appOnly {
		w := f.win.sum(c.bucketNum(c.now), WindowLong)
		appNotes = append(appNotes, fmt.Sprintf("%s sport %d: TCP answers, application checks fail (%d of %d in 5 min): not a path fault (%s)",
			f.Name(), f.SPort(), w.AppFail, w.App, groupName(f)))
	}
	if len(bad) == 0 {
		if len(appOnly) > 0 {
			L.Level = LocApplication
			L.Supporting = appNotes
			for _, f := range appOnly {
				L.BadFlows = append(L.BadFlows, f.Name())
			}
		}
		c.setLoc(ep, L)
		return
	}
	L.Contradicting = append(L.Contradicting, appNotes...)
	for _, f := range bad {
		w := f.win.sum(c.bucketNum(c.now), WindowLong)
		L.BadFlows = append(L.BadFlows, f.Name())
		L.Supporting = append(L.Supporting, fmt.Sprintf("%s sport %d %s: %d/%d failures in 5 min (%s)",
			f.Name(), f.SPort(), f.State(), w.Failures(), w.Valid, groupName(f)))
	}
	// Groups: B = all monitored members failing, G = all monitored members
	// healthy, mixed = same visible signature with both.
	var B, G, mixed []*Group
	for _, g := range ep.groups {
		if g.Level != LevelConfirmed && g.Level != LevelPartialDistinct {
			continue
		}
		var nb, ng, n int
		for _, f := range g.Members {
			if !f.Role.Monitored() || f.invalid != ValidFlow {
				continue
			}
			n++
			if slices.Contains(bad, f) {
				nb++
			} else if slices.Contains(good, f) {
				ng++
			}
		}
		switch {
		case n == 0:
		case nb > 0 && ng > 0:
			mixed = append(mixed, g)
		case nb > 0 && nb == n:
			B = append(B, g)
		case ng > 0 && ng == n:
			G = append(G, g)
		}
	}
	for _, g := range B {
		L.BadGroups = append(L.BadGroups, g.ID)
	}
	for _, g := range G {
		L.GoodGroups = append(L.GoodGroups, g.ID)
	}
	ungrouped := 0
	for _, f := range bad {
		if f.group == nil || (f.level != LevelConfirmed && f.level != LevelPartialDistinct) {
			ungrouped++
		}
	}
	// Hop-level analysis on failing flows (MTR rule: loss that does not
	// persist downstream is likely ICMP rate limiting, not transit loss).
	start := TTL(0)
	for _, f := range bad {
		if t, sup := lossStartTTL(f); t > 0 {
			if start == 0 || t < start {
				start = t
			}
			L.Supporting = append(L.Supporting, sup)
		}
	}
	L.SuspectedLossStartTTL = start
	for _, f := range bad {
		if len(f.sig.assumed) > 0 {
			L.Limitations = append(L.Limitations, fmt.Sprintf("%s got no answer at TTL %s: the router there is taken from the other ports, its own path may differ",
				f.Name(), ttlList(f.sig.assumed)))
		}
	}

	switch {
	case len(good) == 0:
		if len(B) >= 2 {
			L.Level = LocCorrelatedPath
		} else {
			L.Level = LocFlowFailure
		}
		L.Limitations = append(L.Limitations, "no healthy control flows: no single segment can be blamed by route comparison")
	case len(mixed) > 0 && len(B) == 0:
		L.Level = LocForwardNotDistinct
		for _, g := range mixed {
			L.Supporting = append(L.Supporting, fmt.Sprintf("%s: failing and healthy flows share the same visible signature", g.ID))
		}
		L.Limitations = append(L.Limitations, "invisible forward-path differences (LAG/MPLS/middlebox/anycast/LB) or the reverse path may be involved; not distinguishable from here")
	case len(B) == 0 && ungrouped > 0:
		L.Level = LocRouteAmbiguity
		L.Limitations = append(L.Limitations, "failing flows have incomplete or ambiguous observed routes")
	case len(B) > 0 && len(G) > 0:
		// A segment is its two ends (segKey): the same pair of routers is
		// the same segment wherever a route has it.
		segB := map[segKey]int{}
		detail := map[segKey]Segment{} // as the first failing route has it
		for _, g := range B {
			for _, sg := range segmentInfo(&g.Sig) {
				segB[sg.key]++
				if _, ok := detail[sg.key]; !ok {
					detail[sg.key] = sg
				}
			}
		}
		inG := map[segKey]bool{}
		for _, g := range G {
			for _, sg := range segmentInfo(&g.Sig) {
				inG[sg.key] = true
			}
		}
		var suspected []segKey
		for k, n := range segB {
			if n == len(B) && !inG[k] {
				suspected = append(suspected, k)
			} else if n == len(B) && inG[k] {
				L.Contradicting = append(L.Contradicting, "segment "+k.String()+" is shared with healthy groups")
			}
		}
		slices.SortFunc(suspected, func(a, b segKey) int { return strings.Compare(a.String(), b.String()) })
		slices.Sort(L.Contradicting)
		for _, k := range suspected {
			L.SuspectedSegments = append(L.SuspectedSegments, k.String())
			L.Segments = append(L.Segments, detail[k])
		}
		if len(L.SuspectedSegments) > 0 {
			L.Level = LocSuspectedSegment
			L.Supporting = append(L.Supporting, fmt.Sprintf("segments seen in all failing groups (%s) and in no healthy group (%s)",
				strings.Join(L.BadGroups, ","), strings.Join(L.GoodGroups, ",")))
			if len(L.SuspectedSegments) > 1 {
				L.Limitations = append(L.Limitations, "several candidate segments remain; none is singled out")
			}
		} else {
			L.Level = LocInconclusive
			L.Limitations = append(L.Limitations, "no known segment is unique to failing groups (hidden hops or shared segments)")
		}
		if len(mixed) > 0 {
			L.Contradicting = append(L.Contradicting, "some groups contain both failing and healthy flows")
		}
	default:
		L.Level = LocInconclusive
		if len(B) > 0 {
			L.Limitations = append(L.Limitations, "no healthy group with a known route to compare against")
		}
	}
	if len(bad) == 1 && L.Level == LocInconclusive && len(good) > 0 {
		L.Level = LocFlowFailure
	}
	L.Limitations = append(L.Limitations, "observed responder addresses do not identify physical links; ICMP replies may use a different return path than TCP")
	L.AffectedGroups = append(append([]string{}, L.BadGroups...), groupIDs(mixed)...)
	if c.monitorImpaired() {
		L.Quality = append(L.Quality, "capture_impaired")
	}
	for _, f := range bad {
		if f.sm.stale {
			L.Quality = append(L.Quality, "stale")
			break
		}
	}
	if ungrouped > 0 || ep.coverage.Incomplete {
		L.Quality = append(L.Quality, "incomplete_topology")
	}
	c.setLoc(ep, L)
}

func groupName(f *Flow) string {
	if f.group == nil {
		return "route " + f.level.String()
	}
	return f.group.ID + " " + f.level.String()
}

// lossStartTTL finds the first TTL of a failing flow from which apparent hop
// loss persists downstream, by the rule the tree marks use (markDownstream):
// the hop answers and loses significantly (lossElevated), it is not rate
// limited (possibleRateLimit: no later answering hop loses significantly
// less), and every later answering hop loses significantly too. A hop that
// never answers says nothing about loss: it neither starts loss nor shows
// that loss persists. The one exception is a port that is DOWN and gets no
// answer from some TTL on, the destination included: nothing passes beyond
// that point, so the loss starts there (or the router there does not
// answer and it starts right after).
func lossStartTTL(f *Flow) (TTL, string) {
	r := f.route
	L := r.top()
	if r.distance > 0 {
		L = min(L, r.distance)
	}
	for t := TTL(1); t <= L; t++ {
		h := r.hopIf(t)
		if !hopAnswers(h) || !lossElevated(h.Timeouts, h.Replies+h.Timeouts) || possibleRateLimit(r, t) {
			continue
		}
		persist, seen := true, 0
		for u := t + 1; u <= L; u++ {
			d := r.hopIf(u)
			if !hopAnswers(d) {
				continue
			}
			if !lossElevated(d.Timeouts, d.Replies+d.Timeouts) {
				persist = false
				break
			}
			seen++
		}
		if persist {
			// Silent hops and hops with too few probes neither confirm nor refute: say
			// "persists" only when a later hop actually shows it.
			tail := "and persists downstream"
			if seen == 0 {
				tail = "(no data from later hops)"
			}
			return t, fmt.Sprintf("%s: apparent hop loss starts at TTL %d (%d/%d) %s", f.Name(), t, h.Timeouts, h.Replies+h.Timeouts, tail)
		}
	}
	if f.State() != FDown {
		return 0, ""
	}
	for t := TTL(1); t <= L; t++ {
		h := r.hopIf(t)
		if h.Replies > 0 || h.Timeouts < 5 {
			continue
		}
		silent := true
		for u := t + 1; u <= L && silent; u++ {
			silent = r.hopIf(u).Replies == 0
		}
		if silent {
			return t, fmt.Sprintf("%s: no answer from TTL %d on (%d/%d), the destination included", f.Name(), t, h.Timeouts, h.Timeouts)
		}
	}
	return 0, ""
}

// hopAnswers: the hop has replied and has enough probes to judge its loss.
func hopAnswers(h *HopStat) bool {
	return h != nil && h.Replies > 0 && h.Replies+h.Timeouts >= 5
}

// possibleRateLimit: elevated apparent loss on a hop that does not persist
// on later hops, while the flow's E2E is healthy or later hops answer.
func possibleRateLimit(r *RouteObs, t TTL) bool {
	h := r.hopIf(t)
	if h == nil {
		return false
	}
	for u := t + 1; u <= r.top(); u++ {
		d := r.hopIf(u)
		if lossDropsAfter(h.Timeouts, h.Replies+h.Timeouts, d.Timeouts, d.Replies+d.Timeouts) {
			return true
		}
	}
	return false
}

// lossDropsAfter reports whether a hop's share of unanswered probes
// (lost of n) is significant (Wilson lower bound above 5%) and a later
// answering hop (dLost of dn) loses significantly less: its Wilson upper
// bound is below this hop's lower bound. Then the loss does not persist
// downstream: the router limits its ICMP replies, traffic through it is
// not lost. A hop that never answers is silent, not rate limited. Merely
// "not provably lossy" downstream is not enough: 1 timeout in 5 later
// cannot clear a hop with 50% loss.
func lossDropsAfter(lost, n, dLost, dn uint32) bool {
	if n < 5 || lost == 0 || lost == n || dn < 5 || dLost == dn {
		return false
	}
	lo, _ := stats.Wilson(int64(lost), int64(n))
	if lo <= 0.05 {
		return false
	}
	_, dhi := stats.Wilson(int64(dLost), int64(dn))
	return dhi < lo
}

func groupIDs(gs []*Group) []string {
	var out []string
	for _, g := range gs {
		out = append(out, g.ID)
	}
	return out
}

// setLoc publishes a LOCALIZATION_RESULT only when the level or the set of
// suspected segments changes. Changes of supporting/contradicting data
// alone, or INCONCLUSIVE → INCONCLUSIVE, are not events. Leaving a confirmed
// level (incl. back to NONE) is always reported.
func (c *Core) setLoc(ep *Endpoint, L Localization) {
	L.key = L.Level.String() + "|" + strings.Join(L.SuspectedSegments, ",")
	prev := ep.locPublished
	ep.loc = L
	if L.key == prev.key {
		return
	}
	if prev.key == "" && L.Level == LocNone {
		ep.locPublished = L
		return
	}
	if prev.Level == LocInconclusive && L.Level == LocInconclusive {
		return
	}
	ep.locPublished = L
	c.ev.localization(ep, prev)
}

func ttlList(ts []TTL) string {
	var b strings.Builder
	for i, t := range ts {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprint(&b, int(t))
	}
	return b.String()
}
