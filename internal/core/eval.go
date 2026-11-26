package core

import (
	"cmp"
	"slices"
	"time"

	"github.com/hotid/mpmtr/internal/stats"
)

// EPState is the endpoint state.
type EPState uint8

const (
	EPUnknown EPState = iota
	EPOK
	EPLoss
	EPDown
)

// Scope of an endpoint problem.
type Scope uint8

const (
	ScopeNone Scope = iota
	ScopePartial
	ScopeAll
	ScopeUnknown
)

// EndpointAgg are the aggregated flow counts of an endpoint.
type EndpointAgg struct {
	Total         int     `json:"total"`
	Measured      int     `json:"measured"`
	OK            int     `json:"ok"`
	Loss          int     `json:"loss"`
	Down          int     `json:"down"`
	Unknown       int     `json:"unknown"`
	Invalid       int     `json:"invalid"`
	RTTDegraded   int     `json:"rtt_degraded"`
	Stale         int     `json:"stale"`
	Coverage      float64 `json:"coverage"`
	W5            Window  `json:"window_5m"`
	AvgFailure    float64 `json:"avg_failure"`    // mean of per-flow failure rates (flows with valid > 0)
	PooledFailure float64 `json:"pooled_failure"` // sum failures / sum valid
	PooledOK      bool    `json:"pooled_ok"`
	WorstFailure  float64 `json:"worst_failure"`
	WorstFlow     string  `json:"worst_flow"`
	FullyDown     int     `json:"fully_down"`
	ProblemShare  float64 `json:"problem_share"`
}

// Coverage of discovered PathGroups by monitored representatives.
type Coverage struct {
	Groups           int  `json:"groups"`
	Represented      int  `json:"represented"`
	UnderRepresented int  `json:"under_represented"`
	Incomplete       bool `json:"incomplete"`
}

// Heterogeneity results.
type Heterogeneity struct {
	Loss         Hetero   `json:"loss"`
	LossOutliers []string `json:"loss_outliers"`
	GroupLoss    Hetero   `json:"group_loss"`
	GroupOutl    []string `json:"group_outl"`
	RTTRelative  []string `json:"rtt_relative"`
}

func (c *Core) nextEvalAt() Mono {
	return c.epochStart + Mono(c.evalBN+2)*c.bucket
}

// maybeEval runs the 10-second evaluation once per completed bucket.
func (c *Core) maybeEval() {
	cur := c.bucketNum(c.now)
	if cur-1 <= c.evalBN {
		return
	}
	bn := cur - 1
	c.evalBN = bn
	for _, ep := range c.eps {
		c.evalEndpointAll(ep, bn)
	}
	c.buildHopOwners()
	c.evalMonitor()
	c.gcResp()
}

func (c *Core) evalEndpointAll(ep *Endpoint, bn int64) {
	for _, f := range ep.Flows {
		if f.Role.Monitored() {
			c.evalFlow(f, bn)
		}
	}
	c.evalRTT(ep, bn)
	if c.cfg.Discovery {
		c.regroup(ep)
	}
	c.evalHetero(ep, bn)
	c.evalGroups(ep)
	c.evalEndpoint(ep)
	c.localize(ep)
	c.assignMonitors(ep)
	if ep.ac != nil {
		if ep.ac.unclustered > 0 && ep.ac.status == ACRunning {
			c.acCluster(ep)
		}
		c.censusWatchdog(ep)
		c.acAssign(ep)
	}
	c.maybeIncident(ep)
	c.ev.checkEndpoint(ep)
}

// bucketMedian returns the median RTT (us) and sample count of flow f in
// bucket bn.
func (c *Core) bucketMedian(f *Flow, bn int64, scratch []uint32) (uint32, int) {
	slot := &f.rtt.bmed[bn&3]
	if slot.ok && slot.bn == bn {
		return slot.med, slot.n
	}
	med, n := c.bucketMedianRing(f, bn, scratch)
	if bn < c.bucketNum(c.now) { // only cache completed buckets
		*slot = bucketMed{bn: bn, med: med, n: n, ok: true}
	}
	return med, n
}

func (c *Core) bucketMedianRing(f *Flow, bn int64, scratch []uint32) (uint32, int) {
	scratch = scratch[:0]
	f.rtt.ring.Do(func(s rttSample) {
		if int64(s.bn) == bn {
			scratch = append(scratch, s.us)
		}
	})
	if len(scratch) == 0 {
		return 0, 0
	}
	return stats.Median(scratch), len(scratch)
}

type bmed struct {
	f   *Flow
	med [3]uint32
	n   [3]int
}

// evalRTT detects relative (vs other flows) and absolute (vs own healthy
// baseline) RTT degradation, sustained over RTTPeriods 10-second periods.
func (c *Core) evalRTT(ep *Endpoint, bn int64) {
	P := c.cfg.RTTPeriods
	if P > 3 {
		P = 3
	}
	var scratch [rttRingSize]uint32
	var meds []bmed
	for _, f := range ep.Flows {
		if !f.Role.Monitored() || f.invalid != ValidFlow {
			continue
		}
		var m bmed
		m.f = f
		for i := 0; i < P; i++ {
			m.med[i], m.n[i] = c.bucketMedian(f, bn-int64(i), scratch[:])
		}
		meds = append(meds, m)
	}
	factor, absMin := c.cfg.RTTFactor, float64(c.cfg.RTTAbsMin/time.Microsecond)
	cf, cabs := c.cfg.RTTClearFactor, float64(c.cfg.RTTClearAbs/time.Microsecond)
	exceeds := func(m, ref float64, on bool) bool {
		if on { // hysteresis: stay degraded until clearly below clear threshold
			return m >= cf*ref && m >= ref+cabs
		}
		return m >= factor*ref && m >= ref+absMin
	}
	var ctrl [3][]uint32
	for i := range meds {
		m := &meds[i]
		f := m.f
		sm := &f.sm
		total := m.n[0] + m.n[1] + m.n[2]
		enough := total >= c.cfg.RTTMinSamples && m.n[0] > 0 && m.n[1] > 0 && m.n[2] > 0

		// Relative: control median of the other flows in each period.
		relAll, relNone := enough, enough
		for k := 0; k < P && enough; k++ {
			ctrl[k] = ctrl[k][:0]
			for j := range meds {
				if j != i && meds[j].n[k] >= 3 && meds[j].f.State() != FDown {
					ctrl[k] = append(ctrl[k], meds[j].med[k])
				}
			}
			if len(ctrl[k]) < 2 {
				relAll, relNone = false, false
				break
			}
			ref := float64(stats.Median(ctrl[k]))
			e := exceeds(float64(m.med[k]), ref, sm.rttRel)
			relAll = relAll && e
			relNone = relNone && !e
			if k == 0 {
				sm.rttRef = ref
			}
		}
		// Absolute: own baseline.
		b := &f.rtt.baseline
		absAll, absNone := enough && b.established, enough && b.established
		bv := float64(b.value())
		for k := 0; k < P && absAll; k++ {
			e := exceeds(float64(m.med[k]), bv, sm.rttAbs)
			absAll = absAll && e
			absNone = absNone && !e
		}
		for k := 0; k < P && !absAll && absNone; k++ {
			if exceeds(float64(m.med[k]), bv, sm.rttAbs) {
				absNone = false
			}
		}
		was := sm.rttRel || sm.rttAbs
		if !sm.rttRel && relAll {
			sm.rttRel = true
		} else if sm.rttRel && relNone {
			sm.rttRel = false
		}
		if !sm.rttAbs && absAll {
			sm.rttAbs = true
		} else if sm.rttAbs && absNone {
			sm.rttAbs = false
		}
		sm.baselineUnknown = !b.established
		now := sm.rttRel || sm.rttAbs
		if now && !was {
			sm.seqRTT++
			c.ev.flow(f, EvRTTDegradation)
		} else if was && !now {
			c.ev.flow(f, EvRTTRecovered)
		}
		// Baseline maintenance: only healthy periods, frozen otherwise.
		w := f.win.sum(bn, 1)
		healthy := w.Failures() == 0 && w.Impaired == 0 && w.Positive > 0 && !now &&
			sm.avail != AvailDown && sm.quality != QLoss && f.invalid == ValidFlow && !c.monitorImpaired()
		if healthy && b.established && m.n[0] > 0 && exceeds(float64(m.med[0]), bv, false) {
			healthy = false // onset period: do not let it pull the baseline
		}
		if healthy {
			c.feedBaseline(f, bn, m.med[0], m.n[0], scratch[:])
		}
	}
}

// baseline is a per-flow rolling RTT baseline over the last hour of
// healthy measurements (one median per minute).
type baseline struct {
	established bool
	initial     uint32
	initBuf     []uint32
	minutes     stats.Ring[uint32]
	curMin      int64
	acc         [6]uint32
	accN        int
}

func (b *baseline) value() uint32 {
	if b.minutes.Len() >= 3 {
		v := make([]uint32, 0, 60)
		b.minutes.Do(func(x uint32) { v = append(v, x) })
		return stats.Median(v)
	}
	return b.initial
}

func (c *Core) feedBaseline(f *Flow, bn int64, med uint32, n int, scratch []uint32) {
	b := &f.rtt.baseline
	if !b.established {
		f.rtt.ring.Do(func(s rttSample) {
			if int64(s.bn) == bn {
				b.initBuf = append(b.initBuf, s.us)
			}
		})
		if len(b.initBuf) >= c.cfg.BaselineSamples {
			b.initial = stats.Median(b.initBuf)
			b.initBuf = nil
			b.established = true
			b.minutes = stats.NewRing[uint32](60)
			b.curMin = bn / 6
		}
		return
	}
	m := bn / 6
	if m != b.curMin {
		if b.accN > 0 {
			b.minutes.Add(stats.Median(b.acc[:b.accN]))
		}
		b.curMin, b.accN = m, 0
	}
	if n > 0 && b.accN < len(b.acc) {
		b.acc[b.accN] = med
		b.accN++
	}
}

// evalHetero tests loss heterogeneity between flows and between groups.
func (c *Core) evalHetero(ep *Endpoint, bn int64) {
	h := Heterogeneity{}
	type fw struct {
		f *Flow
		w Window
	}
	var fs []fw
	for _, f := range ep.Flows {
		if f.Role.Monitored() && f.invalid == ValidFlow {
			w := f.win.sum(bn, WindowLong)
			if w.Valid >= 30 {
				fs = append(fs, fw{f, w})
			}
		}
	}
	h.Loss = HeteroInsufficient
	if len(fs) >= 2 {
		h.Loss = HeteroNotDetected
		var tv, tf int64
		for _, x := range fs {
			tv += x.w.Valid
			tf += x.w.Failures()
		}
		for _, x := range fs {
			ov, of := tv-x.w.Valid, tf-x.w.Failures()
			if ov < 30 {
				continue
			}
			r, _ := stats.Rate(x.w.Failures(), x.w.Valid)
			ro, _ := stats.Rate(of, ov)
			lo, _ := stats.Wilson(x.w.Failures(), x.w.Valid)
			_, hio := stats.Wilson(of, ov)
			if r-ro >= 0.05 && lo > hio {
				h.Loss = HeteroYes
				h.LossOutliers = append(h.LossOutliers, x.f.Name())
			}
		}
	}
	// Groups by actual pooled counts.
	type gw struct {
		g    *Group
		v, f int64
	}
	var gs []gw
	for _, g := range ep.groups {
		if g.Level != LevelConfirmed && g.Level != LevelPartialDistinct {
			continue
		}
		var x gw
		x.g = g
		for _, f := range g.measured() {
			if f.invalid == ValidFlow {
				w := f.win.sum(bn, WindowLong)
				x.v += w.Valid
				x.f += w.Failures()
			}
		}
		if x.v >= 30 {
			gs = append(gs, x)
		}
	}
	h.GroupLoss = HeteroInsufficient
	if len(gs) >= 2 {
		h.GroupLoss = HeteroNotDetected
		var tv, tf int64
		for _, x := range gs {
			tv += x.v
			tf += x.f
		}
		for _, x := range gs {
			ov, of := tv-x.v, tf-x.f
			r, _ := stats.Rate(x.f, x.v)
			ro, _ := stats.Rate(of, ov)
			lo, _ := stats.Wilson(x.f, x.v)
			_, hio := stats.Wilson(of, ov)
			if ov >= 30 && r-ro >= 0.05 && lo > hio {
				h.GroupLoss = HeteroYes
				h.GroupOutl = append(h.GroupOutl, x.g.ID)
			}
		}
	}
	for _, f := range ep.Flows {
		if f.Role.Monitored() && f.sm.rttRel {
			h.RTTRelative = append(h.RTTRelative, f.Name())
		}
	}
	ep.hetero = h
}

// evalGroups aggregates member flow states into PathGroup states.
func (c *Core) evalGroups(ep *Endpoint) {
	for _, g := range ep.groups {
		var ok, loss, down, unk, warm, n int
		for _, f := range g.measured() {
			n++
			switch f.State() {
			case FOK:
				ok++
			case FLoss:
				loss++
			case FDown:
				down++
			case FUnknown:
				unk++
				if f.sm.reason == ReasonWarmup {
					warm++
				}
			}
		}
		g.Partial = false
		switch {
		case n == 0:
			g.State = GUnknown
		case down == n:
			g.State = GDown
		case down+loss > 0:
			g.State = GLoss
			g.Partial = ok > 0 || unk > 0
		case ok == n, ok > 0 && ok+warm == n:
			// Flows still in warmup (newly measured source ports) do not
			// hide the verdict of the measured ones. Other unknowns (stale,
			// impaired, loss pending) still keep the route UNKNOWN.
			g.State = GOK
		default:
			g.State = GUnknown
		}
		g.Hetero = ok > 0 && (loss+down) > 0
	}
}

// evalEndpoint aggregates flows into the endpoint state and scope. DOWN
// requires confirmed DOWN of all relevant flows; insufficient data never
// becomes confirmed health.
func (c *Core) evalEndpoint(ep *Endpoint) {
	a := EndpointAgg{}
	var rateSum float64
	var rateN int
	for _, f := range ep.Flows {
		if !f.Role.Monitored() {
			continue
		}
		a.Total++
		st := f.State()
		if st == FInvalid {
			a.Invalid++
			continue
		}
		switch st {
		case FOK:
			a.OK++
		case FLoss:
			a.Loss++
		case FDown:
			a.Down++
		default:
			a.Unknown++
		}
		if f.sm.stale {
			a.Stale++
		}
		if f.sm.rttRel || f.sm.rttAbs {
			a.RTTDegraded++
		}
		w := f.win.sum(c.bucketNum(c.now), WindowLong)
		a.W5.Valid += w.Valid
		a.W5.Timeout += w.Timeout
		a.W5.App += w.App
		a.W5.AppFail += w.AppFail
		a.W5.Unreach += w.Unreach
		a.W5.Positive += w.Positive
		a.W5.Skipped += w.Skipped
		a.W5.Impaired += w.Impaired
		if r, ok := stats.Rate(w.Failures(), w.Valid); ok {
			rateSum += r
			rateN++
			if r > a.WorstFailure || a.WorstFlow == "" {
				a.WorstFailure, a.WorstFlow = r, f.Name()
			}
			if w.Positive == 0 && w.Valid >= int64(c.cfg.DownAfter) {
				a.FullyDown++
			}
		}
	}
	rel := a.Total - a.Invalid
	a.Measured = a.OK + a.Loss + a.Down
	if rel > 0 {
		a.Coverage = float64(a.Measured) / float64(rel)
		a.ProblemShare = float64(a.Loss+a.Down) / float64(rel)
	}
	if rateN > 0 {
		a.AvgFailure = rateSum / float64(rateN)
	}
	a.PooledFailure, a.PooledOK = stats.Rate(a.W5.Failures(), a.W5.Valid)
	ep.agg = a

	st, sc := EPUnknown, ScopeUnknown
	switch {
	case rel == 0:
	case a.Down == rel:
		st, sc = EPDown, ScopeAll
	case a.Down+a.Loss > 0:
		st = EPLoss
		switch {
		case a.OK > 0:
			sc = ScopePartial
		case a.Unknown == 0:
			sc = ScopeAll
		case a.Down == 0:
			// All measured flows are degraded but still answer: LOSS/ALL
			// (the unmeasured remainder is shown in the counts).
			sc = ScopeAll
		default:
			// Some flows confirmed DOWN, others unknown: the extent is not
			// known (never promoted to a global DOWN).
			sc = ScopeUnknown
		}
	case a.Coverage >= c.cfg.OKCoverage && a.Unknown == 0:
		st, sc = EPOK, ScopeNone
	case a.Coverage >= c.cfg.OKCoverage:
		// Enough coverage, nothing failing; the unknown remainder is shown.
		st, sc = EPOK, ScopeNone
	}
	ep.state, ep.scope = st, sc

	cov := Coverage{}
	for _, g := range ep.groups {
		if g.Level != LevelConfirmed && g.Level != LevelPartialDistinct {
			continue
		}
		cov.Groups++
		n := len(g.measured())
		if n > 0 {
			cov.Represented++
		}
		if n < min(2, len(g.Members)+len(g.Tentative)) {
			cov.UnderRepresented++
		}
	}
	cov.Incomplete = cov.Represented < cov.Groups
	ep.coverage = cov
}

// assignMonitors gives every route that discovery proved distinct (levels
// confirmed and partial_distinct) cfg.Flows measured ports, taken from the
// route's own ports in probing order. A measured port is never swapped for
// another; it is stopped only when it turns out to duplicate a route that
// already has cfg.Flows measured ports (two routes merged, or the port's
// path moved onto such a route) — the lowest-numbered ports stay.
func (c *Core) assignMonitors(ep *Endpoint) {
	if !c.cfg.Discovery || c.cfg.DiscoverOnly {
		return
	}
	for _, g := range ep.groups {
		if g.Level != LevelConfirmed && g.Level != LevelPartialDistinct {
			continue
		}
		cands := append(append([]*Flow(nil), g.Members...), g.Tentative...)
		slices.SortFunc(cands, func(a, b *Flow) int { return cmp.Compare(a.ID, b.ID) })
		have := 0
		for _, f := range cands {
			if !f.Role.Monitored() {
				continue
			}
			if have >= c.cfg.Flows && !c.acRepresents(f) {
				c.deactivate(f)
				ep.stopped = append(ep.stopped, StoppedFlow{Flow: f.Name(), SPort: f.SPort(), Group: g.ID, At: c.nowRT})
				if len(ep.stopped) > 20 {
					ep.stopped = ep.stopped[1:]
				}
				continue
			}
			have++
		}
		for _, f := range cands {
			if have >= c.cfg.Flows {
				break
			}
			if f.Role != RoleCandidate || f.invalid != ValidFlow {
				continue
			}
			c.activate(f, RoleActive)
			have++
		}
	}
}

// incident is an elevated-priority diagnostic trace on an endpoint.
type incident struct {
	ep       *Endpoint
	started  Mono
	flows    []*Flow
	controls []*Flow
	pending  int
}

func (c *Core) maybeIncident(ep *Endpoint) {
	if !c.cfg.TraceOnFailure {
		return
	}
	if inc := ep.incident; inc != nil {
		if c.now-inc.started > Mono(5*time.Minute) {
			c.endIncident(ep)
		}
		return
	}
	if ep.lastInc != 0 && c.now-ep.lastInc < Mono(time.Minute) {
		return
	}
	var bad, good []*Flow
	for _, f := range ep.Flows {
		if !f.Role.Monitored() || f.invalid != ValidFlow {
			continue
		}
		// Extra traces are for path trouble: a flow whose TCP answers
		// and whose application checks fail has none to trace.
		if f.sm.consecFail >= 2 || (f.sm.lossTicks > 0 && !f.sm.lossByApp) || f.tcpFailing() || f.sm.rttRel || f.sm.rttAbs {
			bad = append(bad, f)
		} else if f.sm.quality == QOK || (f.sm.avail == AvailUp && f.sm.consecPos >= 3) {
			good = append(good, f)
		}
	}
	if len(bad) == 0 {
		return
	}
	if len(bad) > 4 {
		bad = bad[:4]
	}
	// Controls: same group first, then other groups.
	slices.SortStableFunc(good, func(a, b *Flow) int {
		sa, sb := 1, 1
		for _, x := range bad {
			if a.group != nil && a.group == x.group {
				sa = 0
			}
			if b.group != nil && b.group == x.group {
				sb = 0
			}
		}
		return sa - sb
	})
	var ctl []*Flow
	seenGroup := map[*Group]bool{}
	for _, f := range good {
		if len(ctl) >= c.cfg.IncidentControls {
			break
		}
		if f.group != nil && seenGroup[f.group] && len(good) > c.cfg.IncidentControls {
			continue
		}
		seenGroup[f.group] = true
		ctl = append(ctl, f)
	}
	inc := &incident{ep: ep, started: c.now, flows: bad, controls: ctl}
	ep.incident = inc
	for _, f := range append(append([]*Flow{}, bad...), ctl...) {
		if f.sw != nil && f.sw.class != ClassIncident {
			f.sw = nil // incident sweep takes precedence over refresh/discovery for this flow
			if f.EP.disc.inBatch > 0 {
				c.discCandidateDone(f)
			}
		}
		f.incident = inc
		inc.pending++
		c.startSweep(f, ClassIncident, c.cfg.IncidentRounds)
	}
}

func (c *Core) incidentFlowDone(f *Flow) {
	inc := f.incident
	f.incident = nil
	if inc == nil {
		return
	}
	inc.pending--
	if inc.pending <= 0 {
		c.endIncident(inc.ep)
	}
}

func (c *Core) endIncident(ep *Endpoint) {
	inc := ep.incident
	if inc == nil {
		return
	}
	for _, f := range append(append([]*Flow{}, inc.flows...), inc.controls...) {
		if f.incident == inc {
			f.incident = nil
			if f.sw != nil && f.sw.class == ClassIncident {
				f.sw = nil
			}
		}
	}
	ep.incident = nil
	ep.lastInc = c.now
}

// evalMonitor tracks the measurer's own health.
func (c *Core) evalMonitor() {
	imp := c.monitorImpaired()
	if imp != c.impairedNow {
		c.impairedNow = imp
		if imp {
			c.ev.global(EvMonitoringImpaired, c.impairedReasons())
		} else {
			c.ev.global(EvMonitoringRecovered, nil)
		}
	}
}

func (c *Core) impairedReasons() []string {
	var r []string
	if c.lastDropMono != 0 && c.now-c.lastDropMono < Mono(10*time.Second) {
		r = append(r, "capture_drops")
	}
	if c.lastWMMono != 0 && c.now-c.lastWMMono > Mono(time.Second) {
		r = append(r, "capture_stalled")
	}
	return r
}

// EvaluateNow runs one evaluation over the current (partial) bucket. Used
// at the end of report mode so the final state reflects the latest data.
func (c *Core) EvaluateNow() {
	c.now, c.nowRT = c.clk.Now()
	bn := c.bucketNum(c.now)
	for _, ep := range c.eps {
		c.evalEndpointAll(ep, bn)
	}
	c.evalMonitor()
}
