package core

import (
	"time"

	"github.com/hotid/mpmtr/internal/stats"
)

// Avail is the confirmed TCP availability of a flow.
type Avail uint8

const (
	AvailUnknown Avail = iota
	AvailUp
	AvailDown
)

// Quality is the statistical quality state of a flow.
type Quality uint8

const (
	QUnknown Quality = iota
	QOK
	QLoss
)

// FState is the combined display state of a flow.
type FState uint8

const (
	FUnknown FState = iota
	FOK
	FLoss
	FDown
	FInvalid
)

type flowSM struct {
	avail      Avail
	quality    Quality
	reason     Reason
	consecFail int
	consecPos  int
	lastValid  Mono
	lastPos    Mono
	lossTicks  int
	lossFloor  int64 // onset window starts here after a LOSS clear
	epoch      int
	epochStart Mono

	monitoredSince Mono
	stale          bool
	impaired       bool
	downSince      Mono
	downHeld       bool // DOWN criteria met but measurer impaired
	// avail is DOWN while either holds: TCP does not answer (tcpDown), or
	// it does and the application checks fail in a row (appDown).
	tcpDown, appDown    bool
	appFails, appPasses int // application checks failed / passed in a row
	// LOSS (or the evidence gathering for it) rests on the application
	// checks alone: TCP itself is within its limits.
	lossByApp bool
	bg        downBG // background loss outside DOWN periods (DOWN threshold)

	rttRel, rttAbs  bool
	baselineUnknown bool
	rttRef          float64

	// incident sequence numbers per kind, for stable event keys
	seqDown, seqLoss, seqRTT int
}

func (s *flowSM) init(now Mono) {
	*s = flowSM{epochStart: now, reason: ReasonWarmup}
}

// tcpFailing: the path or the server's TCP fails on this flow. appFailing:
// TCP is fine and only the application checks fail, which says nothing
// about the path.
func (f *Flow) tcpFailing() bool {
	return f.sm.tcpDown || (f.sm.avail != AvailDown && f.sm.quality == QLoss && !f.sm.lossByApp)
}

func (f *Flow) appFailing() bool {
	return !f.sm.tcpDown && (f.sm.appDown || (f.sm.quality == QLoss && f.sm.lossByApp))
}

// State returns the combined state of the flow.
func (f *Flow) State() FState {
	switch {
	case f.invalid != ValidFlow:
		return FInvalid
	case f.sm.avail == AvailDown:
		return FDown
	case f.sm.quality == QLoss:
		return FLoss
	case f.sm.quality == QOK:
		return FOK
	}
	return FUnknown
}

func (c *Core) staleAfter() Mono {
	iv := c.cfgDur(c.cfg.Interval)
	return max(5*iv, Mono(5*time.Second)) + c.cfgDur(c.cfg.Timeout)
}

// maxSeriesGap: a run of failures separated by a longer gap without valid
// measurements is not a consecutive series.
func (c *Core) maxSeriesGap() Mono {
	return 3*c.cfgDur(c.cfg.Interval) + c.cfgDur(c.cfg.Timeout)
}

// monitorImpaired reports whether the local measurer is currently impaired
// (capture drops recently, or the capture watermark stopped advancing).
func (c *Core) monitorImpaired() bool {
	if c.lastDropMono != 0 && c.now-c.lastDropMono < Mono(10*time.Second) {
		return true
	}
	if c.lastWMMono != 0 && c.now-c.lastWMMono > Mono(time.Second) {
		return true
	}
	return false
}

// record dispatches a finalized probe to E2E or hop statistics.
func (c *Core) record(p *Probe) {
	switch p.class {
	case ClassE2E, ClassApp:
		c.recordE2E(p)
		if p.hasTS && c.cfg.Anycast {
			c.acObserve(p)
		}
	case ClassCensus:
		c.recordCensus(p)
	default:
		c.recordHop(p)
	}
}

func (c *Core) recordE2E(p *Probe) {
	f := p.flow
	o := p.outcome
	if o != OutLocalError && o != OutCancelled && o != OutSkipped {
		if p.class == ClassE2E {
			f.Executed++ // -c counts TCP probes; application checks come on top
		}
		f.lastE2E = c.now
	}
	if f.invalid != ValidFlow {
		f.C.Invalid++
		return
	}
	switch o {
	case OutSynAck:
		f.C.SynAck++
	case OutRst:
		f.C.Rst++
	case OutICMPUnreach:
		f.C.Unreach++
	case OutTimeout:
		f.C.Timeout++
	case OutWeak:
		// counted at match time
	case OutUnexpected:
		f.C.Unexpected++
	case OutLocalError:
		f.C.LocalErr++
	case OutCaptureImpaired:
		f.C.Impaired++
	case OutCancelled:
		f.C.Cancelled++
	case OutRemoteState:
		f.C.RemoteState++
	case OutAppOK:
		f.C.AppOK++
	case OutAppFail:
		f.C.AppFail++
	}
	bn := c.bucketNum(p.sentMono)
	if bn < 0 {
		bn = 0
	}
	f.win.add(bn, o)
	if o.Valid() {
		f.episode.add(o.Failure())
		f.route.E2EValid++
		if o.Failure() {
			f.route.E2EFail++
		}
	}
	if p.class == ClassE2E && o.Positive() && p.id == f.lastSent { // (finalized late: nothing sent since)
		f.tupleClean = true
	}
	if f.appWant && p.class == ClassE2E {
		c.push(event{at: c.now, kind: evApp, flow: f})
	}
	if o.Positive() {
		us, kern := c.rttUs(p)
		if !kern {
			f.C.TxTSFallback++
			c.M.TxTSFallback++
		}
		f.rtt.add(us, bn)
		f.route.RTTSum += float64(us)
		f.route.RTTN++
	}
	c.availUpdate(f, o)
}

// availUpdate is the fast availability state machine (DOWN after a run of
// consecutive valid failures that the flow's background loss does not
// explain, see downNeed; recovery after N consecutive strict positives). It
// does not wait for statistical warmup.
func (c *Core) availUpdate(f *Flow, o Outcome) {
	sm := &f.sm
	bg := &sm.bg
	wasDown := sm.avail == AvailDown
	inDown := sm.tcpDown // the TCP DOWN period is not background
	if o.Valid() {
		if sm.lastValid != 0 && c.now-sm.lastValid > c.maxSeriesGap() {
			sm.consecFail, sm.consecPos = 0, 0
			bg.endRun()
		}
		sm.lastValid = c.now
		bg.decay(c.now)
	}
	switch {
	case o.Failure():
		sm.consecFail++
		sm.consecPos = 0
		if !inDown {
			bg.run++
		}
	case o.Answered():
		sm.consecPos++
		sm.consecFail = 0
		sm.lastPos = c.now
		if !inDown {
			bg.endRun()
			bg.n++
		}
	case o == OutWeak || o == OutUnexpected:
		// Something answered: never build a DOWN series across it.
		sm.consecFail = 0
		bg.endRun()
	}
	// TCP: only a failure of the path itself completes the run: a local
	// send error or an impaired capture says nothing about the network.
	switch {
	case !sm.tcpDown && o.Failure() && sm.consecFail >= c.downNeed(f):
		if c.monitorImpaired() {
			sm.downHeld = true
			return
		}
		bg.run = 0 // the run that made the flow DOWN is not background
		sm.downHeld = false
		sm.tcpDown = true
	case sm.tcpDown && sm.consecPos >= c.cfg.UpAfter:
		sm.tcpDown = false
	}
	// The application: its checks are few (one per --app-interval) and TCP
	// probes that succeed in between say nothing about it, so it has a run
	// of its own.
	switch o {
	case OutAppFail:
		sm.appFails++
		sm.appPasses = 0
		if sm.appFails >= c.cfg.AppDownAfter {
			sm.appDown = true
		}
	case OutAppOK:
		sm.appPasses++
		sm.appFails = 0
		if sm.appPasses >= c.cfg.AppUpAfter {
			sm.appDown = false
		}
	}
	switch down := sm.tcpDown || sm.appDown; {
	case down && !wasDown:
		sm.avail = AvailDown
		sm.downSince = c.now
		sm.seqDown++
		if !sm.tcpDown {
			sm.reason = ReasonAppDown
		}
		c.ev.flow(f, EvFlowDown)
	case !down && wasDown:
		sm.avail = AvailUp
		// New recovery epoch: the DOWN period stays in lifetime
		// counters but is excluded from the quality windows, so it
		// cannot cause an immediate LOSS after recovery.
		c.newEpoch(f, ReasonPostRecovery)
		c.ev.flow(f, EvFlowRecovered)
	case down && sm.tcpDown && sm.reason == ReasonAppDown:
		sm.reason = ReasonNone // TCP stopped answering too: the plain DOWN
	case down && !sm.tcpDown && sm.appDown:
		sm.reason = ReasonAppDown
	case !down && sm.avail == AvailUnknown && o.Answered():
		sm.avail = AvailUp
	}
}

func (c *Core) newEpoch(f *Flow, reason Reason) {
	sm := &f.sm
	sm.epoch++
	sm.epochStart = c.now
	sm.quality = QUnknown
	sm.reason = reason
	sm.lossTicks = 0
	f.win.reset()
}

// evalFlow runs the 10-second evaluation of one monitored flow for the
// completed bucket bn: staleness, validity, LOSS onset/clear, quality.
func (c *Core) evalFlow(f *Flow, bn int64) {
	sm := &f.sm
	w5 := f.win.sum(bn, WindowLong)
	w1 := f.win.sum(bn, WindowShort)
	// Onset window: after a LOSS clear, old (already reported) failures are
	// not re-used as fresh evidence.
	wOn := f.win.sumFrom(bn, WindowLong, sm.lossFloor)
	fresh := sm.lastValid != 0 && c.now-sm.lastValid <= c.staleAfter()
	if c.cfg.ReportCountReached(f) && sm.lastValid != 0 {
		fresh = true // report mode: the flow finished its probes, data is complete
	}
	sm.stale = !fresh && c.now-sm.monitoredSince > c.staleAfter()
	// Remote TCP state left over from earlier probes (our RST missing or
	// lost on the way) shows up as challenge ACKs / missing RSTs: the flow's
	// measurements are impaired, not a network loss.
	// A probe that got no answer while the server held an earlier probe's
	// connection is in the window's impaired count, so the flow is impaired
	// while that lasts and no longer.
	sm.impaired = w1.Impaired > 0 || (f.C.RstMissing > 0 && f.C.RstMissing*4 > f.C.SynAck)

	// The kernel did not send the flow's probes out of the interface chosen
	// by the per-flow (port-aware) route lookup: identity not honoured.
	if f.C.EgressMismatch >= 3 && f.C.EgressMismatch*2 >= f.C.Sent {
		c.invalidate(f, InvalidEgressMismatch)
	}
	// Measurement validity: weak/unexpected replies dominating.
	if w5.WeakUnexp >= 5 && w5.WeakUnexp*2 > w5.WeakUnexp+w5.Valid {
		c.invalidate(f, InvalidWeakDominant)
	}
	if f.invalid != ValidFlow {
		sm.reason = ReasonInvalid
		return
	}
	if sm.avail == AvailDown {
		return // quality is not evaluated while confirmed DOWN
	}
	lo, _ := stats.Wilson(wOn.Failures(), wOn.Valid)
	// The same test on the application checks alone: they are far fewer
	// than the TCP probes, so they are never pooled with them.
	appLo, _ := stats.Wilson(wOn.AppFail, wOn.App)
	appLoss := wOn.App >= int64(c.cfg.AppDownAfter) && wOn.AppFail >= 2 && appLo > c.cfg.LossWilsonLow
	tcpLoss := wOn.Valid >= int64(c.cfg.LossMinValid) && lo > c.cfg.LossWilsonLow
	switch sm.quality {
	case QLoss:
		if tcpLoss {
			sm.lossByApp = false
		}
		r1, ok := stats.Rate(w1.Failures(), w1.Valid)
		if ok && w1.Valid >= int64(c.cfg.LossMinValid) && r1 <= c.cfg.LossClearRate &&
			sm.consecPos >= c.cfg.LossClearConsec && fresh && w1.AppFail == 0 && sm.appFails == 0 {
			sm.quality = QOK
			sm.reason = ReasonNone
			sm.lossTicks = 0
			sm.lossFloor = bn + 1
			c.ev.flow(f, EvFlowLossCleared)
		}
	default:
		if (tcpLoss || appLoss) && !c.monitorImpaired() {
			sm.lossTicks++
			sm.lossByApp = !tcpLoss
		} else {
			sm.lossTicks = 0
		}
		switch {
		case sm.lossTicks >= c.cfg.LossTicks:
			sm.quality = QLoss
			sm.reason = ReasonNone
			sm.seqLoss++
			c.ev.flow(f, EvFlowLoss)
		case sm.stale:
			sm.quality, sm.reason = QUnknown, ReasonStale
		case c.monitorImpaired() && sm.quality == QUnknown:
			sm.reason = ReasonCaptureImpaired
		case sm.lossTicks > 0 && sm.quality == QUnknown:
			sm.reason = ReasonLossPending // loss evidence not yet confirmed: never OK
		case w5.Valid >= int64(c.cfg.LossMinValid) && fresh && sm.lossTicks == 0:
			sm.quality, sm.reason = QOK, ReasonNone
		default:
			if sm.quality != QOK {
				if sm.reason == ReasonNone {
					sm.reason = ReasonWarmup
				}
			}
		}
	}
}

// ResetStats starts a new measurement epoch: session statistics and
// evaluation windows are cleared and every monitored flow starts a fresh
// warmup. No events are generated by the reset itself.
func (c *Core) ResetStats() {
	c.now, c.nowRT = c.clk.Now()
	c.epochNum++
	for _, f := range c.flows {
		f.C = Counters{}
		f.Executed = 0
		f.win.reset()
		base := f.rtt.baseline
		f.rtt = rttState{ring: f.rtt.ring, baseline: base}
		f.rtt.ring.Reset()
		f.episode = lossEpisodes{}
		seqD, seqL, seqR := f.sm.seqDown, f.sm.seqLoss, f.sm.seqRTT
		f.sm.init(c.now)
		f.sm.seqDown, f.sm.seqLoss, f.sm.seqRTT = seqD, seqL, seqR
		f.sm.monitoredSince = c.now
		f.sm.reason = ReasonReset
		if f.route != nil {
			f.route.End = c.now
			f.routeHist = append(f.routeHist, f.route)
			if len(f.routeHist) > 4 {
				f.routeHist = f.routeHist[1:]
			}
			nr := newRouteObs(f.nextRVer, c.now)
			nr.Reason = ChangeReset
			nr.distance = f.route.distance
			f.nextRVer++
			f.route = nr
		}
	}
	for _, ep := range c.eps {
		ep.state, ep.scope = EPUnknown, ScopeUnknown
		ep.emittedState = EPUnknown
		for _, g := range ep.groups {
			g.emitted = GUnknown
		}
	}
	c.M = Metrics{}
	c.ev.resetEmitted()
}
