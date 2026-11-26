package core

import (
	"cmp"
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"time"

	"github.com/hotid/mpmtr/internal/wire"
)

// FlowRef identifies a flow inside an event.
type FlowRef struct {
	Flow       string     `json:"flow"`
	SPort      wire.Port  `json:"sport"`
	Group      string     `json:"group,omitempty"`
	Transition EventKind  `json:"transition,omitempty"`
	TTL        TTL        `json:"ttl,omitempty"`
	Old        netip.Addr `json:"old,omitzero"`
	New        netip.Addr `json:"new,omitzero"`
	Reason     string     `json:"reason,omitempty"`
}

// Event is one significant transition. Value changes inside an unchanged
// state never produce events.
type Event struct {
	Time      time.Time    `json:"time"`
	Type      EventKind    `json:"type"`
	Key       string       `json:"key"`
	Endpoint  string       `json:"endpoint,omitempty"`
	State     string       `json:"state,omitempty"`
	Scope     string       `json:"scope,omitempty"`
	PrevState string       `json:"prev_state,omitempty"`
	Group     string       `json:"group,omitempty"`
	Flows     []FlowRef    `json:"flows,omitempty"`
	Details   EventDetails `json:"details,omitempty"` // what kind of details depends on Type
}

type pendingFlow struct {
	f    *Flow
	kind EventKind
}

type pendingRoute struct {
	f        *Flow
	ttl      TTL
	old, new netip.Addr
	reason   RouteChange
	ver      int
}

type eventSink struct {
	c      *Core
	pf     []pendingFlow
	pr     []pendingRoute
	inv    []*Flow
	first  Mono
	out    func(Event)
	recent []Event
	gseq   int
	locSeq int
	epSeq  map[*Endpoint]int
}

func newEventSink(c *Core) *eventSink { return &eventSink{c: c, epSeq: map[*Endpoint]int{}} }

// SetEventHandler registers the consumer of events (JSONL writer, UI).
func (c *Core) SetEventHandler(fn func(Event)) { c.ev.out = fn }

// RecentEvents returns the last events (newest last).
func (c *Core) RecentEvents() []Event { return c.ev.recent }

func (s *eventSink) mark() {
	if len(s.pf)+len(s.pr)+len(s.inv) == 0 {
		s.first = s.c.now
	}
}

func (s *eventSink) flow(f *Flow, kind EventKind) {
	s.mark()
	s.pf = append(s.pf, pendingFlow{f, kind})
}

func (s *eventSink) routeChanged(f *Flow, ttl TTL, old, nu netip.Addr, reason RouteChange) {
	s.mark()
	s.pr = append(s.pr, pendingRoute{f: f, ttl: ttl, old: old, new: nu, reason: reason, ver: f.nextRVer - 1})
}

func (s *eventSink) flowInvalid(f *Flow) {
	s.mark()
	s.inv = append(s.inv, f)
}

func (s *eventSink) resetEmitted() { s.pf, s.pr, s.inv = nil, nil, nil }

func (s *eventSink) emit(e Event) {
	e.Time = s.c.nowRT.Time()
	if len(s.recent) >= 64 {
		s.recent = s.recent[1:]
	}
	s.recent = append(s.recent, e)
	if s.out != nil {
		s.out(e)
	}
}

func (s *eventSink) global(typ EventKind, reasons []string) {
	if typ == EvMonitoringImpaired {
		s.gseq++
	}
	e := Event{Type: typ, Key: fmt.Sprintf("monitor#%d", s.gseq)}
	if reasons != nil {
		e.Details = &MonitorDetails{Reasons: reasons}
	}
	s.emit(e)
}

func (s *eventSink) localization(ep *Endpoint, prev Localization) {
	L := ep.loc
	old := prev.Level
	s.locSeq++
	s.emit(Event{Type: EvLocalization, Key: fmt.Sprintf("%s/localization#%d", ep.Target, s.locSeq), Endpoint: ep.Target,
		State: L.Level.String(), PrevState: old.String(),
		Details: &LocalizationDetails{OldLevel: old, NewLevel: L.Level, Segments: L.Segments,
			LossStartTTL: L.SuspectedLossStartTTL, AffectedGroups: L.AffectedGroups,
			AffectedFlows: L.BadFlows, GoodGroups: L.GoodGroups, Supporting: L.Supporting,
			Contradicting: L.Contradicting, Limitations: L.Limitations, Quality: L.Quality}})
}

func flowKey(f *Flow, fam string, seq int) string {
	return fmt.Sprintf("%s/%s:%d/%s#%d", f.EP.Target, f.Name(), f.SPort(), fam, seq)
}

func ref(f *Flow, tr EventKind) FlowRef {
	r := FlowRef{Flow: f.Name(), SPort: f.SPort(), Transition: tr}
	if f.group != nil {
		r.Group = f.group.ID
	}
	return r
}

// flush aggregates pending transitions into events. Simultaneous transitions
// of several flows are reported once at the highest level (endpoint or
// group) that describes them; flow detail is kept inside the event.
// Recovery is never suppressed.
func (s *eventSink) flush(force bool) {
	c := s.c
	if len(s.pf)+len(s.pr)+len(s.inv) == 0 {
		// Endpoint/group emitted states still track silent changes.
		return
	}
	if !force && c.now-s.first < Mono(2*time.Second) {
		return
	}
	pf, pr, inv := s.pf, s.pr, s.inv
	s.pf, s.pr, s.inv = nil, nil, nil

	for _, f := range inv {
		s.emit(Event{Type: EvMonitoringImpaired, Key: fmt.Sprintf("%s/%s:%d/invalid", f.EP.Target, f.Name(), f.SPort()),
			Endpoint: f.EP.Target, Flows: []FlowRef{ref(f, EvMeasurementInvalid)},
			Details: &MonitorDetails{Reason: f.invalid, Scope: "flow"}})
	}
	byEP := map[*Endpoint][]pendingFlow{}
	var eps []*Endpoint
	for _, p := range pf {
		if _, ok := byEP[p.f.EP]; !ok {
			eps = append(eps, p.f.EP)
		}
		byEP[p.f.EP] = append(byEP[p.f.EP], p)
	}
	slices.SortFunc(eps, func(a, b *Endpoint) int { return cmp.Compare(a.ID, b.ID) })
	for _, ep := range eps {
		s.flushEndpoint(ep, byEP[ep])
	}
	s.flushRoutes(pr)
}

func (s *eventSink) flushEndpoint(ep *Endpoint, pf []pendingFlow) {
	c := s.c
	c.evalGroups(ep)
	c.evalEndpoint(ep)
	var availLoss, rtt []pendingFlow
	for _, p := range pf {
		if p.kind.rtt() {
			rtt = append(rtt, p)
		} else {
			availLoss = append(availLoss, p)
		}
	}
	consumed := map[*Flow]bool{}
	hasRecovery := false
	for _, p := range availLoss {
		if p.kind.recovery() {
			hasRecovery = true
		}
	}
	// Endpoint level.
	old, oldSc := ep.emittedState, ep.emittedScope
	st, sc := ep.state, ep.scope
	typ := EvNone
	switch {
	case st == EPDown && old != EPDown:
		typ = EvEndpointDown
	case st == EPLoss && sc != ScopeUnknown && (old != EPLoss || oldSc != sc):
		if sc == ScopePartial {
			typ = EvPartialPathFailure
		} else {
			typ = EvEndpointLoss
		}
	case (old == EPLoss || old == EPDown) && (st == EPOK || (st == EPUnknown && hasRecovery)):
		typ = EvEndpointRecovered
	}
	if typ != EvNone {
		if typ != EvEndpointRecovered {
			s.epSeq[ep]++
		}
		d := &EndpointDetails{FlowsTotal: ep.agg.Total, FlowsDown: ep.agg.Down, FlowsLoss: ep.agg.Loss,
			FlowsOK: ep.agg.OK, FlowsUnknown: ep.agg.Unknown, Coverage: ep.agg.Coverage}
		e := Event{Type: typ, Key: fmt.Sprintf("%s/endpoint#%d", ep.Target, s.epSeq[ep]), Endpoint: ep.Target,
			State: st.String(), Scope: sc.String(), PrevState: old.String(), Details: d}
		for _, p := range availLoss {
			e.Flows = append(e.Flows, ref(p.f, p.kind))
			consumed[p.f] = true
		}
		for _, g := range ep.groups {
			if g.State != g.emitted {
				d.Groups = append(d.Groups, g.ID+":"+g.State.String())
			}
		}
		s.emit(e)
	}
	switch {
	case typ != EvNone:
		ep.emittedState, ep.emittedScope = st, sc
	case st == EPOK:
		ep.emittedState, ep.emittedScope = st, sc
	case st == EPUnknown && old != EPDown && old != EPLoss:
		ep.emittedState, ep.emittedScope = st, sc
	}
	// Group level for transitions not yet described.
	for _, g := range ep.groups {
		var mine []pendingFlow
		for _, p := range availLoss {
			if !consumed[p.f] && p.f.group == g {
				mine = append(mine, p)
			}
		}
		monitored := len(g.measured())
		prev := g.emitted
		g.emitted = g.State
		if prev == g.State {
			continue
		}
		recovering := (prev == GDown || prev == GLoss) && g.State != GLoss && g.State != GDown
		if recovering && g.problemEmitted {
			// fall through: always report recovery of a reported group problem
		} else if len(mine) < 2 || monitored < 2 {
			continue
		}
		gt := EvNone
		switch {
		case g.State == GDown:
			gt = EvGroupDown
		case g.State == GLoss && prev != GDown:
			gt = EvGroupLoss
		case (prev == GDown || prev == GLoss) && g.State != GLoss && g.State != GDown:
			gt = EvGroupRecovered
		}
		if gt == EvNone {
			continue
		}
		if gt != EvGroupRecovered {
			g.incSeq++
			g.problemEmitted = true
		} else {
			g.problemEmitted = false
		}
		e := Event{Type: gt, Key: fmt.Sprintf("%s/%s/group#%d", ep.Target, g.ID, g.incSeq), Endpoint: ep.Target,
			Group: g.ID, State: g.State.String(), PrevState: prev.String(),
			Details: &GroupDetails{Level: g.Level, Partial: g.Partial, Hetero: g.Hetero}}
		for _, p := range mine {
			e.Flows = append(e.Flows, ref(p.f, p.kind))
			consumed[p.f] = true
		}
		s.emit(e)
	}
	// Remaining flow transitions.
	for _, p := range availLoss {
		// Problem transitions described by an endpoint/group event are not
		// repeated; recovery is never suppressed by aggregation.
		if consumed[p.f] && !p.kind.recovery() {
			continue
		}
		fam, seq := "down", p.f.sm.seqDown
		if p.kind == EvFlowLoss || p.kind == EvFlowLossCleared {
			fam, seq = "loss", p.f.sm.seqLoss
		}
		s.emit(Event{Type: p.kind, Key: flowKey(p.f, fam, seq), Endpoint: ep.Target,
			State: p.f.State().String(), Flows: []FlowRef{ref(p.f, p.kind)},
			Details: &FlowDetails{Quality: p.f.sm.quality, Avail: p.f.sm.avail,
				ConsecFail: p.f.sm.consecFail, ConsecPos: p.f.sm.consecPos}})
	}
	// RTT transitions: one event per (type, group).
	type rk struct {
		typ EventKind
		g   *Group
	}
	rg := map[rk][]*Flow{}
	var order []rk
	for _, p := range rtt {
		k := rk{p.kind, p.f.group}
		if _, ok := rg[k]; !ok {
			order = append(order, k)
		}
		rg[k] = append(rg[k], p.f)
	}
	for _, k := range order {
		fs := rg[k]
		gid := ""
		if k.g != nil {
			gid = k.g.ID
		}
		e := Event{Type: k.typ, Endpoint: ep.Target, Group: gid,
			Key: flowKey(fs[0], "rtt", fs[0].sm.seqRTT)}
		if len(fs) > 1 {
			e.Key = fmt.Sprintf("%s/%s/rtt#%d", ep.Target, gid, fs[0].sm.seqRTT)
		}
		kinds := []string{}
		for _, f := range fs {
			r := ref(f, k.typ)
			if f.sm.rttRel {
				r.Reason = "relative"
			}
			if f.sm.rttAbs {
				r.Reason += "+absolute"
			}
			e.Flows = append(e.Flows, r)
			kinds = append(kinds, r.Reason)
		}
		e.Details = &RTTDetails{Kinds: kinds}
		s.emit(e)
	}
}

func (s *eventSink) flushRoutes(pr []pendingRoute) {
	type rk struct {
		ep *Endpoint
		g  *Group
	}
	m := map[rk][]pendingRoute{}
	var order []rk
	for _, p := range pr {
		k := rk{p.f.EP, p.f.group}
		if _, ok := m[k]; !ok {
			order = append(order, k)
		}
		m[k] = append(m[k], p)
	}
	for _, k := range order {
		ps := m[k]
		gid := ""
		if k.g != nil {
			gid = k.g.ID
		}
		e := Event{Type: EvRouteChanged, Endpoint: k.ep.Target, Group: gid,
			Key: fmt.Sprintf("%s/%s:%d/route#%d", k.ep.Target, ps[0].f.Name(), ps[0].f.SPort(), ps[0].ver)}
		for _, p := range ps {
			r := ref(p.f, EvRouteChanged)
			r.TTL, r.Reason = p.ttl, p.reason.String()
			r.Old, r.New = p.old, p.new
			e.Flows = append(e.Flows, r)
		}
		e.Details = &RouteDetails{Note: "route change is not packet loss"}
		s.emit(e)
	}
}

// checkEndpoint emits endpoint-level transitions that happened without a
// pending flow transition (e.g. scope refined from UNKNOWN to PARTIAL once
// the other flows finished warmup).
func (s *eventSink) checkEndpoint(ep *Endpoint) {
	for _, p := range s.pf {
		if p.f.EP == ep {
			return
		}
	}
	s.flushEndpoint(ep, nil)
}

// Flush forces pending events out (used at shutdown and in tests).
func (c *Core) Flush() {
	c.now, c.nowRT = c.clk.Now()
	c.ev.flush(true)
}

// EventDetails is what an event says beyond its common fields: one of the
// *Details types below, by the event's Type.
type EventDetails interface{ eventDetails() }

// MonitorDetails: the measurer itself is impaired (reasons), or one port
// cannot be measured (reason, scope "flow").
type MonitorDetails struct {
	Reasons []string      `json:"reasons,omitempty"`
	Reason  InvalidReason `json:"reason,omitempty"`
	Scope   string        `json:"scope,omitempty"`
}

// LocalizationDetails of LOCALIZATION_RESULT.
type LocalizationDetails struct {
	OldLevel       LocLevel  `json:"old_level"`
	NewLevel       LocLevel  `json:"new_level"`
	Segments       []Segment `json:"suspected_segments"`
	LossStartTTL   TTL       `json:"suspected_loss_start_ttl"`
	AffectedGroups []string  `json:"affected_groups"`
	AffectedFlows  []string  `json:"affected_flows"`
	GoodGroups     []string  `json:"good_groups"`
	Supporting     []string  `json:"supporting"`
	Contradicting  []string  `json:"contradicting"`
	Limitations    []string  `json:"limitations"`
	Quality        []string  `json:"quality"`
}

// EndpointDetails of the ENDPOINT_* events and PARTIAL_PATH_FAILURE.
type EndpointDetails struct {
	FlowsTotal   int      `json:"flows_total"`
	FlowsDown    int      `json:"flows_down"`
	FlowsLoss    int      `json:"flows_loss"`
	FlowsOK      int      `json:"flows_ok"`
	FlowsUnknown int      `json:"flows_unknown"`
	Coverage     float64  `json:"coverage"`
	Groups       []string `json:"groups,omitempty"` // routes whose state changed: "ID:STATE"
}

// GroupDetails of the PATHGROUP_* events.
type GroupDetails struct {
	Level   Level `json:"level"`
	Partial bool  `json:"partial"`
	Hetero  bool  `json:"intragroup_heterogeneity"`
}

// FlowDetails of the FLOW_* events.
type FlowDetails struct {
	Quality    Quality `json:"quality"`
	Avail      Avail   `json:"avail"`
	ConsecFail int     `json:"consecutive_failures"`
	ConsecPos  int     `json:"consecutive_positive"`
}

// RTTDetails of the RTT_* events: per flow, "relative", "+absolute" or both.
type RTTDetails struct {
	Kinds []string `json:"kinds"`
}

// RouteDetails of ROUTE_CHANGED.
type RouteDetails struct {
	Note string `json:"note"`
}

func (*MonitorDetails) eventDetails()      {}
func (*LocalizationDetails) eventDetails() {}
func (*EndpointDetails) eventDetails()     {}
func (*GroupDetails) eventDetails()        {}
func (*FlowDetails) eventDetails()         {}
func (*RTTDetails) eventDetails()          {}
func (*RouteDetails) eventDetails()        {}

// detailsFor is an empty details value of the kind an event type carries
// (nil: none).
func detailsFor(k EventKind) EventDetails {
	switch k {
	case EvMonitoringImpaired, EvMonitoringRecovered:
		return &MonitorDetails{}
	case EvLocalization:
		return &LocalizationDetails{}
	case EvEndpointDown, EvEndpointLoss, EvPartialPathFailure, EvEndpointRecovered:
		return &EndpointDetails{}
	case EvGroupDown, EvGroupLoss, EvGroupRecovered:
		return &GroupDetails{}
	case EvFlowDown, EvFlowLoss, EvFlowRecovered, EvFlowLossCleared:
		return &FlowDetails{}
	case EvRTTDegradation, EvRTTRecovered:
		return &RTTDetails{}
	case EvRouteChanged:
		return &RouteDetails{}
	}
	return nil
}

// UnmarshalJSON reads an event back: the details are read as the kind the
// event's type carries.
func (e *Event) UnmarshalJSON(b []byte) error {
	type plain Event
	aux := struct {
		*plain
		Details json.RawMessage `json:"details"`
	}{plain: (*plain)(e)}
	if err := json.Unmarshal(b, &aux); err != nil {
		return err
	}
	e.Details = nil
	if len(aux.Details) == 0 || string(aux.Details) == "null" {
		return nil
	}
	d := detailsFor(e.Type)
	if d == nil {
		return fmt.Errorf("event %s carries no details, got %s", e.Type, aux.Details)
	}
	if err := json.Unmarshal(aux.Details, d); err != nil {
		return fmt.Errorf("details of %s: %w", e.Type, err)
	}
	e.Details = d
	return nil
}
