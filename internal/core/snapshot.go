package core

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/hotid/mpmtr/internal/wire"

	"github.com/hotid/mpmtr/internal/stats"
)

// WinSnap is a statistics window. Rates are nil when valid == 0 (UNKNOWN).
type WinSnap struct {
	Valid       int64    `json:"valid"`
	Timeout     int64    `json:"timeout"`
	Unreach     int64    `json:"icmp_unreachable"`
	Positive    int64    `json:"positive"`
	Skipped     int64    `json:"skipped"`
	Impaired    int64    `json:"impaired_or_local"`
	TimeoutRate *float64 `json:"timeout_rate"`
	FailureRate *float64 `json:"failure_rate"`
	ReplyRate   *float64 `json:"reply_rate"`
	WilsonLo    *float64 `json:"failure_wilson95_lo"`
	WilsonHi    *float64 `json:"failure_wilson95_hi"`
	// Application checks (--app): counted apart from TCP, with a rate of
	// their own. Absent without checks.
	App         int64    `json:"app_checks,omitempty"`
	AppFail     int64    `json:"app_failed,omitempty"`
	AppFailRate *float64 `json:"app_failure_rate,omitempty"`
}

func fp(v float64) *float64 { return &v }

// RouteVerSnap is an earlier version of a flow's route with the end-to-end
// results measured while it lasted.
type RouteVerSnap struct {
	Ver       int         `json:"version"`
	StartMs   int64       `json:"start_uptime_ms"`
	EndMs     int64       `json:"end_uptime_ms"`
	EndedBy   RouteChange `json:"ended_by"` // why the next version started
	Sig       string      `json:"signature"`
	Valid     uint64      `json:"valid"`
	Failed    uint64      `json:"failed"`
	MeanRTTUs *float64    `json:"mean_rtt_us"`
}

func winSnap(w Window) WinSnap {
	s := WinSnap{Valid: w.Valid, Timeout: w.Timeout, Unreach: w.Unreach, App: w.App, AppFail: w.AppFail, Positive: w.Positive, Skipped: w.Skipped, Impaired: w.Impaired}
	if w.App > 0 {
		s.AppFailRate = fp(float64(w.AppFail) / float64(w.App))
	}
	if w.Valid > 0 {
		v := float64(w.Valid)
		s.TimeoutRate = fp(float64(w.Timeout) / v)
		s.FailureRate = fp(float64(w.Failures()) / v)
		s.ReplyRate = fp(float64(w.Positive) / v)
		lo, hi := stats.Wilson(w.Failures(), w.Valid)
		s.WilsonLo, s.WilsonHi = fp(lo), fp(hi)
	}
	return s
}

// RTTSnap summarizes RTT in microseconds.
type RTTSnap struct {
	N             int     `json:"n"`
	Last          uint32  `json:"last_us"`
	Min           uint32  `json:"min_us"`
	Mean          float64 `json:"mean_us"`
	Median        uint32  `json:"median_us"`
	P95           uint32  `json:"p95_us"`
	P99           *uint32 `json:"p99_us,omitempty"`
	Max           uint32  `json:"max_us"`
	Jitter        float64 `json:"jitter_us"`
	Baseline      uint32  `json:"baseline_us,omitempty"`
	BaselineKnown bool    `json:"baseline_known"`
	Window        int     `json:"recent_samples"`
}

// HopSnap is one hop row.
type HopSnap struct {
	TTL       TTL          `json:"ttl"`
	TTLTo     TTL          `json:"ttl_to,omitempty"`   // collapsed run of non-answering TTLs`
	Kind      HopKind      `json:"kind"`               // what the row stands for
	Responder netip.Addr   `json:"responder,omitzero"` // the router that answers (hop, dst)
	Server    string       `json:"server,omitempty"`   // server rows: its name
	AppNote   string       `json:"app_note,omitempty"` // DST and server rows: what the --app plugin noted
	Others    []netip.Addr `json:"other_responders,omitempty"`
	Sent      uint32       `json:"sent"`
	Replies   uint32       `json:"replies"`
	LossOK    bool         `json:"-"`
	Loss      *float64     `json:"apparent_loss"`
	Last      uint32       `json:"rtt_last_us"`
	Min       uint32       `json:"rtt_min_us"`
	Median    uint32       `json:"rtt_median_us"`
	P95       uint32       `json:"rtt_p95_us"`
	Max       uint32       `json:"rtt_max_us"`
	Jitter    float64      `json:"jitter_us"`
	AgeMs     int64        `json:"age_ms"`
	Unstable  bool         `json:"unstable,omitempty"`
	Through   []netip.Addr `json:"also_answered_by,omitempty"` // routers of later TTLs that answered probes sent with this TTL too
	Stale     bool         `json:"stale,omitempty"`
	RateLimit bool         `json:"possible_icmp_rate_limit,omitempty"`
	LowConf   uint32       `json:"quote_seq_mismatch,omitempty"`
	Unreach   bool         `json:"icmp_unreachable,omitempty"`
	// MPLS is the label stack the router reported (RFC 4950), outermost
	// first. MPLSStacks lists every different stack when the ports whose
	// hop this row sums up were given different ones (MPLS is then the first).
	MPLS       []uint32   `json:"mpls_labels,omitempty"`
	MPLSStacks [][]uint32 `json:"mpls_stacks,omitempty"`
	Flows      int        `json:"flows"`
	Name       string     `json:"name,omitempty"`
	// What the row's numbers say once the rows after it are taken into
	// account (the live screen colours by these).
	// LossPersists: the hop's share of unanswered probes is significant and
	// so is that of every answering hop after it, down to a destination
	// that loses end to end. On a DST or server row: its own end-to-end
	// loss is significant.
	// RTTShift: the row's recent round-trip times stand above its own
	// earlier ones, and on a hop row the same holds on every hop after it,
	// down to the destination. RTTSpike (DST and server rows): only the
	// last sample does.
	LossPersists bool `json:"loss_persists_downstream,omitempty"`
	RTTShift     bool `json:"rtt_shift,omitempty"`
	RTTSpike     bool `json:"rtt_spike,omitempty"`
	rttUp        bool // the row's own recent RTT is above its history
	rttKnown     bool // enough samples to say so
}

// FlowSnap is one flow.
type FlowSnap struct {
	Name        string         `json:"flow"`
	ID          FlowID         `json:"id"`
	SPort       wire.Port      `json:"sport"`
	Focus       bool           `json:"focus,omitempty"` // traced in full every interval (live screen, key f)
	Src         netip.Addr     `json:"src"`
	Role        Role           `json:"role"`
	State       FState         `json:"state"`
	Avail       Avail          `json:"availability"`
	Quality     Quality        `json:"quality"`
	Reason      Reason         `json:"reason,omitempty"`
	Invalid     InvalidReason  `json:"invalid_reason,omitempty"` // why the port cannot be measured (reason "invalid")
	Flags       FlowFlags      `json:"flags,omitempty"`
	Group       string         `json:"group,omitempty"`
	Level       Level          `json:"group_level"`
	C           Counters       `json:"counters"`
	ACMoved     int            `json:"anycast_answers_other_server,omitempty"`
	ACUnknown   int            `json:"anycast_answers_unknown_clock,omitempty"`
	ACServer    string         `json:"anycast_server,omitempty"`
	AppStage    string         `json:"app_last_failure_stage,omitempty"`
	AppErr      string         `json:"app_last_failure,omitempty"`
	AppNote     string         `json:"app_note,omitempty"`
	Executed    int            `json:"executed"`
	W60         WinSnap        `json:"window_60s"`
	W5          WinSnap        `json:"window_5m"`
	Life        WinSnap        `json:"lifetime"`
	RTT         RTTSnap        `json:"rtt"`
	SinceOKMs   int64          `json:"ms_since_last_success"`
	ConsecFail  int            `json:"consecutive_failures"`
	DownNeed    int            `json:"down_after_failures"` // consecutive failures that make it DOWN now
	BGLoss      float64        `json:"background_loss"`     // loss outside DOWN periods (decayed, half-life 30 min)
	FailAfter   float64        `json:"fail_after_fail"`     // P(failure | previous failure) in that background
	ConsecPos   int            `json:"consecutive_positive"`
	Episodes    int            `json:"loss_episodes"`
	MaxRun      int            `json:"max_loss_run"`
	MeanRun     float64        `json:"mean_loss_run"`
	RouteVer    int            `json:"route_version"`
	RouteVers   int            `json:"route_versions"`
	RouteHist   []RouteVerSnap `json:"route_history,omitempty"` // earlier versions of the route, oldest first
	Distance    TTL            `json:"distance"`
	Sig         string         `json:"signature,omitempty"`
	AssumedHops []TTL          `json:"assumed_hops,omitempty"` // TTLs of the signature this port got no answer at: the router is the one the other ports saw there
	OldestHopMs int64          `json:"oldest_hop_age_ms"`
	Hops        []HopSnap      `json:"hops,omitempty"`
}

// GroupSnap is one PathGroup.
type GroupSnap struct {
	ID           string      `json:"id"`
	Level        Level       `json:"level"`
	State        GState      `json:"state"`
	Flows        []string    `json:"flows"`
	Ports        []wire.Port `json:"sports"`
	Tentative    []string    `json:"tentative_flows,omitempty"`
	Monitored    int         `json:"monitored"`
	Measured     []wire.Port `json:"measured_sports,omitempty"`
	Warmup       int         `json:"warmup_flows,omitempty"` // monitored flows still collecting their first samples
	W5           WinSnap     `json:"window_5m"`
	WorstFailure *float64    `json:"worst_flow_failure_rate"`
	RTTMedian    uint32      `json:"rtt_median_us"`
	Sig          string      `json:"signature"`
	Hetero       bool        `json:"intragroup_heterogeneity,omitempty"`
	Partial      bool        `json:"partial,omitempty"`
	HiddenHops   bool        `json:"hidden_hops,omitempty"`
}

// AnycastSnap is the census of the servers behind an anycast address.
type AnycastSnap struct {
	Status   AnycastStatus `json:"status"` // running | done | unidentifiable | no_timestamps
	Explored int           `json:"ports_explored"`
	Answers  int           `json:"answers"`
	Moved    int           `json:"answers_from_another_server"`
	Unknown  int           `json:"answers_from_unknown_clock"`
	Phantoms int           `json:"phantom_servers_dropped,omitempty"`
	GivenUp  int           `json:"census_given_up,omitempty"` // census SYNs that never got their turn
	Servers  []ServerSnap  `json:"servers"`
}

// ServerSnap is one server behind the address.
type ServerSnap struct {
	Name     string      `json:"name"`
	Hz       ClockRate   `json:"ts_hz"`
	Ports    int         `json:"ports"`
	Measured []wire.Port `json:"measured_sports,omitempty"`
	Flows    []string    `json:"measured_flows,omitempty"`
	Groups   []string    `json:"groups,omitempty"` // routes of its measured ports
	State    RowState    `json:"state"`
	E2E      HopSnap     `json:"e2e"`                  // the measured ports' end-to-end probes
	App      [2]uint64   `json:"app_checks,omitempty"` // application checks done, failed
}

// Unresolved is a traced port whose incomplete trace (a hop that has not
// answered yet) fits several routes; it joins one when the hop answers.
type Unresolved struct {
	Flow  string    `json:"flow"`
	SPort wire.Port `json:"sport"`
	Fits  []string  `json:"fits_groups"`
}

// TreeRow is one line of the route tree.
type TreeRow struct {
	SPort  wire.Port   `json:"sport,omitempty"`  // measured port behind the row (server rows)
	SPorts []wire.Port `json:"sports,omitempty"` // server rows: all its measured ports on this route
	App    [2]uint64   `json:"app,omitempty"`    // server rows: application checks done, failed
	State  RowState    `json:"state,omitempty"`  // server rows: state of its measured port(s)
	Prefix string      `json:"prefix"`
	// Path names the row and stays the same from one snapshot to the next
	// (the screen remembers the selected and the folded rows by it). It is a
	// name only: where the row hangs in the tree is Parent.
	Path   string     `json:"path"`
	Parent int        `json:"parent"` // index of the row this one hangs under; -1 at the top
	Branch bool       `json:"branch"` // drawn with a connector: one of several rows under its parent
	E2E    bool       `json:"e2e"`
	Hop    HopSnap    `json:"hop"`
	Group  *GroupSnap `json:"group,omitempty"`
}

// EPSnap is one endpoint.
type EPSnap struct {
	Target       string          `json:"target"`
	Addr         netip.Addr      `json:"addr"`
	Port         wire.Port       `json:"port"`
	State        EPState         `json:"state"`
	Scope        Scope           `json:"scope"`
	Agg          EndpointAgg     `json:"flows_summary"`
	W5           WinSnap         `json:"window_5m"`
	Coverage     Coverage        `json:"group_coverage"`
	Discovery    DiscoveryStatus `json:"discovery"`
	Groups       []GroupSnap     `json:"groups"`
	Flows        []FlowSnap      `json:"flows"`
	Candidates   int             `json:"discovery_only_flows"`
	Tree         []TreeRow       `json:"tree,omitempty"`
	Localization Localization    `json:"localization"`
	Hetero       Heterogeneity   `json:"heterogeneity"`
	Unassigned   []string        `json:"flows_without_group,omitempty"`
	Unresolved   []Unresolved    `json:"unresolved_flows,omitempty"`
	Stopped      []StoppedFlow   `json:"stopped_flows,omitempty"`
	RouteRefresh int64           `json:"route_refresh_est_ms"`
	Incident     bool            `json:"incident_trace_active"`
	Anycast      *AnycastSnap    `json:"anycast,omitempty"`
}

// Snapshot is a consistent copy of the core state for UI and reports.
type Snapshot struct {
	Time            time.Time `json:"time"`
	UptimeMs        int64     `json:"uptime_ms"`
	Epoch           int       `json:"measurement_epoch"`
	WindowLongS     float64   `json:"window_long_seconds"`  // length of the "5m" window (longer when --interval > 1s)
	WindowShortS    float64   `json:"window_short_seconds"` // length of the "60s" window
	Endpoints       []EPSnap  `json:"endpoints"`
	M               Metrics   `json:"metrics"`
	HopPPS          float64   `json:"hop_pps"`
	E2EPPS          float64   `json:"e2e_pps"`
	Inflight        int       `json:"inflight"`
	RespLimited     int       `json:"responders_limited"`
	Responders      int       `json:"responders_tracked"`
	Impaired        bool      `json:"monitoring_impaired"`
	ImpairedReasons []string  `json:"monitoring_impaired_reasons,omitempty"`
	LagAvgMs        float64   `json:"scheduler_lag_avg_ms"`
	LagMaxMs        float64   `json:"scheduler_lag_max_ms"`
	Events          []Event   `json:"-"`
}

// SnapOpts select the level of detail.
type SnapOpts struct {
	Hops bool // per-flow hop tables
	Tree bool
	Only EndpointID // the endpoint to include in detail (AllEndpoints: every one)
}

// Snapshot builds a snapshot.
func (c *Core) Snapshot(o SnapOpts) *Snapshot {
	c.now, c.nowRT = c.clk.Now()
	s := &Snapshot{Time: c.nowRT.Time(), UptimeMs: int64(c.now / Mono(time.Millisecond)), Epoch: c.epochNum,
		WindowLongS: (WindowLong * time.Duration(c.bucket)).Seconds(), WindowShortS: (WindowShort * time.Duration(c.bucket)).Seconds(), M: c.M,
		HopPPS: c.hopRate.rate(c.now), E2EPPS: c.e2eRate.rate(c.now), Inflight: c.inflight,
		Impaired: c.monitorImpaired(), ImpairedReasons: c.impairedReasons(), Responders: len(c.resp)}
	for _, rb := range c.resp {
		if !rb.tb.Available(int64(c.now)) {
			s.RespLimited++
		}
	}
	if c.M.LagN > 0 {
		s.LagAvgMs = float64(c.M.LagSum/Mono(c.M.LagN)) / 1e6
	}
	s.LagMaxMs = float64(c.M.LagMax) / 1e6
	s.Events = append([]Event(nil), c.ev.recent...)
	for _, ep := range c.eps {
		detail := o.Only == AllEndpoints || o.Only == ep.ID
		s.Endpoints = append(s.Endpoints, c.epSnap(ep, detail && o.Hops, detail && o.Tree))
	}
	return s
}

func (c *Core) epSnap(ep *Endpoint, hops, tree bool) EPSnap {
	c.evalGroups(ep)
	c.evalEndpoint(ep)
	e := EPSnap{Target: ep.Target, Addr: ep.Addr, Port: ep.Port, State: ep.state, Scope: ep.scope,
		Agg: ep.agg, W5: winSnap(ep.agg.W5), Coverage: ep.coverage, Discovery: ep.discoveryStatus(c.cfg.Discovery),
		Localization: ep.loc, Hetero: ep.hetero, Incident: ep.incident != nil}
	for _, st := range ep.stopped {
		// A route's identifier follows what is known of the route: say the
		// one the port's route has now, not the one it had when it stopped.
		if f := ep.byPort[st.SPort]; st.Group != "" && f != nil && f.group != nil {
			st.Group = f.group.ID
		}
		e.Stopped = append(e.Stopped, st)
	}
	if ep.ac != nil {
		e.Anycast = c.anycastSnap(ep)
	}
	var refresh []int64
	for _, f := range ep.Flows {
		// Only ports that will still resolve: measured ones (hop refresh
		// keeps probing) or ones being traced. A discovery candidate left
		// half-traced when discovery stopped never gets another probe.
		if len(f.fits) > 1 && (f.Role.Monitored() || f.sw != nil && !f.sw.done) {
			u := Unresolved{Flow: f.Name(), SPort: f.SPort()}
			for _, g := range f.fits {
				u.Fits = append(u.Fits, g.ID)
			}
			e.Unresolved = append(e.Unresolved, u)
		}
		if !f.Role.Monitored() {
			if f.route.sweeps > 0 || f.sw != nil {
				e.Candidates++
			}
			continue
		}
		fs := c.flowSnap(f, hops)
		e.Flows = append(e.Flows, fs)
		if fs.OldestHopMs > 0 {
			refresh = append(refresh, fs.OldestHopMs)
		}
		if f.group == nil {
			e.Unassigned = append(e.Unassigned, f.Name())
		}
	}
	if len(refresh) > 0 {
		slices.Sort(refresh)
		e.RouteRefresh = refresh[len(refresh)/2]
	}
	for _, g := range ep.groups {
		e.Groups = append(e.Groups, c.groupSnap(g))
	}
	if tree {
		e.Tree = c.buildTree(ep)
	}
	return e
}

func (c *Core) flowSnap(f *Flow, hops bool) FlowSnap {
	bn := c.bucketNum(c.now)
	sm := &f.sm
	s := FlowSnap{Name: f.Name(), ID: f.ID, SPort: f.SPort(), Focus: f == c.focus, Src: f.Tmpl.Src, Role: f.Role,
		State: f.State(), Avail: sm.avail, Quality: sm.quality, Reason: sm.reason, Invalid: f.invalid,
		Level: f.level, C: f.C, Executed: f.Executed,
		W60: winSnap(f.win.sum(bn, WindowShort)), W5: winSnap(f.win.sum(bn, WindowLong)),
		ConsecFail: sm.consecFail, ConsecPos: sm.consecPos, Episodes: f.episode.episodes, MaxRun: f.episode.max,
		MeanRun: f.episode.mean(), RouteVer: f.route.Ver, RouteVers: len(f.routeHist) + 1, Distance: f.route.distance,
		Sig: f.sig.canon, AssumedHops: f.sig.assumed, SinceOKMs: -1, DownNeed: c.downNeed(f)}
	s.BGLoss, s.FailAfter = sm.bg.rates()
	for i, r := range f.routeHist {
		next := f.route
		if i+1 < len(f.routeHist) {
			next = f.routeHist[i+1]
		}
		v := RouteVerSnap{Ver: r.Ver, StartMs: int64(r.Start / Mono(time.Millisecond)), EndMs: int64(r.End / Mono(time.Millisecond)),
			EndedBy: next.Reason, Sig: computeSig(r).canon, Valid: r.E2EValid, Failed: r.E2EFail}
		if r.RTTN > 0 {
			v.MeanRTTUs = fp(r.RTTSum / float64(r.RTTN))
		}
		s.RouteHist = append(s.RouteHist, v)
	}
	s.Life = winSnap(Window{Valid: int64(f.C.Valid()), Timeout: int64(f.C.Timeout), Unreach: int64(f.C.Unreach), App: int64(f.C.AppOK + f.C.AppFail), AppFail: int64(f.C.AppFail),
		Positive: int64(f.C.SynAck + f.C.Rst + f.C.AppOK + f.C.AppFail), Skipped: int64(f.C.Skipped), Impaired: int64(f.C.Impaired + f.C.LocalErr)})
	if f.group != nil {
		s.Group = f.group.ID
	}
	if sm.avail == AvailDown {
		// quality is not evaluated while DOWN; what stays is why it is DOWN
		// when TCP itself answers
		if s.Reason != ReasonAppDown {
			s.Reason = ReasonNone
		}
	}
	if sm.lastPos != 0 {
		s.SinceOKMs = int64((c.now - sm.lastPos) / Mono(time.Millisecond))
	}
	add := func(cond bool, flag FlowFlag) {
		if cond {
			s.Flags = append(s.Flags, flag)
		}
	}
	add(sm.stale, FlagStale)
	add(sm.impaired || c.monitorImpaired(), FlagImpaired)
	add(f.invalid != ValidFlow, FlagInvalid)
	add(sm.rttRel || sm.rttAbs, FlagRTTDegraded)
	add(sm.rttRel, FlagRTTRelative)
	add(sm.rttAbs, FlagRTTAbsolute)
	add(sm.baselineUnknown || !f.rtt.baseline.established, FlagBaselineUnknown)
	add(sm.downHeld, FlagDownHeld)
	add(f.C.Weak > 0, FlagSeqTranslation)
	add(f.C.RstMissing > 0, FlagRSTMissing)
	add(f.incident != nil, FlagIncidentTrace)
	add(sm.avail == AvailUp && sm.quality == QUnknown && sm.epoch > 0, FlagQualityPending)
	// RTT
	var v []uint32
	f.rtt.ring.Do(func(x rttSample) { v = append(v, x.us) })
	sum := stats.Summarize(v)
	s.RTT = RTTSnap{N: int(f.rtt.n), Last: f.rtt.last, Min: f.rtt.min, Max: f.rtt.max, Median: sum.Median, P95: sum.P95,
		Jitter: f.rtt.jit.J, Window: sum.N, BaselineKnown: f.rtt.baseline.established}
	if f.rtt.n > 0 {
		s.RTT.Mean = f.rtt.sum / float64(f.rtt.n)
	}
	if sum.HasP99 {
		p := sum.P99
		s.RTT.P99 = &p
	}
	if f.rtt.baseline.established {
		s.RTT.Baseline = f.rtt.baseline.value()
	}
	var oldest int64
	for t := TTL(1); t <= f.route.top(); t++ {
		h := f.route.hopIf(t)
		if h.LastProbe != 0 {
			oldest = max(oldest, int64((c.now-h.LastProbe)/Mono(time.Millisecond)))
		}
	}
	s.OldestHopMs = oldest
	if hops {
		s.Hops = c.flowHops(f)
	}
	s.ACMoved, s.ACUnknown = f.acMoved, f.acUnknown
	s.AppStage, s.AppErr, s.AppNote = f.appStage, f.appErr, f.appNote
	if sv := f.EP.ServerOf(f.SPort()); sv != nil {
		s.ACServer = sv.Name()
		// The route of this flow ends at that server, not just at the address.
		for i := range s.Hops {
			if s.Hops[i].Kind == KindDst {
				s.Hops[i].Name = fmt.Sprintf("%s (%.0f Hz)", sv.Name(), sv.Hz)
			}
		}
	}
	return s
}

// hopStale: the hop was not probed for 30 s (three buckets: the refresh
// sends one hop probe per interval and flow, so a slow --interval needs
// longer to come round).
func (c *Core) hopStale(h *HopStat) bool {
	return h.LastProbe == 0 || c.now-h.LastProbe > 3*c.bucket
}

func (c *Core) flowHops(f *Flow) []HopSnap {
	r := f.route
	L := r.top()
	if r.distance > 0 && L > r.distance {
		L = r.distance
	}
	var out []HopSnap
	for t := TTL(1); t <= L; t++ {
		h := r.hopIf(t)
		hs := c.aggHops([]*HopStat{h}, t)
		hs.RateLimit = possibleRateLimit(r, t)
		if r.distance > 0 && t == r.distance {
			hs.Kind = KindDst
			hs.Responder = f.EP.Addr
			c.e2eFlowsAsHop([]*Flow{f}, &hs) // the flow's loss is the loss to its last hop
		}
		out = append(out, hs)
	}
	ps, parent := make([]*HopSnap, len(out)), make([]int, len(out))
	for i := range out {
		ps[i], parent[i] = &out[i], i-1
	}
	markDownstream(ps, parent) // one path: every hop hangs under the one before it
	return collapseNoReply(out)
}

// collapseNoReply merges consecutive hops without any reply into one row.
func collapseNoReply(in []HopSnap) []HopSnap {
	var out []HopSnap
	for _, h := range in {
		if h.Replies == 0 && h.Kind != KindDst && len(out) > 0 {
			p := &out[len(out)-1]
			if p.Replies == 0 && p.Kind != KindDst && (p.Kind == h.Kind || p.Kind == KindSilent || h.Kind == KindSilent) {
				to := h.TTL
				if p.TTLTo == 0 {
					p.TTLTo = p.TTL
				}
				p.TTLTo = to
				p.Sent += h.Sent
				if h.Kind == KindSilent {
					p.Kind = KindSilent
				}
				p.Stale = p.Stale && h.Stale
				continue
			}
		}
		out = append(out, h)
	}
	return out
}

// aggHops aggregates real per-flow observations of one TTL. Counts are
// sums of actually sent/answered probes — never copied between flows.
func (c *Core) aggHops(hs []*HopStat, ttl TTL) HopSnap {
	s := HopSnap{TTL: ttl, Flows: len(hs)}
	var v []uint32
	judged, shifted := 0, 0
	resp := map[netip.Addr]uint32{}
	var lastAt Mono
	var lastProbe Mono
	stale := true
	const maxMPLSStacks = 4
	var stacks [][]uint32
	for _, h := range hs {
		if h == nil {
			continue
		}
		s.Sent += h.Sent
		s.Replies += h.Replies
		s.LowConf += h.LowConf
		from := len(v)
		h.rtt.Do(func(x uint32) { v = append(v, x) })
		// Each port's samples are judged against that port's own history
		// (they are in time order only within one port).
		if sh, _, ok := stats.Level(v[from:], hopRecent); ok {
			judged++
			if sh {
				shifted++
			}
		}
		s.Unstable = s.Unstable || h.Unstable || h.multi() >= 2
		s.Unreach = s.Unreach || h.UnreachSeen
		h.responders(func(a netip.Addr, n uint32) { resp[a] += n })
		for _, a := range h.through {
			if a.IsValid() && !slices.Contains(s.Through, a) {
				s.Through = append(s.Through, a)
			}
		}
		if h.LastReply > lastAt {
			lastAt = h.LastReply
			s.Last = h.Last
		}
		if h.LastProbe > lastProbe {
			lastProbe = h.LastProbe
		}
		if !c.hopStale(h) {
			stale = false
		}
		if h.jit.Valid() {
			s.Jitter = max(s.Jitter, h.jit.J)
		}
		if h.NMPLS > 0 {
			st := make([]uint32, h.NMPLS)
			for i := range st {
				st[i] = h.MPLS[i].Label
			}
			known := slices.ContainsFunc(stacks, func(x []uint32) bool { return slices.Equal(x, st) })
			if !known && len(stacks) < maxMPLSStacks {
				stacks = append(stacks, st)
			}
		}
	}
	if len(stacks) > 0 {
		s.MPLS = stacks[0]
	}
	if len(stacks) > 1 {
		s.MPLSStacks = stacks
	}
	s.Stale = stale
	if s.Sent >= 3 {
		s.Loss = fp(float64(s.Sent-s.Replies) / float64(s.Sent))
		s.LossOK = true
	}
	// The row's RTT is up when at least half of the ports that can say see it.
	s.rttKnown, s.rttUp = judged > 0, shifted > 0 && 2*shifted >= judged
	sum := stats.Summarize(v)
	s.Min, s.Median, s.P95, s.Max = sum.Min, sum.Median, sum.P95, sum.Max
	if lastProbe != 0 {
		s.AgeMs = int64((c.now - lastProbe) / Mono(time.Millisecond))
	} else {
		s.AgeMs = -1
	}
	// dominant responder
	var best netip.Addr
	var bn uint32
	keys := make([]netip.Addr, 0, len(resp))
	for k := range resp {
		keys = append(keys, k)
	}
	slices.SortFunc(keys, netip.Addr.Compare) // a tie goes to the lower address
	for _, k := range keys {
		if resp[k] > bn {
			best, bn = k, resp[k]
		}
	}
	s.Responder = best
	for _, k := range keys {
		if k != best {
			s.Others = append(s.Others, k)
		}
	}
	switch {
	case s.Unstable:
		s.Kind = KindUnstable
	case best.IsValid():
		s.Kind = KindHop
	case len(s.Through) > 0:
		s.Kind = KindHidden // only the next hop answered the probes sent here
	case s.Sent >= 3:
		s.Kind = KindSilent
	default:
		s.Kind = KindUnknown
	}
	return s
}

func (c *Core) groupSnap(g *Group) GroupSnap {
	bn := c.bucketNum(c.now)
	s := GroupSnap{ID: g.ID, Level: g.Level, State: g.State, Sig: g.Sig.canon, Hetero: g.Hetero, Partial: g.Partial}
	var w Window
	var worst float64
	worstOK := false
	var rtts []uint32
	all := append(append([]*Flow(nil), g.Members...), g.Tentative...)
	slices.SortFunc(all, byFlowID)
	for _, f := range all {
		if f.level == LevelTentative {
			s.Tentative = append(s.Tentative, f.Name())
		} else {
			s.Flows = append(s.Flows, f.Name())
		}
		s.Ports = append(s.Ports, f.SPort())
		if f.Role.Monitored() {
			s.Measured = append(s.Measured, f.SPort())
		}
		if !f.Role.Monitored() {
			continue
		}
		s.Monitored++
		if f.State() == FUnknown && f.sm.reason == ReasonWarmup {
			s.Warmup++
		}
		fw := f.win.sum(bn, WindowLong)
		w.Valid += fw.Valid
		w.Timeout += fw.Timeout
		w.App += fw.App
		w.AppFail += fw.AppFail
		w.Unreach += fw.Unreach
		w.Positive += fw.Positive
		w.Skipped += fw.Skipped
		w.Impaired += fw.Impaired
		if r, ok := stats.Rate(fw.Failures(), fw.Valid); ok && (!worstOK || r > worst) {
			worst, worstOK = r, true
		}
		f.rtt.ring.Do(func(x rttSample) { rtts = append(rtts, x.us) })
	}
	s.W5 = winSnap(w)
	if worstOK {
		s.WorstFailure = fp(worst)
	}
	if len(rtts) > 0 {
		s.RTTMedian = stats.Median(rtts)
	}
	s.HiddenHops = slices.ContainsFunc(g.Sig.elems, func(e hopElem) bool { return e.kind == eSilent })
	return s
}

// buildTree renders PathGroups as a tree: shared prefixes are shown once
// and the tree branches where observed routes differ. Without topology no
// tree is invented.
func (c *Core) buildTree(ep *Endpoint) []TreeRow {
	type node struct {
		elem     hopElem
		ttl      TTL
		flows    []*Flow
		children []*node
		ends     []*Group
	}
	root := &node{}
	var groups []*Group
	for _, g := range ep.groups {
		if len(g.Sig.hops) == 0 && !g.Sig.distKnown {
			continue
		}
		groups = append(groups, g)
	}
	if len(groups) == 0 {
		return nil
	}
	// Display: a TTL where every route that answered shows the same router
	// (typically the first hops) is drawn as that router for routes whose
	// probe there was not answered — not as a separate branch.
	sole := map[int]netip.Addr{}
	conflict := map[int]bool{}
	for _, g := range groups {
		for i, e := range g.Sig.hops {
			if e.kind != eKnown {
				continue
			}
			if x, ok := sole[i]; ok && x != e.addr {
				conflict[i] = true
			}
			sole[i] = e.addr
		}
	}
	for _, g := range groups {
		fl := append(append([]*Flow{}, g.Members...), g.Tentative...)
		n := root
		// The route as its canonical elements: the tree is built from
		// them, never from the signature's text.
		parts := slices.Clone(g.Sig.elems)
		for i := range parts {
			if a, ok := sole[i]; ok && (parts[i].kind == eUnknown || parts[i].kind == eSilent) && !conflict[i] {
				parts[i] = hopElem{kind: eKnown, addr: a}
			}
		}
		for i, el := range parts {
			var ch *node
			for _, x := range n.children {
				if x.elem == el {
					ch = x
					break
				}
			}
			if ch == nil {
				ch = &node{elem: el, ttl: TTL(i + 1)}
				n.children = append(n.children, ch)
			}
			ch.flows = append(ch.flows, fl...)
			n = ch
		}
		n.ends = append(n.ends, g)
	}
	var rows []TreeRow
	var walk func(n *node, prefix, path string, parent int)
	emitEnd := func(g *Group, prefix, path string, parent int, last, only bool) {
		conn, cont := "├─", "│ "
		if last {
			conn, cont = "└─", "  "
		}
		if only { // continuation of a single chain: no branch connector
			conn, cont = "", " " // servers' connectors start under "DST" (the row's text is one space in)
		}
		gs := c.groupSnap(g)
		// The route ends with its DST row: the destination is the route's
		// last hop, and the route's loss is the loss to it — so the row
		// shows the end-to-end probes of the route's measured port(s) (and
		// the TTL-limited discovery probes that reached it when the route is
		// not measured). The route's name and state go into its flags.
		var hs []*HopStat
		for _, f := range append(append([]*Flow{}, g.Members...), g.Tentative...) {
			if f.route.distance > 0 {
				hs = append(hs, f.route.hopIf(f.route.distance))
			}
		}
		h := c.aggHops(hs, TTL(len(g.Sig.hops)+1))
		h.Kind, h.Responder = KindDst, ep.Addr
		if !g.Sig.distKnown {
			h = HopSnap{TTL: TTL(len(g.Sig.hops) + 1), Kind: KindDst}
		}
		c.e2eAsHop(g, &h)
		dp := path + ">DST:" + g.ID
		dst := len(rows)
		rows = append(rows, TreeRow{Prefix: prefix + conn, Path: dp, Parent: parent, Branch: conn != "", Hop: h, Group: &gs})
		// Anycast: the servers measured through this route, after its DST.
		if ep.ac != nil {
			ss := c.serversOn(ep, g)
			for i, s := range ss {
				sc := "├─"
				if i == len(ss)-1 {
					sc = "└─"
				}
				// Only this route's ports: a server reached by several routes
				// shows, under each, what that route delivers.
				var fl []*Flow
				for _, f := range c.measuredOf(ep, s) {
					if f.group == g {
						fl = append(fl, f)
					}
				}
				hs := HopSnap{Kind: KindServer, Server: s.Name(), Name: fmt.Sprintf("%.0f Hz", s.Hz)}
				c.e2eFlowsAsHop(fl, &hs)
				r := TreeRow{Prefix: prefix + cont + sc, Path: dp + ">" + s.Name(), Parent: dst, Branch: true, Hop: hs, State: RowNotMeasured}
				for _, f := range fl {
					r.App[0] += f.C.AppSent
					r.App[1] += f.C.AppFail
				}
				for _, f := range fl {
					r.SPorts = append(r.SPorts, f.SPort())
				}
				if len(fl) > 0 {
					r.SPort = fl[0].SPort()
					r.State = serverState(fl)
				}
				rows = append(rows, r)
			}
		}
	}
	walk = func(n *node, prefix, path string, parent int) {
		items := len(n.children) + len(n.ends)
		i := 0
		for _, g := range n.ends {
			i++
			emitEnd(g, prefix, path, parent, i == items, items == 1)
		}
		for _, ch := range n.children {
			i++
			last := i == items
			conn, cont := "├─", "│ "
			if last {
				conn, cont = "└─", "  "
			}
			if items == 1 {
				conn, cont = "", ""
			}
			agg := func(nd *node) HopSnap {
				var hs []*HopStat
				for _, f := range nd.flows {
					hs = append(hs, f.route.hopIf(nd.ttl))
				}
				h := c.aggHops(hs, nd.ttl)
				if nd.elem.kind != eKnown {
					if h.Kind == KindHop {
						h.Kind = KindUnknown
					}
				}
				for _, f := range nd.flows {
					if possibleRateLimit(f.route, nd.ttl) {
						h.RateLimit = true
					}
				}
				return h
			}
			h := agg(ch)
			cp := path + ">" + ch.elem.String()
			// Collapse a chain of non-answering hops into one row.
			for h.Replies == 0 && len(ch.children) == 1 && len(ch.ends) == 0 {
				nx := ch.children[0]
				if nx.elem.kind != eSilent && nx.elem.kind != eUnknown {
					break
				}
				hn := agg(nx)
				if hn.Replies != 0 {
					break
				}
				h.TTLTo = nx.ttl
				h.Sent += hn.Sent
				if hn.Kind == KindSilent {
					h.Kind = KindSilent
				}
				h.Stale = h.Stale && hn.Stale
				ch = nx
				cp += ">" + nx.elem.String()
			}
			rows = append(rows, TreeRow{Prefix: prefix + conn, Path: cp, Parent: parent, Branch: conn != "", Hop: h})
			walk(ch, prefix+cont, cp, len(rows)-1)
		}
	}
	walk(root, "", "", -1)
	markRateLimited(rows)
	hs, parent := make([]*HopSnap, len(rows)), make([]int, len(rows))
	for i := range rows {
		hs[i], parent[i] = &rows[i].Hop, rows[i].Parent
	}
	markDownstream(hs, parent)
	return rows
}

// hopRecent and e2eRecent: how many of the newest RTT samples of a hop (a
// port keeps 16) and of a measured port (128) are compared with the ones
// before them.
const (
	hopRecent = 4
	e2eRecent = 8
)

// lossElevated: lost of n unanswered is significantly more than nothing
// (the rule of the loss analysis: Wilson lower bound above 5 %).
func lossElevated(lost, n uint32) bool {
	if n < 5 {
		return false
	}
	lo, _ := stats.Wilson(int64(lost), int64(n))
	return lo > 0.05
}

// markDownstream sets LossPersists and RTTShift on hop rows: what a hop's
// own numbers show counts only when every answering hop after it shows it
// too, down to a destination that shows it end to end, and that on every
// branch under it (a fault of the hop itself would reach them all). A
// router that answers poorly or slowly while traffic passes it unharmed is
// thereby left unmarked. rows[i] hangs under rows[parent[i]] (-1: the
// top), a parent comes before its rows; DST and server rows are set
// already.
func markDownstream(rows []*HopSnap, parent []int) {
	type carry struct{ seen, loss, rtt bool } // over the rows right under i: all of them carry it
	below := make([]carry, len(rows))
	for i := len(rows) - 1; i >= 0; i-- {
		h := rows[i]
		b := below[i]
		l, r := b.seen && b.loss, b.seen && b.rtt
		switch {
		case h.Kind == KindDst || h.Kind == KindServer:
			l, r = l || h.LossPersists, r || h.RTTShift
		default:
			if h.Replies > 0 && h.Kind != KindSilent && h.Sent >= 5 {
				l = l && !h.RateLimit && lossElevated(h.Sent-h.Replies, h.Sent)
				h.LossPersists = l
			}
			if h.rttKnown {
				r = r && h.rttUp
				h.RTTShift = r
			}
		}
		if p := parent[i]; p >= 0 && p < i {
			c := &below[p]
			if !c.seen {
				c.seen, c.loss, c.rtt = true, true, true
			}
			c.loss, c.rtt = c.loss && l, c.rtt && r
		}
	}
}

// markRateLimited flags tree hops whose pooled loss is significant while
// later answering hops of the same branch lose (almost) nothing: the hop
// limits its ICMP replies, traffic through it is not lost. (The per-flow
// rule alone misses this when each port has only a few probes there.)
func markRateLimited(rows []TreeRow) {
	for i := range rows {
		h := rows[i].Hop
		if h.Kind == KindDst || h.Kind == KindSilent || h.Replies == 0 {
			continue
		}
		for j := i + 1; j < len(rows) && Below(rows, j, i); j++ {
			d := rows[j].Hop
			if d.Kind == KindSilent {
				continue
			}
			if lossDropsAfter(h.Sent-h.Replies, h.Sent, d.Sent-d.Replies, d.Sent) {
				rows[i].Hop.RateLimit = true
				break
			}
		}
	}
}

// e2eAsHop fills a route's DST row from the end-to-end probes of its
// measured ports (cumulative since start or reset, like the hop rows).
func (c *Core) e2eAsHop(g *Group, h *HopSnap) {
	c.e2eFlowsAsHop(append(append([]*Flow{}, g.Members...), g.Tentative...), h)
}

// e2eFlowsAsHop fills a DST row from the end-to-end probes of the measured
// flows among fl.
func (c *Core) e2eFlowsAsHop(fl []*Flow, h *HopSnap) {
	measured := false
	// What the application plugin noted, when the ports do not agree: each
	// answer once, in port order.
	var notes []string
	for _, f := range fl {
		if f.Role.Monitored() && f.C.Valid() > 0 {
			measured = true
		}
		if f.Role.Monitored() && f.appNote != "" && !slices.Contains(notes, f.appNote) {
			notes = append(notes, f.appNote)
		}
	}
	if len(notes) > 3 {
		notes = append(notes[:3], "…")
	}
	note := strings.Join(notes, "|")
	h.AppNote = note
	if !measured {
		return // keep the TTL-limited probes that reached the destination
	}
	// Every column from the E2E probes only — never mixed with the
	// TTL-limited probes of other ports.
	*h = HopSnap{TTL: h.TTL, Kind: h.Kind, Responder: h.Responder, Flows: h.Flows, Name: h.Name, Server: h.Server, AppNote: note}
	var valid, fail uint64
	var v []uint32
	var jit float64
	var n int
	var last Mono
	spike, spikeAt := false, Mono(0)
	for _, f := range fl {
		if !f.Role.Monitored() {
			continue
		}
		valid += f.C.Valid()
		fail += f.C.Failures()
		from := len(v)
		f.rtt.ring.Do(func(x rttSample) { v = append(v, x.us) })
		if sh, sp, ok := stats.Level(v[from:], e2eRecent); ok {
			h.rttKnown = true
			h.rttUp = h.rttUp || sh
			if f.lastE2E >= spikeAt && sp {
				spike, spikeAt = true, f.lastE2E
			} else if f.lastE2E > spikeAt {
				spike, spikeAt = false, f.lastE2E
			}
		}
		if f.rtt.n > 0 {
			if h.Min == 0 || f.rtt.min < h.Min {
				h.Min = f.rtt.min
			}
			h.Max = max(h.Max, f.rtt.max)
			jit += f.rtt.jit.J
			n++
		}
		if f.lastE2E > last {
			last, h.Last = f.lastE2E, f.rtt.last
		}
	}
	if valid == 0 {
		return
	}
	h.Sent, h.Replies = uint32(valid), uint32(valid-fail)
	l := float64(fail) / float64(valid)
	h.Loss, h.LossOK = &l, true
	h.RTTShift, h.RTTSpike = h.rttUp, spike && !h.rttUp
	h.LossPersists = lossElevated(h.Sent-h.Replies, h.Sent)
	sum := stats.Summarize(v)
	h.Median, h.P95 = sum.Median, sum.P95
	if n > 0 {
		h.Jitter = jit / float64(n)
	}
	if last > 0 {
		h.AgeMs = int64(c.now-last) / 1e6
	}
	h.Stale = false
}

// measuredOf returns the measured flows of a server (anycast).
func (c *Core) measuredOf(ep *Endpoint, s *Server) []*Flow {
	var out []*Flow
	for _, f := range ep.Flows {
		if f.Role.Monitored() && ep.ac.portSrv[f.SPort()] == s {
			out = append(out, f)
		}
	}
	return out
}

// serversOn lists the servers whose measured port goes through route g.
func (c *Core) serversOn(ep *Endpoint, g *Group) []*Server {
	var out []*Server
	for _, s := range ep.ac.servers {
		for _, f := range c.measuredOf(ep, s) {
			if f.group == g {
				out = append(out, s)
				break
			}
		}
	}
	return out
}

func (c *Core) anycastSnap(ep *Endpoint) *AnycastSnap {
	a := ep.ac
	out := &AnycastSnap{Status: a.status, Explored: a.explored, Answers: len(a.answers), Moved: a.moved, Unknown: a.unknownClk, Phantoms: a.phantoms, GivenUp: a.stuck}
	for _, s := range a.servers {
		ss := ServerSnap{Name: s.Name(), Hz: s.Hz, Ports: len(s.ports), State: RowNotMeasured}
		fl := c.measuredOf(ep, s)
		for _, f := range fl {
			ss.Measured = append(ss.Measured, f.SPort())
			ss.Flows = append(ss.Flows, f.Name())
			if f.group != nil && !slices.Contains(ss.Groups, f.group.ID) {
				ss.Groups = append(ss.Groups, f.group.ID)
			}
		}
		if len(fl) > 0 {
			ss.State = serverState(fl)
		}
		ss.E2E = HopSnap{Kind: KindServer, Server: s.Name(), Name: fmt.Sprintf("%.0f Hz", s.Hz)}
		c.e2eFlowsAsHop(fl, &ss.E2E)
		for _, f := range fl {
			ss.App[0] += f.C.AppSent
			ss.App[1] += f.C.AppFail
		}
		out.Servers = append(out.Servers, ss)
	}
	return out
}

// serverState is the state word of a server from its measured ports, by
// the rule of a route (evalGroups): ports still collecting their first
// results do not hide the verdict of the others, and a server with nothing
// but such ports is WARMUP, not UNKNOWN.
func serverState(fl []*Flow) RowState {
	var ok, loss, down, warm, n int
	for _, f := range fl {
		n++
		switch f.State() {
		case FOK:
			ok++
		case FLoss:
			loss++
		case FDown:
			down++
		case FUnknown:
			if f.sm.reason == ReasonWarmup {
				warm++
			}
		}
	}
	return serverWord(ok, loss, down, warm, n)
}

func serverWord(ok, loss, down, warm, n int) RowState {
	switch {
	case n == 0:
		return RowNotMeasured
	case down == n:
		return RowDown
	case down+loss > 0:
		return RowLoss
	case ok == n, ok > 0 && ok+warm == n:
		return RowOK
	case warm == n:
		return RowWarmup
	}
	return RowUnknown
}

// Below reports whether row j of a tree hangs under row i, at any depth.
// The rows are in the order of a walk from the top, so everything below a
// row follows it without a gap.
func Below(rows []TreeRow, j, i int) bool {
	for {
		p := rows[j].Parent
		if p < 0 || p >= j { // the top, or not a tree: a parent comes first
			return false
		}
		if p == i {
			return true
		}
		j = p
	}
}
