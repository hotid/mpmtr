package core

import (
	"fmt"
	"slices"
	"strings"
)

// The enumerations of the snapshot are written to JSON as their names and
// read back from them: the report keeps its text, and the code that draws
// it compares constants, never strings.

func enumText[T ~uint8](v T, names []string) ([]byte, error) {
	if int(v) >= len(names) {
		return nil, fmt.Errorf("value %d of %T has no name", v, v)
	}
	return []byte(names[v]), nil
}

func enumParse[T ~uint8](dst *T, b []byte, names []string) error {
	i := slices.Index(names, string(b))
	if i < 0 {
		return fmt.Errorf("%q is not a %T (one of %q)", b, *dst, names)
	}
	*dst = T(i)
	return nil
}

var (
	roleNames        = []string{"candidate", "active", "retired"}
	invalidNames     = []string{"", "local_nat", "local_seq_rewrite", "weak_or_unexpected_dominant", "local_route_changed", "egress_interface_mismatch"}
	availNames       = []string{"UNKNOWN", "UP", "DOWN"}
	qualityNames     = []string{"UNKNOWN", "OK", "LOSS"}
	fstateNames      = []string{"UNKNOWN", "OK", "LOSS", "DOWN", "MEASUREMENT_INVALID"}
	epstateNames     = []string{"UNKNOWN", "OK", "LOSS", "DOWN"}
	scopeNames       = []string{"NONE", "PARTIAL", "ALL", "UNKNOWN"}
	gstateNames      = []string{"UNKNOWN", "OK", "LOSS", "DOWN"}
	levelNames       = []string{"unresolved", "ambiguous", "tentative", "partial_distinct", "confirmed"}
	rowNames         = []string{"", "UNKNOWN", "OK", "LOSS", "DOWN", "WARMUP", "not measured"}
	hopKindNames     = []string{"hop", "silent", "unknown", "unstable", "hidden", "dst", "server"}
	reasonNames      = []string{"", "warmup", "stale", "capture_impaired", "loss_pending", "post_recovery", "reset", "invalid", "app_down"}
	routeChangeNames = []string{"", "responder_changed", "distance_increased", "distance_decreased", "retrace", "stats_reset"}
	locNames         = []string{"NONE", "CONFIRMED_FLOW_FAILURE", "CORRELATED_PATH_FAILURE", "SUSPECTED_SEGMENT",
		"FORWARD_PATH_NOT_DISTINGUISHED", "ROUTE_AMBIGUITY", "INCONCLUSIVE", "APPLICATION_FAILURE"}
	eventNames = []string{"", "MONITORING_IMPAIRED", "MONITORING_RECOVERED", "LOCALIZATION_RESULT",
		"ENDPOINT_DOWN", "ENDPOINT_LOSS", "PARTIAL_PATH_FAILURE", "ENDPOINT_RECOVERED",
		"PATHGROUP_DOWN", "PATHGROUP_LOSS", "PATHGROUP_RECOVERED",
		"FLOW_DOWN", "FLOW_LOSS", "FLOW_RECOVERED", "FLOW_LOSS_CLEARED",
		"RTT_DEGRADATION", "RTT_RECOVERED", "ROUTE_CHANGED", "MEASUREMENT_INVALID"}
	heteroNames = []string{"", "heterogeneous", "no_detected_heterogeneity", "insufficient_data"}
)

func (r Role) String() string                { return roleNames[r] }
func (r Role) MarshalText() ([]byte, error)  { return enumText(r, roleNames) }
func (r *Role) UnmarshalText(b []byte) error { return enumParse(r, b, roleNames) }
func (r InvalidReason) String() string       { return invalidNames[r] }
func (r InvalidReason) MarshalText() ([]byte, error) {
	return enumText(r, invalidNames)
}
func (r *InvalidReason) UnmarshalText(b []byte) error { return enumParse(r, b, invalidNames) }
func (a Avail) String() string                        { return availNames[a] }
func (a Avail) MarshalText() ([]byte, error)          { return enumText(a, availNames) }
func (a *Avail) UnmarshalText(b []byte) error         { return enumParse(a, b, availNames) }
func (q Quality) String() string                      { return qualityNames[q] }
func (q Quality) MarshalText() ([]byte, error)        { return enumText(q, qualityNames) }
func (q *Quality) UnmarshalText(b []byte) error       { return enumParse(q, b, qualityNames) }
func (s FState) String() string                       { return fstateNames[s] }
func (s FState) MarshalText() ([]byte, error)         { return enumText(s, fstateNames) }
func (s *FState) UnmarshalText(b []byte) error        { return enumParse(s, b, fstateNames) }
func (s EPState) String() string                      { return epstateNames[s] }
func (s EPState) MarshalText() ([]byte, error)        { return enumText(s, epstateNames) }
func (s *EPState) UnmarshalText(b []byte) error       { return enumParse(s, b, epstateNames) }
func (s Scope) String() string                        { return scopeNames[s] }
func (s Scope) MarshalText() ([]byte, error)          { return enumText(s, scopeNames) }
func (s *Scope) UnmarshalText(b []byte) error         { return enumParse(s, b, scopeNames) }
func (g GState) String() string                       { return gstateNames[g] }
func (g GState) MarshalText() ([]byte, error)         { return enumText(g, gstateNames) }
func (g *GState) UnmarshalText(b []byte) error        { return enumParse(g, b, gstateNames) }
func (l Level) String() string                        { return levelNames[l] }
func (l Level) MarshalText() ([]byte, error)          { return enumText(l, levelNames) }
func (l *Level) UnmarshalText(b []byte) error         { return enumParse(l, b, levelNames) }

// RowState is the state word of a route or of a server as it is shown: the
// measured states, and the two that say why there is none yet.
type RowState uint8

const (
	RowNone    RowState = iota // the row has no state of its own (a hop)
	RowUnknown                 // the data cannot decide
	RowOK
	RowLoss
	RowDown
	RowWarmup      // every measured port is still collecting its first results
	RowNotMeasured // no measured port
)

func (s RowState) String() string                { return rowNames[s] }
func (s RowState) MarshalText() ([]byte, error)  { return enumText(s, rowNames) }
func (s *RowState) UnmarshalText(b []byte) error { return enumParse(s, b, rowNames) }

// HopKind says what a hop row stands for.
type HopKind uint8

const (
	KindHop      HopKind = iota // a router that answers
	KindSilent                  // probed, never answered
	KindUnknown                 // not established yet
	KindUnstable                // several routers answer at this TTL
	KindHidden                  // only the next hop answered the probes sent here
	KindDst                     // the destination: the route's end-to-end result
	KindServer                  // a server behind the address (anycast)
)

func (k HopKind) String() string                { return hopKindNames[k] }
func (k HopKind) MarshalText() ([]byte, error)  { return enumText(k, hopKindNames) }
func (k *HopKind) UnmarshalText(b []byte) error { return enumParse(k, b, hopKindNames) }

// Hetero is the verdict on whether flows (or routes) differ in loss.
type Hetero uint8

const (
	HeteroNone         Hetero = iota // not judged
	HeteroYes                        // some differ
	HeteroNotDetected                // none differs
	HeteroInsufficient               // too little data to say
)

func (h Hetero) String() string                { return heteroNames[h] }
func (h Hetero) MarshalText() ([]byte, error)  { return enumText(h, heteroNames) }
func (h *Hetero) UnmarshalText(b []byte) error { return enumParse(h, b, heteroNames) }

// Row is the state of a route as a row shows it.
func (g GState) Row() RowState {
	return [...]RowState{GUnknown: RowUnknown, GOK: RowOK, GLoss: RowLoss, GDown: RowDown}[g]
}

// Row is the state of a flow as a row shows it. A flow whose measurement
// cannot be trusted has no verdict.
func (s FState) Row() RowState {
	return [...]RowState{FUnknown: RowUnknown, FOK: RowOK, FLoss: RowLoss, FDown: RowDown, FInvalid: RowUnknown}[s]
}

// Row is the state of an endpoint as a row shows it.
func (s EPState) Row() RowState {
	return [...]RowState{EPUnknown: RowUnknown, EPOK: RowOK, EPLoss: RowLoss, EPDown: RowDown}[s]
}

// FlowFlag is one of the remarks on a flow in the snapshot.
type FlowFlag string

const (
	FlagStale           FlowFlag = "STALE"                      // no result for a while
	FlagImpaired        FlowFlag = "MEASUREMENT_IMPAIRED"       // the local measurement is impaired
	FlagInvalid         FlowFlag = "MEASUREMENT_INVALID"        // the port cannot be measured
	FlagRTTDegraded     FlowFlag = "RTT_DEGRADED"               // RTT above the baseline
	FlagRTTRelative     FlowFlag = "RTT_RELATIVE"               // … relative to the other flows
	FlagRTTAbsolute     FlowFlag = "RTT_ABSOLUTE"               // … relative to its own baseline
	FlagBaselineUnknown FlowFlag = "BASELINE_UNKNOWN"           // no RTT baseline yet
	FlagDownHeld        FlowFlag = "DOWN_HELD_IMPAIRED"         // DOWN not declared while the measurement is impaired
	FlagSeqTranslation  FlowFlag = "POSSIBLE_SEQ_TRANSLATION"   // answers with a foreign acknowledgement number
	FlagRSTMissing      FlowFlag = "RST_MISSING"                // the kernel did not reset a SYN/ACK
	FlagIncidentTrace   FlowFlag = "INCIDENT_TRACE"             // being traced because of a failure
	FlagQualityPending  FlowFlag = "RESPONDING_QUALITY_PENDING" // answers, no loss verdict yet
)

// FlowFlags are the remarks on one flow.
type FlowFlags []FlowFlag

// Has reports whether the flow carries the remark.
func (fs FlowFlags) Has(f FlowFlag) bool { return slices.Contains(fs, f) }

// Join is the remarks as text.
func (fs FlowFlags) Join(sep string) string {
	out := make([]string, len(fs))
	for i, f := range fs {
		out[i] = string(f)
	}
	return strings.Join(out, sep)
}

// Reason says why a flow has no verdict (or why its measurement is not
// trusted). It decides things: a route whose other ports are only warming
// up is still OK.
type Reason uint8

const (
	ReasonNone            Reason = iota
	ReasonWarmup                 // still collecting the first results
	ReasonStale                  // no result for too long
	ReasonCaptureImpaired        // the local capture lost packets
	ReasonLossPending            // loss seen, not yet confirmed
	ReasonPostRecovery           // a new epoch after a recovery from DOWN
	ReasonReset                  // a new epoch after a reset of the statistics
	ReasonInvalid                // the port cannot be measured: see the invalid reason
	ReasonAppDown                // TCP answers, the application checks fail in a row
)

func (r Reason) String() string                { return reasonNames[r] }
func (r Reason) MarshalText() ([]byte, error)  { return enumText(r, reasonNames) }
func (r *Reason) UnmarshalText(b []byte) error { return enumParse(r, b, reasonNames) }

// RouteChange says what made a new version of a flow's route.
type RouteChange uint8

const (
	ChangeNone      RouteChange = iota
	ChangeResponder             // another router answers at a TTL
	ChangeLonger                // the destination is further away
	ChangeShorter               // the destination is nearer
	ChangeRetrace               // traced anew after a change elsewhere on the route
	ChangeReset                 // the statistics were reset
)

func (r RouteChange) String() string                { return routeChangeNames[r] }
func (r RouteChange) MarshalText() ([]byte, error)  { return enumText(r, routeChangeNames) }
func (r *RouteChange) UnmarshalText(b []byte) error { return enumParse(r, b, routeChangeNames) }

// LocLevel is how far the comparison of failing and healthy flows got.
type LocLevel uint8

const (
	LocNone LocLevel = iota
	LocFlowFailure
	LocCorrelatedPath
	LocSuspectedSegment
	LocForwardNotDistinct
	LocRouteAmbiguity
	LocInconclusive
	LocApplication // TCP answers on every failing port; only application checks fail: not a path fault
)

func (l LocLevel) String() string                { return locNames[l] }
func (l LocLevel) MarshalText() ([]byte, error)  { return enumText(l, locNames) }
func (l *LocLevel) UnmarshalText(b []byte) error { return enumParse(l, b, locNames) }

// EventKind is the type of an event, and of a flow's transition inside one.
type EventKind uint8

const (
	EvNone EventKind = iota
	EvMonitoringImpaired
	EvMonitoringRecovered
	EvLocalization
	EvEndpointDown
	EvEndpointLoss
	EvPartialPathFailure
	EvEndpointRecovered
	EvGroupDown
	EvGroupLoss
	EvGroupRecovered
	EvFlowDown
	EvFlowLoss
	EvFlowRecovered
	EvFlowLossCleared
	EvRTTDegradation
	EvRTTRecovered
	EvRouteChanged
	EvMeasurementInvalid // a flow's transition only
)

func (k EventKind) String() string                { return eventNames[k] }
func (k EventKind) MarshalText() ([]byte, error)  { return enumText(k, eventNames) }
func (k *EventKind) UnmarshalText(b []byte) error { return enumParse(k, b, eventNames) }

// problem: the flow got worse; recovery: it got better. Problems of
// several flows at once are told as one event of the endpoint or the route;
// a recovery is always told.
func (k EventKind) recovery() bool { return k == EvFlowRecovered || k == EvFlowLossCleared }
func (k EventKind) rtt() bool      { return k == EvRTTDegradation || k == EvRTTRecovered }
