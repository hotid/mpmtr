package core

import (
	"encoding"
	"encoding/json"
	"net/netip"
	"testing"
)

type textEnum interface {
	encoding.TextMarshaler
	String() string
}

// The names in the JSON report are a contract with whoever reads it: each
// enumeration has exactly these names, in this order, every value has one,
// and a name reads back to its value. An unknown name is an error, not a
// silent zero.
func TestEnumNames(t *testing.T) {
	for _, tc := range []struct {
		what  string
		names []string
		value func(i int) textEnum
		parse func(b []byte) (textEnum, error)
	}{
		{"role", []string{"candidate", "active", "retired"},
			func(i int) textEnum { return Role(i) }, func(b []byte) (textEnum, error) { var v Role; return v, v.UnmarshalText(b) }},
		{"invalid reason", []string{"", "local_nat", "local_seq_rewrite", "weak_or_unexpected_dominant", "local_route_changed", "egress_interface_mismatch"},
			func(i int) textEnum { return InvalidReason(i) }, func(b []byte) (textEnum, error) { var v InvalidReason; return v, v.UnmarshalText(b) }},
		{"availability", []string{"UNKNOWN", "UP", "DOWN"},
			func(i int) textEnum { return Avail(i) }, func(b []byte) (textEnum, error) { var v Avail; return v, v.UnmarshalText(b) }},
		{"quality", []string{"UNKNOWN", "OK", "LOSS"},
			func(i int) textEnum { return Quality(i) }, func(b []byte) (textEnum, error) { var v Quality; return v, v.UnmarshalText(b) }},
		{"flow state", []string{"UNKNOWN", "OK", "LOSS", "DOWN", "MEASUREMENT_INVALID"},
			func(i int) textEnum { return FState(i) }, func(b []byte) (textEnum, error) { var v FState; return v, v.UnmarshalText(b) }},
		{"endpoint state", []string{"UNKNOWN", "OK", "LOSS", "DOWN"},
			func(i int) textEnum { return EPState(i) }, func(b []byte) (textEnum, error) { var v EPState; return v, v.UnmarshalText(b) }},
		{"scope", []string{"NONE", "PARTIAL", "ALL", "UNKNOWN"},
			func(i int) textEnum { return Scope(i) }, func(b []byte) (textEnum, error) { var v Scope; return v, v.UnmarshalText(b) }},
		{"route state", []string{"UNKNOWN", "OK", "LOSS", "DOWN"},
			func(i int) textEnum { return GState(i) }, func(b []byte) (textEnum, error) { var v GState; return v, v.UnmarshalText(b) }},
		{"route level", []string{"unresolved", "ambiguous", "tentative", "partial_distinct", "confirmed"},
			func(i int) textEnum { return Level(i) }, func(b []byte) (textEnum, error) { var v Level; return v, v.UnmarshalText(b) }},
		{"row state", []string{"", "UNKNOWN", "OK", "LOSS", "DOWN", "WARMUP", "not measured"},
			func(i int) textEnum { return RowState(i) }, func(b []byte) (textEnum, error) { var v RowState; return v, v.UnmarshalText(b) }},
		{"hop kind", []string{"hop", "silent", "unknown", "unstable", "hidden", "dst", "server"},
			func(i int) textEnum { return HopKind(i) }, func(b []byte) (textEnum, error) { var v HopKind; return v, v.UnmarshalText(b) }},
		{"reason", []string{"", "warmup", "stale", "capture_impaired", "loss_pending", "post_recovery", "reset", "invalid", "app_down"},
			func(i int) textEnum { return Reason(i) }, func(b []byte) (textEnum, error) { var v Reason; return v, v.UnmarshalText(b) }},
		{"route change", []string{"", "responder_changed", "distance_increased", "distance_decreased", "retrace", "stats_reset"},
			func(i int) textEnum { return RouteChange(i) }, func(b []byte) (textEnum, error) { var v RouteChange; return v, v.UnmarshalText(b) }},
		{"localization level", []string{"NONE", "CONFIRMED_FLOW_FAILURE", "CORRELATED_PATH_FAILURE", "SUSPECTED_SEGMENT", "FORWARD_PATH_NOT_DISTINGUISHED", "ROUTE_AMBIGUITY", "INCONCLUSIVE", "APPLICATION_FAILURE"},
			func(i int) textEnum { return LocLevel(i) }, func(b []byte) (textEnum, error) { var v LocLevel; return v, v.UnmarshalText(b) }},
		{"event", []string{"", "MONITORING_IMPAIRED", "MONITORING_RECOVERED", "LOCALIZATION_RESULT", "ENDPOINT_DOWN", "ENDPOINT_LOSS", "PARTIAL_PATH_FAILURE",
			"ENDPOINT_RECOVERED", "PATHGROUP_DOWN", "PATHGROUP_LOSS", "PATHGROUP_RECOVERED", "FLOW_DOWN", "FLOW_LOSS", "FLOW_RECOVERED", "FLOW_LOSS_CLEARED",
			"RTT_DEGRADATION", "RTT_RECOVERED", "ROUTE_CHANGED", "MEASUREMENT_INVALID"},
			func(i int) textEnum { return EventKind(i) }, func(b []byte) (textEnum, error) { var v EventKind; return v, v.UnmarshalText(b) }},
		{"heterogeneity", []string{"", "heterogeneous", "no_detected_heterogeneity", "insufficient_data"},
			func(i int) textEnum { return Hetero(i) }, func(b []byte) (textEnum, error) { var v Hetero; return v, v.UnmarshalText(b) }},
	} {
		for i, want := range tc.names {
			v := tc.value(i)
			b, err := v.MarshalText()
			if err != nil || string(b) != want || v.String() != want {
				t.Errorf("%s %d: %q (String %q, err %v), want %q", tc.what, i, b, v.String(), err, want)
			}
			back, err := tc.parse([]byte(want))
			if err != nil {
				t.Errorf("%s: %q does not read back: %v", tc.what, want, err)
			} else if bb, _ := back.MarshalText(); string(bb) != want {
				t.Errorf("%s: %q reads back as %q", tc.what, want, bb)
			}
		}
		// one past the last: no name, so an error and not a wrong word
		if _, err := tc.value(len(tc.names)).MarshalText(); err == nil {
			t.Errorf("%s: value %d has a name, the list above is incomplete", tc.what, len(tc.names))
		}
		if _, err := tc.parse([]byte("no such name")); err == nil {
			t.Errorf("%s: an unknown name was accepted", tc.what)
		}
	}
}

// The last constant of each enumeration has a name: a value added without
// one would panic in String.
func TestEnumLastConstants(t *testing.T) {
	_ = []string{RoleRetired.String(), InvalidEgressMismatch.String(), AvailDown.String(), QLoss.String(), FInvalid.String(),
		EPDown.String(), ScopeUnknown.String(), GDown.String(), LevelConfirmed.String(), RowNotMeasured.String(),
		KindServer.String(), HeteroInsufficient.String(), ReasonAppDown.String(), ChangeReset.String(), LocApplication.String(), EvMeasurementInvalid.String()}
	for _, n := range []int{len(roleNames) - int(RoleRetired), len(invalidNames) - int(InvalidEgressMismatch), len(availNames) - int(AvailDown),
		len(qualityNames) - int(QLoss), len(fstateNames) - int(FInvalid), len(epstateNames) - int(EPDown), len(scopeNames) - int(ScopeUnknown),
		len(gstateNames) - int(GDown), len(levelNames) - int(LevelConfirmed), len(rowNames) - int(RowNotMeasured),
		len(hopKindNames) - int(KindServer), len(heteroNames) - int(HeteroInsufficient), len(reasonNames) - int(ReasonAppDown),
		len(routeChangeNames) - int(ChangeReset), len(locNames) - int(LocApplication), len(eventNames) - int(EvMeasurementInvalid)} {
		if n != 1 {
			t.Errorf("an enumeration and its names differ in length by %d", n-1)
		}
	}
}

// In JSON an enumeration is its name in quotes, and a row without a state
// has no "state" at all.
func TestEnumJSON(t *testing.T) {
	b, err := json.Marshal(struct {
		S FState   `json:"s"`
		K HopKind  `json:"k"`
		R RowState `json:"r,omitempty"`
		W RowState `json:"w,omitempty"`
	}{FDown, KindDst, RowNone, RowWarmup})
	if err != nil || string(b) != `{"s":"DOWN","k":"dst","w":"WARMUP"}` {
		t.Fatalf("%s %v", b, err)
	}
}

// An event reads back from its JSON line with its details as the type the
// event's kind carries; every kind that is ever sent has one, and details
// on a kind that has none are refused.
func TestEventJSON(t *testing.T) {
	for _, e := range []Event{
		{Type: EvMonitoringImpaired, Key: "monitor#1", Details: &MonitorDetails{Reasons: []string{"capture_drops"}}},
		{Type: EvMonitoringImpaired, Key: "x/F1:20000/invalid", Details: &MonitorDetails{Reason: InvalidLocalNAT, Scope: "flow"},
			Flows: []FlowRef{{Flow: "F1", SPort: 20000, Transition: EvMeasurementInvalid}}},
		{Type: EvMonitoringRecovered, Key: "monitor#1"},
		{Type: EvLocalization, State: "SUSPECTED_SEGMENT", PrevState: "NONE",
			Details: &LocalizationDetails{OldLevel: LocNone, NewLevel: LocSuspectedSegment, LossStartTTL: 3, AffectedFlows: []string{"F1"}}},
		{Type: EvPartialPathFailure, State: "LOSS", Scope: "PARTIAL", PrevState: "OK",
			Details: &EndpointDetails{FlowsTotal: 4, FlowsLoss: 1, FlowsOK: 3, Coverage: 1, Groups: []string{"G00001:LOSS"}}},
		{Type: EvEndpointRecovered, Details: &EndpointDetails{FlowsTotal: 4, FlowsOK: 4, Coverage: 1}},
		{Type: EvGroupDown, Group: "G00001", Details: &GroupDetails{Level: LevelConfirmed, Partial: true}},
		{Type: EvFlowDown, Details: &FlowDetails{Quality: QLoss, Avail: AvailDown, ConsecFail: 22}},
		{Type: EvRTTDegradation, Details: &RTTDetails{Kinds: []string{"relative+absolute"}}},
		{Type: EvRouteChanged, Details: &RouteDetails{Note: "route change is not packet loss"},
			Flows: []FlowRef{{Flow: "F2", SPort: 20001, Transition: EvRouteChanged, TTL: 3, Old: netip.MustParseAddr("192.0.2.1"), New: netip.MustParseAddr("192.0.2.2"), Reason: ChangeResponder.String()}}},
	} {
		b, err := json.Marshal(e)
		if err != nil {
			t.Fatalf("%s: %v", e.Type, err)
		}
		var back Event
		if err := json.Unmarshal(b, &back); err != nil {
			t.Fatalf("%s does not read back: %v\n%s", e.Type, err, b)
		}
		b2, _ := json.Marshal(back)
		if string(b) != string(b2) {
			t.Errorf("%s reads back differently:\n%s\n%s", e.Type, b, b2)
		}
	}
	for k := EvMonitoringImpaired; k < EvMeasurementInvalid; k++ {
		if detailsFor(k) == nil {
			t.Errorf("%s has no details type", k)
		}
	}
	var e Event
	if err := json.Unmarshal([]byte(`{"type":"MEASUREMENT_INVALID","details":{"x":1}}`), &e); err == nil {
		t.Error("details on an event kind that carries none were accepted")
	}
	if err := json.Unmarshal([]byte(`{"type":"FLOW_DWON"}`), &e); err == nil {
		t.Error("an unknown event type was accepted")
	}
}
