package core

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"
)

// The report is JSON whatever the measurement looks like: before the first
// answer, with no valid probe at all, healthy, with a dead flow, with loss.
// A rate over zero samples or an empty statistic must never be a number
// JSON cannot carry (NaN, infinity); what was written reads back the same.
func TestSnapshotIsAlwaysJSON(t *testing.T) {
	good := linear(5, 20*time.Millisecond)
	dead := linear(5, 20*time.Millisecond)
	dead.loss = 1
	lossy := linear(5, 20*time.Millisecond)
	lossy.loss = 0.3
	silent := linear(5, 20*time.Millisecond)
	silent.noReply = true
	refused := linear(5, 20*time.Millisecond)
	refused.unreach = true

	for _, tc := range []struct {
		name    string
		path    *simPath
		sendErr bool
		badOnly bool // the path is for one flow; the others are healthy
	}{
		{name: "healthy", path: good},
		{name: "nothing can be sent", path: good, sendErr: true},
		{name: "one dead flow", path: dead, badOnly: true},
		{name: "every flow dead", path: dead},
		{name: "one lossy flow", path: lossy, badOnly: true},
		{name: "hops never answer", path: silent},
		{name: "destination unreachable", path: refused},
	} {
		var bad *Flow
		s := newSim(t, simpleCfg(), func(f *Flow, _ Mono) *simPath {
			if tc.badOnly && f != bad {
				return good
			}
			return tc.path
		})
		if tc.sendErr {
			s.sendErr = func(*Flow) bool { return true }
		}
		ep := s.add(64)
		if tc.badOnly {
			bad = monitored(ep)[1]
		}
		// At the very start, during warmup, and after verdicts.
		for _, d := range []time.Duration{0, 3 * time.Second, 40 * time.Second, 90 * time.Second} {
			s.run(d)
			s.c.EvaluateNow()
			s.c.Flush()
			for _, o := range []SnapOpts{{Only: AllEndpoints}, {Hops: true, Tree: true, Only: AllEndpoints}} {
				snap := s.c.Snapshot(o)
				if len(snap.Endpoints) != 1 || len(snap.Endpoints[0].Flows) == 0 {
					t.Fatalf("%s after %v: an empty snapshot proves nothing", tc.name, d)
				}
				b, err := json.Marshal(snap)
				if err != nil {
					t.Fatalf("%s after %v: the snapshot is not JSON: %v", tc.name, d, err)
				}
				var back Snapshot
				if err := json.Unmarshal(b, &back); err != nil {
					t.Fatalf("%s after %v: the JSON does not read back: %v", tc.name, d, err)
				}
				b2, err := json.Marshal(&back)
				if err != nil || !bytes.Equal(b, b2) {
					t.Fatalf("%s after %v: read back and written again it differs (err %v)", tc.name, d, err)
				}
			}
			eb, err := json.Marshal(s.c.RecentEvents())
			if err != nil {
				t.Fatalf("%s after %v: the events are not JSON: %v", tc.name, d, err)
			}
			var evs []Event
			if err := json.Unmarshal(eb, &evs); err != nil {
				t.Fatalf("%s after %v: the events do not read back: %v", tc.name, d, err)
			}
			if eb2, _ := json.Marshal(evs); len(evs) > 0 && !bytes.Equal(eb, eb2) {
				t.Fatalf("%s after %v: the events read back differently", tc.name, d)
			}
		}
	}
}
