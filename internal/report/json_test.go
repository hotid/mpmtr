package report

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/hotid/mpmtr/internal/core"
)

// jsonNames collects every field name the report can carry.
func jsonNames(t reflect.Type, seen map[reflect.Type]bool, out map[string]bool) {
	for t.Kind() == reflect.Pointer || t.Kind() == reflect.Slice || t.Kind() == reflect.Array || t.Kind() == reflect.Map {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct || seen[t] {
		return
	}
	seen[t] = true
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		if name == "-" {
			continue
		}
		if name != "" {
			out[name] = true
		}
		jsonNames(f.Type, seen, out)
	}
}

// The names the documentation tells a script to read exist in the report.
// A renamed field breaks every script silently, so the names the README,
// the man page and the documents under docs/ give are pinned here; and each of them really is in the
// documentation (a name dropped from the docs is dropped from this list).
func TestDocumentedJSONNames(t *testing.T) {
	names := map[string]bool{}
	jsonNames(reflect.TypeOf(JSONReport{}), map[reflect.Type]bool{}, names)
	jsonNames(reflect.TypeOf(core.Event{}), map[reflect.Type]bool{}, names)
	docs := ""
	paths, err := filepath.Glob("../../docs/*.md")
	if err != nil || len(paths) == 0 {
		t.Fatalf("no documents under docs/: %v", err)
	}
	for _, p := range append(paths, "../../README.md", "../../man/mpmtr.1") {
		if strings.HasSuffix(p, ".ru.md") {
			continue
		}
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		docs += strings.ReplaceAll(string(b), `\-`, "-")
	}
	for _, n := range []string{
		"exit_code", "incomplete_reasons", "parameters", "hop_info", "ip_info",
		"window_long_seconds", "window_short_seconds",
		"down_after_failures", "background_loss", "fail_after_fail",
		"route_history", "also_answered_by", "suspected_loss_start_ttl",
		"remote_state_conflict", "tx_ts_fallback", "quote_seq_mismatch",
		"app_checks", "app_failed", "app_failure_rate",
	} {
		if !names[n] {
			t.Errorf("the documentation names %q, the report has no such field", n)
		}
		if !strings.Contains(docs, n) {
			t.Errorf("%q is pinned here but no longer in the documentation", n)
		}
	}
}

// The envelope of a JSON report: what is always there, what is there only
// when it says something, and that the text is one JSON document.
func TestJSONReportEnvelope(t *testing.T) {
	at := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	full := &JSONReport{Tool: "mpmtr", Version: "v1", Started: at, Finished: at.Add(time.Minute), Complete: true,
		ExitCode: 0, Params: Params{Count: 100}, Snapshot: &core.Snapshot{}, Events: nil}
	var buf bytes.Buffer
	if err := JSON(&buf, full); err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	dec := json.NewDecoder(&buf)
	if err := dec.Decode(&m); err != nil {
		t.Fatal(err)
	}
	if dec.More() {
		t.Error("more than one JSON document")
	}
	for _, k := range []string{"tool", "version", "started", "finished", "complete", "exit_code", "parameters", "result", "events"} {
		if _, ok := m[k]; !ok {
			t.Errorf("a complete report lacks %q", k)
		}
	}
	for _, k := range []string{"incomplete_reasons", "warnings", "ip_info", "hop_info"} {
		if _, ok := m[k]; ok {
			t.Errorf("%q is there with nothing to say", k)
		}
	}
	if string(m["events"]) != "[]" {
		t.Errorf("no events must be an empty list for a script to iterate, got %s", m["events"])
	}
	if string(m["complete"]) != "true" || string(m["exit_code"]) != "0" || string(m["started"]) != `"2026-01-02T03:04:05Z"` {
		t.Errorf("complete %s exit_code %s started %s", m["complete"], m["exit_code"], m["started"])
	}

	cut := &JSONReport{Tool: "mpmtr", Complete: false, Incomplete: []string{"report-timeout reached"}, ExitCode: 3,
		Snapshot: &core.Snapshot{}, Warnings: []string{"w"}, HopInfo: map[netip.Addr]map[string]HopNote{netip.MustParseAddr("192.0.2.1"): {"p": {Name: "n"}}}}
	buf.Reset()
	if err := JSON(&buf, cut); err != nil {
		t.Fatal(err)
	}
	m = nil
	if err := json.Unmarshal(buf.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	if string(m["complete"]) != "false" || string(m["exit_code"]) != "3" || !strings.Contains(string(m["incomplete_reasons"]), "report-timeout reached") {
		t.Errorf("an incomplete report: %s", buf.String())
	}
	for _, k := range []string{"warnings", "hop_info"} {
		if _, ok := m[k]; !ok {
			t.Errorf("%q is missing though set", k)
		}
	}
}
