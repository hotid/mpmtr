// Package report renders snapshots as plain text (report mode, non-TTY
// live output, and the building blocks of the terminal UI) and as JSON.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/hotid/mpmtr/internal/wire"

	"github.com/hotid/mpmtr/internal/core"
	"github.com/hotid/mpmtr/internal/enrich"
)

// Names resolves addresses for display: Name is the reverse-DNS name, Note
// the network annotation (AS, IX, location; see --asn, --ix, --geoip). ""
// = nothing known (yet). A nil Names shows bare addresses.
type Names interface {
	Name(ip netip.Addr) string
	Note(ip netip.Addr) string
}

// PluginNames is implemented by Names that run plugins: what the
// hop-information plugins (--hop-info) say about a hop, and what the
// application plugin (--app) notes about a server, has its own column.
type PluginNames interface {
	PluginNote(ip netip.Addr) string
	PluginWidth() int // width of the PLUGIN column; 0 = no plugins, no column
}

func pluginWidth(names Names) int {
	if p, ok := names.(PluginNames); ok {
		return p.PluginWidth()
	}
	return 0
}

// HopHeaderFor is HopHeader with the PLUGIN column when names has plugins.
func HopHeaderFor(names Names) string {
	w := pluginWidth(names)
	if w == 0 {
		return HopHeader
	}
	return strings.TrimSuffix(HopHeader, "FLAGS") + fmt.Sprintf("%-*s FLAGS", w, "PLUGIN")
}

// Ms formats microseconds as milliseconds.
func Ms(us uint32) string {
	if us == 0 {
		return "-"
	}
	v := float64(us) / 1000
	switch {
	case v < 10:
		return fmt.Sprintf("%.2f", v)
	case v < 1000:
		return fmt.Sprintf("%.1f", v)
	}
	return fmt.Sprintf("%.0f", v)
}

// Pct formats a rate pointer; nil (UNKNOWN) is shown as "?".
func Pct(p *float64) string {
	if p == nil {
		return "?"
	}
	return fmt.Sprintf("%.1f%%", *p*100)
}

// CI formats a Wilson interval.
func CI(w core.WinSnap) string {
	if w.WilsonLo == nil {
		return "?"
	}
	return fmt.Sprintf("%.1f–%.1f%%", *w.WilsonLo*100, *w.WilsonHi*100)
}

// Age formats milliseconds.
func Age(ms int64) string {
	switch {
	case ms < 0:
		return "never"
	case ms < 1000:
		return fmt.Sprintf("%dms", ms)
	case ms < 120000:
		return fmt.Sprintf("%.0fs", float64(ms)/1000)
	}
	return fmt.Sprintf("%.0fm", float64(ms)/60000)
}

func addr(names Names, ip netip.Addr) string {
	if !ip.IsValid() {
		return ""
	}
	if names != nil {
		if n := names.Name(ip); n != "" {
			return n + " (" + ip.String() + ")"
		}
	}
	return ip.String()
}

// addrList is addresses as text, joined.
func addrList(a []netip.Addr, sep string) string {
	out := make([]string, len(a))
	for i, x := range a {
		out[i] = x.String()
	}
	return strings.Join(out, sep)
}

// hostWidth is the width of the HOST column.
const hostWidth = 40

// HopLine renders one hop with MTR-like columns.
func HopLine(h core.HopSnap, names Names) string { return HopLineTree(h, names, "") }

// HopLineTree renders a hop with the tree prefix inside the host column so
// that the numeric columns stay aligned at any depth.
func HopLineTree(h core.HopSnap, names Names, prefix string) string {
	return HopLineNote(h, names, prefix, hopNote(h, names))
}

// hopNote is the network annotation of the hop's responder.
func hopNote(h core.HopSnap, names Names) string {
	if names == nil || !h.Responder.IsValid() || h.Kind == core.KindServer || h.Kind == core.KindSilent {
		return ""
	}
	return names.Note(h.Responder)
}

// TreeNotes returns the annotation to print on each tree row: shown where
// it changes along the branch (a new AS, IX or location), blank where it
// repeats the nearest annotated hop above. Rows without one inherit.
func TreeNotes(rows []core.TreeRow, names Names) []string {
	out := make([]string, len(rows))
	if names == nil {
		return out
	}
	eff := make([]string, len(rows)) // the annotation in force at each row
	for i, r := range rows {
		parent := ""
		if r.Parent >= 0 && r.Parent < i {
			parent = eff[r.Parent]
		}
		n := hopNote(r.Hop, names)
		switch {
		case n == "":
			eff[i] = parent
		case n == parent:
			eff[i] = n
		default:
			eff[i], out[i] = n, n
		}
	}
	return out
}

// PathNotes is TreeNotes for the hops of one path, in TTL order.
func PathNotes(hops []core.HopSnap, names Names) []string {
	out := make([]string, len(hops))
	if names == nil {
		return out
	}
	last := ""
	for i, h := range hops {
		if n := hopNote(h, names); n != "" && n != last {
			out[i], last = n, n
		}
	}
	return out
}

// HopLineNote is HopLineTree with the annotation given ("" = none).
func HopLineNote(h core.HopSnap, names Names, prefix, note string) string {
	var host string
	switch h.Kind {
	case core.KindSilent:
		host = "* no reply"
	case core.KindUnknown:
		if h.Responder.IsValid() {
			host = "? " + addr(names, h.Responder) + " (unconfirmed)"
		} else {
			host = fmt.Sprintf("? no reply yet (%d probes)", h.Sent)
		}
	case core.KindHidden:
		host = "? only later hops answer: " + addrList(h.Through, ", ")
	case core.KindUnstable:
		host = "~ " + addrList(append([]netip.Addr{h.Responder}, h.Others...), " | ")
	case core.KindDst:
		host = "DST " + addr(names, h.Responder)
		if h.Name != "" { // the anycast server this flow reaches: "S3 (1000 Hz)"
			if full := host + " → " + h.Name; len([]rune(full)) <= hostWidth-len([]rune(prefix)) {
				host = full
			} else {
				host += " → " + strings.Fields(h.Name)[0]
			}
		}
	case core.KindServer:
		host = "server " + h.Server
		if h.Name != "" {
			host += " (" + h.Name + ")"
		}
	default:
		host = addr(names, h.Responder)
	}
	ttl := fmt.Sprint(h.TTL)
	if h.Kind == core.KindServer {
		ttl = ""
	}
	if h.TTLTo > h.TTL {
		ttl = fmt.Sprintf("%d-%d", h.TTL, h.TTLTo)
		if h.Kind == core.KindSilent || h.Replies == 0 {
			host = fmt.Sprintf("* no reply (%d hops)", h.TTLTo-h.TTL+1)
		}
	}
	var flags []string
	if h.Stale {
		flags = append(flags, "stale")
	}
	if h.RateLimit {
		flags = append(flags, "icmp-limit?")
	}
	if len(h.Through) > 0 && h.Kind != core.KindHidden {
		// The router answers an expiring probe and lets it go on: the
		// routers after it answer the same probe too.
		flags = append(flags, "also answered by later hop "+addrList(h.Through, ", "))
	}
	if h.Unstable && h.Kind != core.KindUnstable {
		flags = append(flags, "unstable")
	}
	if h.LowConf > 0 {
		flags = append(flags, fmt.Sprintf("qseq:%d", h.LowConf))
	}
	if h.Unreach {
		flags = append(flags, "unreach")
	}
	if len(h.MPLS) > 0 {
		// One stack is a/b (outermost first); different stacks for
		// different ports are separated by commas.
		stacks := h.MPLSStacks
		if len(stacks) == 0 {
			stacks = [][]uint32{h.MPLS}
		}
		var ss []string
		for _, st := range stacks {
			var l []string
			for _, x := range st {
				l = append(l, fmt.Sprint(x))
			}
			ss = append(ss, strings.Join(l, "/"))
		}
		flags = append(flags, "mpls:"+strings.Join(ss, ","))
	}
	if note != "" {
		flags = append(flags, note)
	}
	loss := "-"
	if h.Loss != nil {
		loss = fmt.Sprintf("%.1f%%", *h.Loss*100)
	}
	hw := hostWidth
	if prefix != "" {
		prefix += " " // a space before the address: double-click copies just the address
	}
	pw := len([]rune(prefix))
	host = prefix + trunc(host, max(8, hw-pw))
	if r := []rune(host); len(r) < hw {
		host += strings.Repeat(" ", hw-len(r))
	}
	tail := strings.Join(flags, " ")
	if w := pluginWidth(names); w > 0 {
		pn := ""
		if h.Responder.IsValid() && h.Kind != core.KindServer && h.Kind != core.KindSilent {
			pn = names.(PluginNames).PluginNote(h.Responder)
		}
		if h.AppNote != "" { // DST and server rows: the application plugin's note
			pn = strings.TrimSpace(pn + " " + h.AppNote)
		}
		pn = trunc(pn, w)
		// padded even when empty: what the caller puts after the row (the
		// route of a DST row) stays under FLAGS
		tail = pn + strings.Repeat(" ", w-len([]rune(pn))) + " " + tail
	}
	if h.Replies == 0 {
		return fmt.Sprintf("%-5s %s %6s %4d %46s %s", ttl, host, loss, h.Sent, "", tail)
	}
	return fmt.Sprintf("%-5s %s %6s %4d %7s %7s %7s %7s %7s %6s %s",
		ttl, host, loss, h.Sent, Ms(h.Last), Ms(h.Median), Ms(h.P95), Ms(h.Min), Ms(h.Max),
		Ms(uint32(h.Jitter)), tail)
}

// DownNote explains a DOWN threshold above the default: on a flow that
// already loses probes a longer run of failures is needed for DOWN.
func DownNote(f core.FlowSnap) string {
	if f.DownNeed <= 5 {
		return ""
	}
	return fmt.Sprintf(" (DOWN at %d: background loss %.0f%%)", f.DownNeed, f.BGLoss*100)
}

// HopHeader matches HopLine. Loss% of a hop is the share of unanswered
// ICMP probes ("apparent loss"), not transit loss.
const HopHeader = "TTL   HOST                                      Loss%  Snt    Last     Med     P95    Best    Wrst   Jttr FLAGS"

// RouteNames maps PathGroup IDs to short display names (A, B, … Z, AA…)
// in the endpoint's group order (most confident and largest first).
func RouteNames(e core.EPSnap) map[string]string {
	m := map[string]string{}
	// Letters follow the tree from top to bottom; routes not in the tree
	// (no snapshot tree) follow in group order.
	var ids []string
	seen := map[string]bool{}
	for _, r := range e.Tree {
		if r.Group != nil && !seen[r.Group.ID] {
			ids, seen[r.Group.ID] = append(ids, r.Group.ID), true
		}
	}
	for _, g := range e.Groups {
		if !seen[g.ID] {
			ids, seen[g.ID] = append(ids, g.ID), true
		}
	}
	for i, id := range ids {
		n := ""
		for k := i; ; k = k/26 - 1 {
			n = string(rune('A'+k%26)) + n
			if k < 26 {
				break
			}
		}
		m[id] = n
	}
	return m
}

// ports joins source ports: "20000,20019".
func ports(p []wire.Port) string {
	s := make([]string, len(p))
	for i, x := range p {
		s[i] = fmt.Sprint(x)
	}
	return strings.Join(s, ",")
}

// ServerTag is the flags text of a server row: its state and measured port.
func ServerTag(r core.TreeRow) string {
	word, tail := ServerTagParts(r)
	return word + tail
}

// ServerTagParts is ServerTag as the state word and the rest.
func ServerTagParts(r core.TreeRow) (word, tail string) {
	if len(r.SPorts) > 0 {
		tail += " · sport " + ports(r.SPorts)
	}
	if r.App[0] > 0 {
		tail += fmt.Sprintf(" · app %d of %d failed", r.App[1], r.App[0])
	}
	return r.State.String(), tail
}

// AnycastLine summarises the census of the servers behind the address.
func AnycastLine(e core.EPSnap) string {
	a := e.Anycast
	if a == nil {
		return ""
	}
	switch a.Status {
	case core.ACUnidentifiable:
		return fmt.Sprintf("servers behind the address: cannot be told apart — the TCP timestamp clock differs per connection (%d answers from %d ports); on servers you run, net.ipv4.tcp_timestamps=2 makes it one per machine", a.Answers, a.Explored)
	case core.ACNoTimestamps:
		return "servers behind the address: cannot be told apart — replies carry no TCP timestamp"
	case core.ACRunning:
		return fmt.Sprintf("servers behind the address: %d so far · census running (%d ports)", len(a.Servers), a.Explored)
	}
	m := 0
	for _, s := range a.Servers {
		if len(s.Measured) > 0 {
			m++
		}
	}
	l := fmt.Sprintf("servers behind the address: %d (census of %d ports) · %d measured", len(a.Servers), a.Explored, m)
	if a.Moved > 0 {
		l += fmt.Sprintf(" · %d answers of measured ports on another server's clock", a.Moved)
	}
	if a.Phantoms > 0 {
		l += fmt.Sprintf(" (%d census servers dropped: never confirmed, all their ports answer as other servers)", a.Phantoms)
	}
	return l
}

// ServerHeader is the header of the server list (columns as the tree's).
var ServerHeader = strings.Replace(HopHeader, "TTL   HOST    ", "      SERVER  ", 1)

// ServerLine is one server of the list: its end-to-end numbers in the
// tree's columns, then state, measured port, ports, route, app checks.
func ServerLine(s core.ServerSnap, routes []string) string {
	h := s.E2E
	h.Kind, h.Server, h.Name = core.KindServer, s.Name, fmt.Sprintf("%.0f Hz", s.Hz)
	st := s.State
	if st == core.RowNone {
		st = core.RowNotMeasured
	}
	tag := st.String()
	if len(s.Measured) > 0 {
		tag += " · sport " + ports(s.Measured)
	}
	tag += fmt.Sprintf(" · %d ports", s.Ports)
	switch len(routes) {
	case 0:
		if len(s.Measured) > 0 {
			tag += " · route not known yet" // its port's trace is still incomplete
		}
	case 1:
		tag += " · route " + routes[0]
	default:
		tag += " · routes " + strings.Join(routes, ",")
	}
	if s.App[0] > 0 {
		tag += fmt.Sprintf(" · app %d of %d failed", s.App[1], s.App[0])
	}
	return HopLineTree(h, nil, "") + "  " + tag
}

// RouteState is the state word of a route: OK, LOSS, DOWN, WARMUP,
// UNKNOWN or "not measured".
func RouteState(g core.GroupSnap) core.RowState {
	switch {
	case g.Monitored == 0:
		return core.RowNotMeasured
	case g.State == core.GUnknown && g.Warmup > 0:
		return core.RowWarmup
	}
	return g.State.Row()
}

// RouteTag is the short route summary shown in the flags of its DST row:
// name, state, the measured port(s), and how many ports discovery traced
// to it. Loss and RTT of the route are the DST row's own columns.
func RouteTag(g core.GroupSnap, name string) string {
	head, word, tail := RouteTagParts(g, name)
	return head + word + tail
}

// RouteTagParts is RouteTag in three parts: the text before the state
// word, the word, and the rest. Whoever colours the state colours the word
// it is given, and never looks for it in the text.
func RouteTagParts(g core.GroupSnap, name string) (head, word, tail string) {
	head, word = "route "+name+" ", RouteState(g).String()
	tag := ""
	var ms []string
	for i, p := range g.Measured {
		if i == 2 {
			ms = append(ms, fmt.Sprintf("+%d", len(g.Measured)-2))
			break
		}
		ms = append(ms, fmt.Sprint(p))
	}
	if len(ms) > 0 {
		tag += " · sport " + strings.Join(ms, ",")
	}
	if n := len(g.Flows) + len(g.Tentative); n > 1 {
		tag += fmt.Sprintf(" · %d ports", n)
	}
	return head, word, tag
}

// GroupLine renders the E2E line at the end of a tree branch.
func GroupLine(g core.GroupSnap) string { return GroupLineNamed(g, "") }

// GroupParts returns the head ("route X: STATE") and the result text of a
// route's E2E line.
func GroupParts(g core.GroupSnap, name string) (head, tail string) {
	var notes []string
	switch g.Level {
	case core.LevelPartialDistinct:
		notes = append(notes, "partly traced, provably different")
	case core.LevelUnresolved:
		notes = append(notes, "not fully traced yet")
	case core.LevelTentative, core.LevelAmbiguous:
		notes = append(notes, g.Level.String())
	}
	if g.HiddenHops {
		notes = append(notes, "some hops never answer")
	}

	if g.Hetero {
		notes = append(notes, "flows on this route differ!")
	}
	label := "route " + g.ID
	if name != "" {
		label = "route " + name
	}
	// State word: UNKNOWN only because flows are still collecting their first
	// samples reads as a problem; call it what it is (RouteState).
	st := RouteState(g).String()
	var res string
	switch {
	case g.Monitored == 0:
		st, res = "-", "not measured (found by discovery only)"
	case g.W5.Valid == 0:
		res = "no answers yet"
	case g.W5.Valid > 0 && g.W5.Timeout+g.W5.Unreach == 0:
		res = fmt.Sprintf("0 of %d probes failed", g.W5.Valid) + appChecks(g.W5, ", ")
	default:
		res = fmt.Sprintf("%s of %d probes failed", Pct(g.W5.FailureRate), g.W5.Valid) + appChecks(g.W5, ", ")
	}
	// Which ports are measured end to end, and how many ports discovery
	// traced (once) to this route.
	var ms []string
	for i, p := range g.Measured {
		if i == 3 {
			ms = append(ms, fmt.Sprintf("+%d", len(g.Measured)-3))
			break
		}
		ms = append(ms, fmt.Sprint(p))
	}
	total := len(g.Flows) + len(g.Tentative)
	who := fmt.Sprintf("%d ports traced to this route", total)
	if total == 1 {
		who = "1 port traced to this route"
	}
	if len(ms) > 0 {
		who = "measured sport " + strings.Join(ms, ",") + " · " + who
	}
	if g.Warmup > 0 && g.Warmup < g.Monitored {
		notes = append([]string{fmt.Sprintf("%d still warming up", g.Warmup)}, notes...)
	}
	note := ""
	if len(notes) > 0 {
		note = "  (" + strings.Join(notes, ", ") + ")"
	}
	rtt := ""
	if g.RTTMedian > 0 {
		rtt = " · rtt " + Ms(g.RTTMedian) + " ms"
	}
	return label + ": " + st, fmt.Sprintf("%s%s · %s%s", res, rtt, who, note)
}

// GroupLineNamed renders the E2E line of a route on one line.
func GroupLineNamed(g core.GroupSnap, name string) string {
	h, t := GroupParts(g, name)
	return fmt.Sprintf("%-17s %s", h, t)
}

// RouteLineTree renders the E2E line of a route inside the hop table: the
// tree prefix and "route X: STATE" fill the HOST column, the result starts
// at the Loss% column like the hop numbers.
func RouteLineTree(g core.GroupSnap, name, prefix string) string {
	h, t := GroupParts(g, name)
	host := prefix + " " + h
	if r := []rune(host); len(r) < 40 {
		host += strings.Repeat(" ", 40-len(r))
	}
	return fmt.Sprintf("%-5s %s  %s", "", host, t)
}

// UnresolvedLine lists ports whose trace still fits several routes (a hop
// has not answered yet); "" when there are none.
func UnresolvedLine(e core.EPSnap) string {
	if len(e.Unresolved) == 0 {
		return ""
	}
	rn := RouteNames(e)
	var parts []string
	for i, u := range e.Unresolved {
		if i == 6 {
			parts = append(parts, fmt.Sprintf("+%d more", len(e.Unresolved)-6))
			break
		}
		var fits []string
		for _, id := range u.Fits {
			fits = append(fits, dash(rn[id]))
		}
		parts = append(parts, fmt.Sprintf("%s (sport %d) fits %s", u.Flow, u.SPort, strings.Join(fits, " or ")))
	}
	return "not yet assigned (a hop has not answered yet): " + strings.Join(parts, "; ")
}

// StoppedLine reports measured ports stopped as duplicates of a route.
func StoppedLine(e core.EPSnap) string {
	if len(e.Stopped) == 0 {
		return ""
	}
	rn := RouteNames(e)
	var parts []string
	for _, s := range e.Stopped {
		to := "route " + dash(rn[s.Group])
		if s.Server != "" {
			to = "server " + s.Server
		}
		parts = append(parts, fmt.Sprintf("%s (sport %d) → %s", s.Flow, s.SPort, to))
	}
	return "stopped measuring (another port already measures it): " + strings.Join(parts, "; ")
}

// DiscoveryStop says in words why discovery stopped.
func DiscoveryStop(d core.DiscoveryStatus) string {
	switch d.Reason {
	case core.StopStability:
		return fmt.Sprintf("done: no new route among the last %d ports traced (%d ports traced)", d.BatchesWithoutNew, d.Ports)
	case core.StopMaxFlows:
		return fmt.Sprintf("stopped: port limit reached (%d ports traced, more routes may exist)", d.Ports)
	case core.StopBudget:
		return fmt.Sprintf("stopped: no free source ports left to trace (%d ports traced, more routes may exist)", d.Ports)
	case core.StopDeadline:
		return fmt.Sprintf("stopped: time limit (%d ports traced, more routes may exist)", d.Ports)
	case core.StopInsufficientData:
		return fmt.Sprintf("stopped: no hop answered (%d ports traced)", d.Ports)
	}
	return fmt.Sprintf("done: %s (%d ports traced)", d.Reason, d.Ports)
}

// FlowHeader matches FlowLine.
const FlowHeader = "FLOW  SPORT  STATE     ROUTE   TRACED      EXEC VALID  TMO  UNR  FAIL5m  CI95          LAST    MIN    MED    P95    MAX  JIT  FLAGS"

// FlowLine renders one flow row.
func FlowLine(f core.FlowSnap) string {
	return FlowLineNamed(f, dash(f.Group))
}

// FlowLineNamed renders a flow row with a display name for its route.
func FlowLineNamed(f core.FlowSnap, route string) string {
	st := f.State.String()
	if f.State == core.FInvalid {
		st = "INVALID"
	}
	if f.State == core.FUnknown && f.Reason == core.ReasonWarmup {
		st = "WARMUP"
	}
	flags := make([]string, 0, len(f.Flags))
	for _, fl := range f.Flags {
		word := string(fl)
		if h, ok := humanFlag[fl]; ok {
			word = h
		}
		if word != "" {
			flags = append(flags, word)
		}
	}
	if f.W5.AppFail > 0 {
		// TCP answered, the application check failed: not a timeout.
		flags = append(flags, fmt.Sprintf("app-failed:%d/%d", f.W5.AppFail, f.W5.App))
	}
	return fmt.Sprintf("%-5s %5d  %-8s  %-7s %-11s %4d %5d %4d %4d  %6s  %-12s %6s %6s %6s %6s %6s %4s  %s",
		f.Name, f.SPort, st, route, trunc(LevelWord(f.Level), 11), f.Executed, f.W5.Valid, f.W5.Timeout, f.W5.Unreach,
		Pct(f.W5.FailureRate), CI(f.W5), Ms(f.RTT.Last), Ms(f.RTT.Min), Ms(f.RTT.Median), Ms(f.RTT.P95), Ms(f.RTT.Max),
		Ms(uint32(f.RTT.Jitter)), strings.Join(flags, ","))
}

// LevelWord says how sure the route assignment of a flow is, in words.
// (JSON has the names: confirmed, partial_distinct, tentative,
// ambiguous, unresolved.)
func LevelWord(l core.Level) string {
	switch l {
	case core.LevelConfirmed:
		return "yes"
	case core.LevelPartialDistinct:
		return "partly"
	case core.LevelTentative:
		return "probably"
	case core.LevelAmbiguous:
		return "ambiguous"
	}
	return "not yet"
}

// humanFlag shortens flags for the flow table; "" hides informational ones
// that are not problems. JSON keeps the full flag names.
var humanFlag = map[core.FlowFlag]string{
	core.FlagBaselineUnknown: "", // normal for the first minute; RTT-UP is simply not armed yet
	core.FlagQualityPending:  "",
	core.FlagRTTDegraded:     "RTT-UP",
	core.FlagRTTRelative:     "",
	core.FlagRTTAbsolute:     "",
	core.FlagImpaired:        "IMPAIRED",
	core.FlagInvalid:         "INVALID",
	core.FlagSeqTranslation:  "SEQ-REWRITE?",
	core.FlagIncidentTrace:   "traced",
}

// InvalidWhy says in words why a flow's measurement is not trusted ("" if
// it is).
func InvalidWhy(r core.InvalidReason) string {
	switch r {
	case core.InvalidWeakDominant:
		return "most packets on this port are not answers to our probes (another connection or prober uses it?)"
	case core.InvalidLocalNAT:
		return "a local NAT changes the source port"
	case core.InvalidSeqRewrite:
		return "a local middlebox rewrites sequence numbers"
	case core.InvalidLocalRoute:
		return "the local route of this port changed"
	case core.InvalidEgressMismatch:
		return "probes leave by another interface than routed"
	}
	return ""
}

// ReasonText is why a flow has no verdict, as shown next to its state.
func ReasonText(f core.FlowSnap) string {
	if f.Reason == core.ReasonInvalid {
		return "invalid: " + f.Invalid.String()
	}
	return f.Reason.String()
}

// FlowLegend explains the flow table.
var FlowLegend = []string{
	"EXEC = probes sent, VALID = probes with a usable result, TMO = no answer, UNR = ICMP unreachable, FAIL5m [CI95] = failure share over 5 min.",
	"With --app the application checks are counted apart from the TCP probes: flag app-failed:N/M (N of M checks failed; TCP answered, the service did not). Three failed checks in a row make the flow DOWN (app_down) even when TCP answers.",
	"TRACED: is the flow's route known? yes = traced and repeated · partly = incomplete but provably different · probably = fits one route · not yet.",
	"WARMUP = fewer than 30 results yet (port just added for a newly found route) · RTT-UP = RTT rose vs its own baseline or vs the other flows.",
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func trunc(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

// SeverityRank orders flow states for sorting (worst first).
func SeverityRank(s core.FState) int {
	switch s {
	case core.FDown:
		return 0
	case core.FLoss:
		return 1
	case core.FInvalid:
		return 2
	case core.FUnknown:
		return 3
	}
	return 4
}

// Verdict summarizes an endpoint in one plain sentence. It is never more
// categorical than the states it is derived from. kind: ok | bad | wait | warn.
func Verdict(e core.EPSnap, impaired bool) (kind, text string) {
	a := e.Agg
	names := RouteNames(e)
	var failing []string
	warm, stale, pending, other := 0, 0, 0, 0
	for _, f := range e.Flows {
		switch f.State {
		case core.FDown, core.FLoss:
			failing = append(failing, fmt.Sprintf("%d", f.SPort))
		case core.FUnknown:
			switch {
			case f.Reason == core.ReasonStale:
				stale++
			case f.Reason == core.ReasonLossPending:
				pending++
			case f.Reason == core.ReasonWarmup:
				warm++
			default:
				other++
			}
		}
	}
	short := func(l []string) string {
		if len(l) > 6 {
			return strings.Join(l[:6], ",") + fmt.Sprintf(" +%d", len(l)-6)
		}
		return strings.Join(l, ",")
	}
	loc := ""
	if L := e.Localization; len(L.SuspectedSegments) > 0 {
		loc = " Suspected segment: " + strings.Join(L.SuspectedSegments, " or ") + " (observed hops, not a proven link)."
	} else if L.Level == core.LocForwardNotDistinct {
		loc = " Failing and healthy flows share the same visible route: the difference is not visible from here."
	}
	prefix := ""
	if impaired {
		prefix = "measurer impaired (capture problems) — results below are not trusted for DOWN. "
	}
	switch {
	case a.Total == 0:
		return "wait", "no monitored flows"
	case e.State == core.EPDown && appDownOnly(e):
		why := ""
		for _, f := range e.Flows {
			if f.State == core.FDown && f.AppErr != "" {
				why = fmt.Sprintf(" Last failure: %s: %s.", f.AppStage, f.AppErr)
				break
			}
		}
		return "bad", prefix + fmt.Sprintf("DOWN: TCP answers on all %d flows, but the application does not: its checks fail in a row on each (%d of %d failed in 5 min).",
			a.Total, e.W5.AppFail, e.W5.App) + why
	case e.State == core.EPDown:
		return "bad", prefix + fmt.Sprintf("DOWN: none of the %d TCP flows gets an answer (a run of consecutive failures on each; TCP timeouts %d, ICMP unreachable %d in 5 min%s).",
			a.Total, e.W5.Timeout, e.W5.Unreach, appChecks(e.W5, "; ")) + loc
	case e.State == core.EPLoss && e.Scope == core.ScopePartial:
		w := ""
		if len(e.Groups) > 0 {
			var bad []string
			for _, g := range e.Groups {
				if g.State == core.GDown || g.State == core.GLoss {
					bad = append(bad, names[g.ID])
				}
			}
			if len(bad) > 0 {
				w = " on route " + strings.Join(bad, ",")
			}
		}
		return "bad", prefix + fmt.Sprintf("PARTIAL FAILURE: %d of %d flows fail%s (sport %s); the other flows are fine.", len(failing), a.Total, w, short(failing)) + loc
	case e.State == core.EPLoss:
		return "bad", prefix + fmt.Sprintf("LOSS: %d flows confirmed failing (sport %s), %d without enough data; E2E failure %s (95%% CI %s, n=%d).",
			len(failing), short(failing), a.Unknown, Pct(e.W5.FailureRate), CI(e.W5), e.W5.Valid) + loc
	case e.State == core.EPOK:
		routes := ""
		if n := len(e.Groups); n == 1 {
			routes = ", 1 route"
		} else if n > 1 {
			routes = fmt.Sprintf(", %d routes", n)
		}
		t := fmt.Sprintf("OK: %d of %d probes failed (95%% CI %s) on %d source ports%s%s.",
			e.W5.Timeout+e.W5.Unreach, e.W5.Valid, CI(e.W5), a.Total, routes, appChecks(e.W5, "; "))
		if a.RTTDegraded > 0 {
			return "warn", prefix + t + fmt.Sprintf(" RTT degraded on %d flows.", a.RTTDegraded)
		}
		if warm > 0 {
			t += fmt.Sprintf(" %d newly added ports still warming up.", warm)
		}
		if a.Unknown > warm {
			t += fmt.Sprintf(" %d flows without a verdict yet.", a.Unknown-warm)
		}
		return "ok", prefix + t
	}
	parts := []string{}
	if warm > 0 {
		parts = append(parts, fmt.Sprintf("%d warming up (need %d valid probes)", warm, 30))
	}
	if pending > 0 {
		parts = append(parts, fmt.Sprintf("%d with loss being confirmed", pending))
	}
	if stale > 0 {
		parts = append(parts, fmt.Sprintf("%d stale (no recent valid probes)", stale))
	}
	if other > 0 {
		parts = append(parts, fmt.Sprintf("%d without trustworthy data (see flow table)", other))
	}
	return "wait", prefix + fmt.Sprintf("collecting data: %d of %d flows have enough samples; %s.", a.Measured, a.Total, strings.Join(parts, ", "))
}

// EndpointSummary renders a compact 1–2 line summary (interactive screen).
func EndpointSummary(e core.EPSnap) []string {
	a := e.Agg
	warm := 0
	for _, f := range e.Flows {
		if f.State == core.FUnknown && f.Reason == core.ReasonWarmup {
			warm++
		}
	}
	var parts []string
	for _, x := range []struct {
		n int
		s string
	}{{a.OK, "ok"}, {a.Loss, "loss"}, {a.Down, "down"}, {warm, "warming up"}, {a.Unknown - warm, "unknown"}, {a.Invalid, "invalid"}} {
		if x.n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", x.n, x.s))
		}
	}
	var rtts []uint32
	for _, f := range e.Flows {
		if f.RTT.Median > 0 {
			rtts = append(rtts, f.RTT.Median)
		}
	}
	sort.Slice(rtts, func(i, j int) bool { return rtts[i] < rtts[j] })
	rtt := "-"
	if len(rtts) > 0 {
		rtt = Ms(rtts[len(rtts)/2])
	}
	d := e.Discovery
	disc := "discovery off"
	switch {
	case d.Running:
		disc = fmt.Sprintf("discovery running (%d ports traced)", d.Ports)
	case d.Stopped:
		disc = "discovery " + DiscoveryStop(d)
	}
	state := e.State.String()
	if e.Scope != core.ScopeNone && e.Scope != core.ScopeUnknown || e.State == core.EPLoss {
		state += "/" + e.Scope.String()
	}
	name := e.Target + " " + hostPort(e.Addr, e.Port)
	if hp := hostPort(e.Addr, e.Port); e.Target == hp || e.Target == e.Addr.String() {
		name = hp
	}
	l1 := fmt.Sprintf("%s  %s  │ flows %d: %s │ E2E fail %s n=%d [95%% CI %s] │ rtt %s ms",
		name, state, a.Total, strings.Join(parts, ", "), Pct(e.W5.FailureRate), e.W5.Valid, CI(e.W5), rtt)
	l2 := fmt.Sprintf("  routes found %d · %s", d.Branches, disc)
	if L := e.Localization; L.Level != core.LocNone {
		l2 += " · localization " + L.Level.String()
	}
	out := []string{l1, l2}
	var notes []string
	if a.RTTDegraded > 0 {
		notes = append(notes, fmt.Sprintf("RTT degraded on %d flows", a.RTTDegraded))
	}
	if e.Hetero.Loss == core.HeteroYes {
		notes = append(notes, "loss differs between flows: "+strings.Join(e.Hetero.LossOutliers, ","))
	}
	if e.Coverage.Incomplete {
		notes = append(notes, fmt.Sprintf("only %d of %d routes have monitored flows", e.Coverage.Represented, e.Coverage.Groups))
	}
	if len(notes) > 0 {
		out[1] += " · " + strings.Join(notes, " · ")
	}
	if l := AnycastLine(e); l != "" {
		out = append(out, "  "+l)
	}
	return out
}

// appChecks says how the application checks of a window went, after sep, or
// nothing when there were none (no --app). They are never pooled with the
// TCP probes: "application checks: 3 of 30 failed".
func appChecks(w core.WinSnap, sep string) string {
	if w.App == 0 {
		return ""
	}
	return fmt.Sprintf("%sapplication checks: %d of %d failed", sep, w.AppFail, w.App)
}

// appDownOnly: every flow that is DOWN is so because its application checks
// fail while TCP answers.
func appDownOnly(e core.EPSnap) bool {
	n := 0
	for _, f := range e.Flows {
		if f.State != core.FDown {
			continue
		}
		if f.Reason != core.ReasonAppDown {
			return false
		}
		n++
	}
	return n > 0
}

// EndpointHeader renders the detailed summary lines of an endpoint.
func EndpointHeader(w io.Writer, e core.EPSnap) {
	a := e.Agg
	fmt.Fprintf(w, "%s (%s)  %s/%s  flows %d: ok %d loss %d down %d unknown %d invalid %d  coverage %.0f%%\n",
		e.Target, hostPort(e.Addr, e.Port), e.State, e.Scope, a.Total, a.OK, a.Loss, a.Down, a.Unknown, a.Invalid, a.Coverage*100)
	fmt.Fprintf(w, "  E2E 5m: valid %d  tcp-timeout %d (%s)  icmp-unreach %d  failure %s [95%% CI %s]%s  failing flows %d of %d  worst %s %s  fully-down %d  rtt-degraded %d\n",
		e.W5.Valid, e.W5.Timeout, Pct(e.W5.TimeoutRate), e.W5.Unreach, Pct(e.W5.FailureRate), CI(e.W5), appChecks(e.W5, "  "),
		a.Loss+a.Down, a.Total-a.Invalid, dash(a.WorstFlow), pctv(a.WorstFailure, a.WorstFlow != ""), a.FullyDown, a.RTTDegraded)
	d := e.Discovery
	gm := "UNKNOWN"
	if d.SingletonMassOK {
		gm = fmt.Sprintf("%.3f", d.SingletonMass)
	}
	stop := string(d.Reason)
	if d.Running {
		stop = "running"
	} else if stop == "" {
		stop = "off"
	}
	fmt.Fprintf(w, "  discovery: %s  explored %d (+%d in progress)  branches %d  batches %d (no new %d)  singleton-mass %s\n",
		stop, d.Explored, d.InProgress, d.Branches, d.Batches, d.BatchesWithoutNew, gm)
	switch {
	case e.Coverage.Incomplete:
		fmt.Fprintf(w, "  COVERAGE INCOMPLETE: %d distinct groups, only %d have monitored flows (%d with fewer than 2)\n",
			e.Coverage.Groups, e.Coverage.Represented, e.Coverage.UnderRepresented)
	case e.Coverage.UnderRepresented > 0:
		fmt.Fprintf(w, "  coverage: %d distinct groups all monitored; %d with fewer than 2 monitored flows\n",
			e.Coverage.Groups, e.Coverage.UnderRepresented)
	}
	h := e.Hetero
	fmt.Fprintf(w, "  heterogeneity: flows %s %s  groups %s %s  rtt-relative %s\n", h.Loss, strings.Join(h.LossOutliers, ","),
		h.GroupLoss, strings.Join(h.GroupOutl, ","), strings.Join(h.RTTRelative, ","))
}

func pctv(v float64, ok bool) string {
	if !ok {
		return "?"
	}
	return fmt.Sprintf("%.1f%%", v*100)
}

// Tree renders the route tree (or nothing when no topology is known).
func Tree(w io.Writer, e core.EPSnap, names Names, width int) {
	if len(e.Tree) == 0 {
		fmt.Fprintln(w, "  (no observed topology yet — flow table only)")
		return
	}
	fmt.Fprintln(w, "  "+HopHeaderFor(names))
	rn := RouteNames(e)
	notes := TreeNotes(e.Tree, names)
	for i, r := range e.Tree {
		line := "  " + HopLineNote(r.Hop, names, r.Prefix, notes[i])
		if r.Group != nil {
			line += " " + RouteTag(*r.Group, rn[r.Group.ID])
		}
		if r.Hop.Kind == core.KindServer {
			line += " " + ServerTag(r)
		}
		fmt.Fprintln(w, clip(line, width))
	}
}

func clip(s string, width int) string {
	if width <= 0 {
		return s
	}
	r := []rune(s)
	if len(r) > width {
		return string(r[:width])
	}
	return s
}

// Localization renders the localization block.
func Localization(w io.Writer, L core.Localization) {
	if L.Level == core.LocNone {
		fmt.Fprintln(w, "  localization: none (no confirmed failing flows)")
		return
	}
	fmt.Fprintf(w, "  localization: %s", L.Level)
	if len(L.SuspectedSegments) > 0 {
		fmt.Fprintf(w, "  suspected segments: %s", strings.Join(L.SuspectedSegments, "; "))
	}
	if L.SuspectedLossStartTTL > 0 {
		fmt.Fprintf(w, "  suspected loss start TTL %d", L.SuspectedLossStartTTL)
	}
	fmt.Fprintln(w)
	for _, s := range L.Supporting {
		fmt.Fprintln(w, "    + "+s)
	}
	for _, s := range L.Contradicting {
		fmt.Fprintln(w, "    - "+s)
	}
	for _, s := range L.Limitations {
		fmt.Fprintln(w, "    ! "+s)
	}
}

// Measurer renders self-diagnostics.
func Measurer(w io.Writer, s *core.Snapshot) {
	m := s.M
	imp := "ok"
	if s.Impaired {
		imp = "MONITORING_IMPAIRED (" + strings.Join(s.ImpairedReasons, ",") + ")"
	}
	fmt.Fprintf(w, "measurer: %s  e2e %.0f pps  hop %.1f pps  inflight %d  responders %d (limited %d)  lag avg %.1fms max %.1fms\n",
		imp, s.E2EPPS, s.HopPPS, s.Inflight, s.Responders, s.RespLimited, s.LagAvgMs, s.LagMaxMs)
	fmt.Fprintf(w, "  capture drops %d (user %d)  unmatched %d  late %d  dup %d  unexpected %d  weak %d  challenge-ack %d  malformed %d\n",
		m.CaptureDrops, m.UserDrops, m.Unmatched, m.Late, m.Duplicate, m.Unexpected, m.Weak, m.ChallengeAck, m.Malformed)
	var sk []string
	for i, n := range m.SkipBy {
		if n > 0 {
			sk = append(sk, fmt.Sprintf("%s=%d", core.SkipReason(i), n))
		}
	}
	fmt.Fprintf(w, "  skipped E2E slots by reason: %s\n", dash(strings.Join(sk, " ")))
	fmt.Fprintf(w, "  tx-ts-fallback %d  tx-not-observed %d  local-errors %d  sched-skips %d  hop-deferred window/resp %d/%d  hop-cancelled %d  quote-seq-mismatch %d  nat %d  port-conflicts %d\n",
		m.TxTSFallback, m.TxNotObserved, m.LocalErrors, m.SchedSkips, m.HopDeferWindow, m.HopDeferResp, m.HopCancelled, m.QuoteSeqMismatch, m.NATDetected, m.PortConflicts)
}

// Text writes a full plain-text report.
func Text(w io.Writer, s *core.Snapshot, names Names, header string) {
	if header != "" {
		fmt.Fprintln(w, header)
	}
	for _, e := range s.Endpoints {
		fmt.Fprintln(w)
		_, v := Verdict(e, s.Impaired)
		fmt.Fprintln(w, "VERDICT "+e.Target+": "+v)
		EndpointHeader(w, e)
		fmt.Fprintln(w, "  route tree (hop Loss% = unanswered ICMP probes to that hop, not transit loss):")
		Tree(w, e, names, 0)
		if l := UnresolvedLine(e); l != "" {
			fmt.Fprintln(w, "  "+l)
		}
		if l := StoppedLine(e); l != "" {
			fmt.Fprintln(w, "  "+l)
		}
		if len(e.Unassigned) > 0 {
			fmt.Fprintf(w, "  flows whose route is not traced yet (run longer): %s\n", strings.Join(e.Unassigned, ","))
		}
		Localization(w, e.Localization)
		fmt.Fprintln(w, "  flows:")
		fmt.Fprintln(w, "  "+FlowHeader)
		fl := append([]core.FlowSnap(nil), e.Flows...)
		sort.SliceStable(fl, func(i, j int) bool { return fl[i].SPort < fl[j].SPort })
		rn := RouteNames(e)
		for _, f := range fl {
			fmt.Fprintln(w, "  "+FlowLineNamed(f, dash(rn[f.Group])))
		}
		for _, l := range FlowLegend {
			fmt.Fprintln(w, "  "+l)
		}
	}
	fmt.Fprintln(w)
	Measurer(w, s)
}

// JSONReport is the machine-readable report.
type JSONReport struct {
	Tool       string                     `json:"tool"`
	Version    string                     `json:"version"`
	Started    time.Time                  `json:"started"`
	Finished   time.Time                  `json:"finished"`
	Complete   bool                       `json:"complete"`
	Incomplete []string                   `json:"incomplete_reasons,omitempty"`
	ExitCode   int                        `json:"exit_code"`
	Params     Params                     `json:"parameters"`
	Snapshot   *core.Snapshot             `json:"result"`
	Events     []core.Event               `json:"events"`
	Warnings   []string                   `json:"warnings,omitempty"`
	IPInfo     map[netip.Addr]enrich.Info `json:"ip_info,omitempty"` // --asn / --ix / --geoip
	// HopInfo: address → plugin name → what it said (--hop-info).
	HopInfo map[netip.Addr]map[string]HopNote `json:"hop_info,omitempty"`
}

// Params are the settings the report was made with.
type Params struct {
	Mode          string  `json:"mode"` // report | discover
	Count         int     `json:"count"`
	Interval      string  `json:"interval"`
	Timeout       string  `json:"timeout"`
	FlowsPerRoute int     `json:"flows_per_route"`
	Ports         int     `json:"ports"`
	MaxTTL        int     `json:"max_ttl"`
	PPS           float64 `json:"pps"`
	ResponderPPS  float64 `json:"responder_pps"`
	Discovery     bool    `json:"discovery"`
	PcapFilter    string  `json:"pcap_filter"`
}

// HopNote is what one hop-information plugin said about an address.
type HopNote struct {
	Name string `json:"name,omitempty"`
	Note string `json:"note,omitempty"`
}

// JSON writes the report.
func JSON(w io.Writer, r *JSONReport) error {
	if r.Events == nil {
		r.Events = []core.Event{} // "events": [] and not null: a script iterates it
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

func hostPort(a netip.Addr, p wire.Port) string { return netip.AddrPortFrom(a, uint16(p)).String() }
