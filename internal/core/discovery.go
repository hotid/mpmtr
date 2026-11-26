package core

// StopReason of discovery. None of them means that all physical paths were
// found.
type StopReason string

const (
	StopNone             StopReason = ""
	StopStability        StopReason = "stability_limit"
	StopMaxFlows         StopReason = "max_flows"
	StopBudget           StopReason = "budget_exhausted"
	StopDeadline         StopReason = "deadline"
	StopInsufficientData StopReason = "insufficient_data"
)

type discovery struct {
	cursor       int // next index in ep.ports
	explored     int
	inBatch      int
	ports        int // distinct ports traced (explored also counts repeated traces)
	batches      int
	noNew        int
	sinceNew     int // ports explored since the last new route
	lastBranches int
	stopped      bool
	reason       StopReason
	started      Mono
	stoppedAt    Mono
	candidates   int
	extraSweeps  map[FlowID]int
}

// DiscoveryStatus is the public view of discovery progress.
type DiscoveryStatus struct {
	Ports             int        `json:"ports_traced"` // distinct source ports traced
	Explored          int        `json:"explored"`     // traces finished (a port can be traced again)
	InProgress        int        `json:"in_progress"`
	Candidates        int        `json:"candidates"`
	Batches           int        `json:"batches"`
	BatchesWithoutNew int        `json:"batches_without_new"`
	Branches          int        `json:"branches"`
	Stopped           bool       `json:"stopped"`
	Reason            StopReason `json:"reason"`
	Running           bool       `json:"running"`
}

func (c *Core) startDiscovery(ep *Endpoint) {
	d := &ep.disc
	d.started = c.now
	d.extraSweeps = map[FlowID]int{}
	if c.countMonitored(ep) == 0 {
		// No measured port (--discover): one SYN to the destination gives
		// the path-length hint (reply TTL) that lets traces go parallel.
		if f, err := c.newFlow(ep, ep.ports[d.cursor]); err == nil {
			d.cursor++
			c.send(f, ClassE2E, TTL(c.cfg.E2ETTL), c.cfgDur(c.cfg.Timeout))
		}
	}
	// Initial sample: monitored flows first, then new ports.
	var batch []*Flow
	for _, f := range ep.Flows {
		if len(batch) < c.cfg.DiscInitial {
			batch = append(batch, f)
		}
	}
	batch = append(batch, c.newCandidates(ep, c.cfg.DiscInitial-len(batch))...)
	c.launchBatch(ep, batch)
}

func (c *Core) newCandidates(ep *Endpoint, n int) []*Flow {
	var out []*Flow
	d := &ep.disc
	for len(out) < n && d.cursor < len(ep.ports) && len(ep.Flows) < c.cfg.MaxFlows+64 {
		if d.candidates+len(out) >= c.cfg.MaxFlows {
			break
		}
		f, err := c.newFlow(ep, ep.ports[d.cursor])
		d.cursor++
		if err != nil {
			continue
		}
		out = append(out, f)
	}
	return out
}

func (c *Core) launchBatch(ep *Endpoint, batch []*Flow) {
	d := &ep.disc
	for _, f := range batch {
		if f.sw != nil {
			continue
		}
		d.inBatch++
		d.candidates++
		c.startSweep(f, ClassDiscovery, 1)
	}
	if d.inBatch == 0 {
		c.stopDiscovery(ep, StopBudget)
	}
}

func (c *Core) discCandidateDone(f *Flow) {
	ep := f.EP
	d := &ep.disc
	if d.stopped {
		return
	}
	d.explored++
	if !f.traced {
		f.traced = true
		d.ports++
	}
	d.inBatch--
	// Pipeline: every finished port updates the routes and the stop rule
	// and is replaced by the next port (no waiting for a whole batch).
	c.discProgress(ep)
}

// resolvable returns flows whose ambiguity more probes could still resolve.
func (c *Core) resolvable(ep *Endpoint) []*Flow {
	var out []*Flow
	for _, f := range ep.Flows {
		if f.level != LevelAmbiguous && f.level != LevelUnresolved {
			continue
		}
		if f.sw != nil || ep.disc.extraSweeps[f.ID] >= 2 || f.route.sweeps == 0 {
			continue
		}
		L := TTL(len(f.sig.hops))
		for t := TTL(1); t <= L; t++ {
			if h := f.route.hopIf(t); h != nil && f.sig.hops[t-1].kind == eUnknown && h.Sent < 3 {
				out = append(out, f)
				break
			}
		}
	}
	return out
}

func (c *Core) discProgress(ep *Endpoint) {
	d := &ep.disc
	c.regroup(ep)
	b := ep.branches()
	if b > d.lastBranches {
		d.sinceNew = 0
		d.lastBranches = b
	} else {
		d.sinceNew++
	}
	d.noNew = d.sinceNew
	d.batches = d.explored
	c.assignMonitors(ep) // new routes are measured right away

	// Stop when new ports keep landing on known routes: no new route among
	// the last max(32, 8×routes) explored ports (with k equally likely
	// routes the chance to miss one is <= (1-1/k)^(8k) ≈ 0.03%).
	res := c.resolvable(ep)
	if d.explored >= c.cfg.DiscInitial && d.sinceNew >= max(32, 8*b) && len(res) == 0 {
		c.stopDiscovery(ep, StopStability)
		return
	}
	// Refill up to the concurrency: unresolved ports first, then new ones.
	want := c.cfg.DiscInitial - d.inBatch
	var batch []*Flow
	for _, f := range res {
		if len(batch) >= want {
			break
		}
		d.extraSweeps[f.ID]++
		d.candidates-- // not a new candidate
		batch = append(batch, f)
	}
	if len(batch) < want {
		batch = append(batch, c.newCandidates(ep, want-len(batch))...)
	}
	if len(batch) == 0 && d.inBatch == 0 {
		if d.candidates >= c.cfg.MaxFlows {
			c.stopDiscovery(ep, StopMaxFlows)
		} else {
			c.stopDiscovery(ep, StopBudget)
		}
		return
	}
	for _, f := range batch {
		if f.sw != nil {
			continue
		}
		d.inBatch++
		d.candidates++
		c.startSweep(f, ClassDiscovery, 1)
	}
}

func (c *Core) stopDiscovery(ep *Endpoint, r StopReason) {
	d := &ep.disc
	if d.stopped {
		return
	}
	c.regroup(ep)
	if r != StopDeadline && ep.branches() == 0 {
		known := false
		for _, f := range ep.Flows {
			if f.sig.known > 0 {
				known = true
				break
			}
		}
		if !known {
			r = StopInsufficientData
		}
	}
	d.stopped, d.reason, d.stoppedAt = true, r, c.now
	// Cancel outstanding discovery sweeps (not monitored refresh).
	for _, f := range ep.Flows {
		if f.sw != nil && f.sw.class == ClassDiscovery && !f.retrace {
			f.sw = nil
		}
	}
	d.inBatch = 0
}

// StopDiscovery ends discovery on all endpoints with the deadline reason.
func (c *Core) StopDiscovery() {
	for _, ep := range c.eps {
		if !ep.disc.stopped && c.cfg.Discovery {
			c.stopDiscovery(ep, StopDeadline)
		}
	}
}

// DiscoveryDone reports whether all endpoints finished discovery.
func (c *Core) DiscoveryDone() bool {
	for _, ep := range c.eps {
		if !ep.disc.stopped {
			return false
		}
	}
	return true
}

func (ep *Endpoint) discoveryStatus(enabled bool) DiscoveryStatus {
	d := &ep.disc
	return DiscoveryStatus{Ports: d.ports, Explored: d.explored, InProgress: d.inBatch, Candidates: d.candidates,
		Batches: d.batches, BatchesWithoutNew: d.noNew, Branches: ep.branches(),
		Stopped: d.stopped, Reason: d.reason,
		Running: enabled && !d.stopped}
}
