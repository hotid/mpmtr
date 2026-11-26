package core

import "time"

// Application checks: a plugin speaks a protocol to the server over a real
// TCP connection opened from the flow's own source port — the same 4-tuple
// the TCP probes use, so a load balancer leads it to the same server. While
// the check runs the flow's raw probes pause (slots count as skipped, never
// as loss) and the correlator leaves the connection's packets alone. A
// failed check is a failure of that server, like a lost probe.

// appDue: an application check is due on this measured port.
func (c *Core) appDue(f *Flow) bool {
	if !c.cfg.App || !f.Role.Monitored() || f.invalid != ValidFlow || f.active != nil || f.burst > 0 || f.appWant {
		return false
	}
	if _, ok := c.tr.(AppChecker); !ok {
		return false
	}
	// Not while discovery or the census sends hundreds of SYNs a second to
	// the same address: under that load real connections time out, and the
	// failure would be the measurer's, not the server's.
	if ep := f.EP; (c.cfg.Discovery && !ep.disc.stopped) || (ep.ac != nil && ep.ac.status == ACRunning) {
		return false
	}
	if f.appDueAt == 0 {
		// spread the first checks over one interval
		f.appDueAt = c.now + Mono(c.hash64(uint64(f.ID), 0xA99)%uint64(c.cfgDur(c.cfg.AppInterval)))
	}
	return c.now >= f.appDueAt
}

func (c *Core) startApp(f *Flow) {
	p := c.allocProbe()
	p.flow, p.class = f, ClassApp
	p.sentMono, p.sentRT = c.now, c.nowRT
	to := c.cfgDur(c.cfg.AppTimeout)
	p.deadMono, p.deadRT = c.now+to+Mono(2*time.Second), c.nowRT.Add(time.Duration(to)+2*time.Second)
	f.active = p
	f.appDueAt = c.now + c.cfgDur(c.cfg.AppInterval)
	f.appUntil = p.deadMono + Mono(time.Second)
	f.C.AppSent++
	c.apps[p.id] = p
	c.inflight++
	c.push(event{at: p.deadMono, kind: evDeadline, p: p, gen: p.id})
	c.tr.(AppChecker).AppCheck(f, p.id, c.cfg.AppTimeout)
}

// OnAppResult delivers the result of an application check (core goroutine).
func (c *Core) OnAppResult(id uint64, r AppResult) {
	c.now, c.nowRT = c.clk.Now()
	if p := c.apps[id]; p != nil {
		c.finishApp(p, r)
	}
}

func (c *Core) finishApp(p *Probe, r AppResult) {
	delete(c.apps, p.id)
	if p.completed {
		return
	}
	f := p.flow
	f.appUntil = c.now + Mono(time.Second) // late packets of the connection
	var o Outcome
	switch r.Outcome {
	case AppLocal, AppPluginFailed:
		o = OutLocalError
		f.C.AppLocal++
	case AppPassed:
		o = OutAppOK
	case AppFailed, AppRefused:
		o = OutAppFail // the server took the connection (or refused it) but failed the protocol
	case AppNoAnswer:
		o = OutTimeout // the handshake itself got no answer
	}
	if o != OutAppOK {
		f.appStage, f.appErr = r.Stage, r.Err
	}
	if r.Outcome.Connected() {
		// The real handshake is an E2E sample too: its RTT.
		p.txSeen, p.txIfOK, p.txRT = true, true, p.sentRT // the kernel sent it: no capture-side checks apply
		p.rxRT = p.sentRT.Add(r.ConnectRTT)
	}
	c.complete(p, o)
}

// appOwns: a packet of f's 4-tuple belongs to its real connection (an
// application check running or just finished): not a probe reply.
func (c *Core) appOwns(f *Flow) bool {
	return f.appUntil != 0 && c.now < f.appUntil
}
