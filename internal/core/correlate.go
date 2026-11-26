package core

import (
	"time"

	"github.com/hotid/mpmtr/internal/wire"
)

// guard is the window during which completed probes still explain replies
// (late SYN/ACK retransmissions from a remote SYN_RECV, slow ICMP).
func (c *Core) guard() Mono {
	g := 3 * c.cfgDur(c.cfg.Timeout)
	if g < Mono(3*time.Second) {
		g = Mono(3 * time.Second)
	}
	return g
}

// OnPacket correlates one captured packet with probes.
func (c *Core) OnPacket(p *wire.Packet) {
	c.now, c.nowRT = c.clk.Now()
	switch p.Kind {
	case wire.KindTCP:
		if p.Outgoing {
			c.onOutgoingTCP(p)
		} else {
			c.onTCP(p)
		}
	case wire.KindICMP:
		if !p.Outgoing {
			c.onICMP(p)
		}
	}
}

func (c *Core) onOutgoingTCP(p *wire.Packet) {
	switch {
	case p.Flags&(wire.SYN|wire.ACK|wire.RST) == wire.SYN:
		pr := c.bySeq[p.Seq]
		if pr == nil {
			// Our port range, unknown seq: if it belongs to a flow with an
			// active probe, something rewrote the sequence number locally.
			if f := c.tuples[mkTuple(p.Src, p.SPort, p.Dst, p.DPort)]; f != nil && f.active != nil && !f.active.txSeen && !c.appOwns(f) {
				c.invalidate(f, InvalidSeqRewrite)
			}
			return
		}
		f := pr.flow
		if p.Dst != f.Tmpl.Dst || p.DPort != f.Tmpl.DPort {
			return // seq collision with foreign traffic
		}
		if p.Src != f.Tmpl.Src || p.SPort != f.Tmpl.SPort {
			// Local source NAT changed the flow identity.
			c.M.NATDetected++
			c.invalidate(f, InvalidLocalNAT)
		}
		if f.IfIndex == 0 || int(p.IfIndex) == f.IfIndex {
			pr.txIfOK = true
		}
		if !pr.txSeen {
			pr.txSeen = true
			if p.TSKernel {
				pr.txRT = Wall(p.TS)
			}
			if pr.completed && c.finalizable(pr) {
				c.finalize(pr)
			}
		}
	case p.Flags&wire.RST != 0:
		// Kernel RST answering a SYN/ACK: seq == our ISN+1.
		if pr := c.bySeq[p.Seq-1]; pr != nil && pr.flow.Tmpl.DPort == p.DPort {
			pr.rstSeen = true
			if pr.completed && c.finalizable(pr) {
				c.finalize(pr)
			}
		}
	}
}

func (c *Core) onTCP(p *wire.Packet) {
	f := c.tuples[mkTuple(p.Dst, p.DPort, p.Src, p.SPort)]
	if f == nil {
		c.M.Unmatched++
		return
	}
	if c.appOwns(f) {
		// The real connection of an application check owns the 4-tuple;
		// only a strict reply to one of our raw probes is still ours.
		if b := c.bySeq[p.Ack-1]; b == nil || b.flow != f || b.class == ClassApp || p.Flags&wire.ACK == 0 {
			return
		}
	}
	isSynAck := p.Flags&(wire.SYN|wire.ACK) == wire.SYN|wire.ACK && p.Flags&wire.RST == 0
	isRstAck := p.Flags&(wire.RST|wire.ACK) == wire.RST|wire.ACK
	ack := p.Ack
	if isSynAck || isRstAck {
		// Strict match against the active probe.
		if a := f.active; a != nil && ack == a.seq+1 {
			c.tcpReply(a, p, isSynAck, false)
			return
		}
		// A parallel discovery probe that reached the destination (this
		// port's path is shorter than the endpoint's known minimum).
		if b := c.bySeq[ack-1]; b != nil && b.burst && b.flow == f && !b.completed {
			c.tcpReply(b, p, isSynAck, false)
			return
		}
		// Guard window: late or duplicate replies to completed probes.
		explained := false
		c.forRecentOrPending(f, ack-1, func(r *probeRec) {
			replied := r.replied
			explained = true
			if replied {
				f.C.Duplicate++
				c.M.Duplicate++
				if isSynAck {
					// SYN/ACK retransmission: the remote did not get our RST.
					f.remoteUntil = c.now + c.guard()
				}
			} else {
				f.C.Late++
				c.M.Late++
			}
		})
		if explained {
			return
		}
		// Weak match: ACK does not fit, but the active probe is the only
		// probe that could explain this reply.
		if a := f.active; a != nil && !c.recentInGuard(f) {
			c.M.Weak++
			c.tcpReply(a, p, isSynAck, true)
			return
		}
		f.C.Unexpected++
		c.M.Unexpected++
		if a := f.active; a != nil {
			a.sawUnexpected = true
		}
		return
	}
	// RST without ACK, bare ACK (challenge ACK), anything else.
	if p.Flags&wire.ACK != 0 && p.Flags&(wire.SYN|wire.RST) == 0 {
		hit := false
		c.forRecentOrPending(f, ack-1, func(*probeRec) { hit = true })
		if hit {
			// RFC 5961 challenge ACK: the remote still holds state for an
			// earlier probe of this 4-tuple.
			f.C.ChallengeAck++
			c.M.ChallengeAck++
			f.remoteUntil = c.now + c.guard()
		}
	}
	f.C.Unexpected++
	c.M.Unexpected++
	if a := f.active; a != nil {
		a.sawUnexpected = true
	}
}

// forRecentOrPending calls fn for a completed (guard window) probe of f
// with the given seq.
func (c *Core) forRecentOrPending(f *Flow, seq uint32, fn func(r *probeRec)) {
	f.recentWithin(c.now, c.guard(), func(r *probeRec) bool {
		if r.seq == seq {
			fn(r)
			return false
		}
		return true
	})
}

func (c *Core) recentInGuard(f *Flow) bool {
	any := false
	f.recentWithin(c.now, c.guard(), func(r *probeRec) bool { any = true; return false })
	return any
}

func (c *Core) tcpReply(a *Probe, p *wire.Packet, synack, weak bool) {
	if !weak && p.TTL > 0 {
		// Path length hint from the reply's TTL (initial 64/128/255): the
		// reverse path, usually close to the forward one.
		base := 255
		switch {
		case p.TTL <= 64:
			base = 64
		case p.TTL <= 128:
			base = 128
		}
		// what is left of the reply's TTL says how many hops it crossed
		if d := TTL(base - int(p.TTL) + 1); d > 0 && (a.flow.EP.distHint == 0 || d < a.flow.EP.distHint) {
			a.flow.EP.distHint = d
		}
	}
	a.rxRT = Wall(p.TS)
	a.from = p.Src
	a.weakAck = weak
	if synack && !weak && p.HasTS {
		a.tsval, a.hasTS = p.TSval, true
	}
	a.gotSynAck = synack && !weak
	var o Outcome
	switch {
	case weak:
		o = OutWeak
		a.flow.C.Weak++
	case a.class != ClassE2E:
		o = OutDestReached
	case synack:
		o = OutSynAck
	default:
		o = OutRst
	}
	c.complete(a, o)
}

func (c *Core) onICMP(p *wire.Packet) {
	f := c.tuples[mkTuple(p.InnerSrc, p.InnerSPort, p.InnerDst, p.InnerDPort)]
	if f == nil {
		c.M.Unmatched++
		return
	}
	if c.appOwns(f) && (!p.HasInnerSeq || c.bySeq[p.InnerSeq] == nil) {
		return // about the real connection of an application check
	}
	a := f.active
	if p.HasInnerSeq {
		if a != nil && p.InnerSeq == a.seq {
			c.icmpReply(a, p, false)
			return
		}
		if b := c.bySeq[p.InnerSeq]; b != nil && b.burst && b.flow == f && !b.completed {
			c.icmpReply(b, p, false)
			return
		}
		explained := false
		c.forRecentOrPending(f, p.InnerSeq, func(r *probeRec) {
			explained = true
			if r.replied {
				f.C.Duplicate++
				c.M.Duplicate++
				c.alsoAnswered(f, r, p)
			} else {
				f.C.Late++
				c.M.Late++
			}
		})
		if explained {
			return
		}
	}
	// Fallback: the quote lacks or mismatches the seq. Accept only when the
	// full 4-tuple matches, exactly one probe can explain it, and an extra
	// identifier agrees (IPv4 IP ID — never sufficient on its own — or the
	// IPv6 flow label).
	if c.cfg.QuoteFallback && a != nil && !c.recentInGuard(f) {
		extra := false
		if p.InnerDst.Is4() {
			extra = p.InnerIPID == a.ipid
		} else {
			// The flow label is the same in every probe of the flow: it
			// confirms the flow, and the probe only when no parallel hop
			// probes of this flow are in flight.
			extra = p.InnerFlowLabel == f.Tmpl.FlowLabel && f.burst == 0
		}
		if extra {
			c.M.QuoteSeqMismatch++
			c.icmpReply(a, p, true)
			return
		}
	}
	f.C.Unexpected++
	c.M.Unexpected++
}

func (c *Core) icmpReply(a *Probe, p *wire.Packet, lowConf bool) {
	a.rxRT = Wall(p.TS)
	a.from = p.Src
	a.icmpType, a.icmpCode = p.ICMPType, p.ICMPCode
	a.lowConf = lowConf
	a.nmpls = p.NMPLS
	a.mpls = p.MPLS
	te := (!p.V6 && p.ICMPType == wire.ICMP4TimeExceed) || (p.V6 && p.ICMPType == wire.ICMP6TimeExceed)
	var o Outcome
	switch {
	case a.class == ClassE2E:
		o = OutICMPUnreach // includes time exceeded on an E2E probe (loop/too long)
	case te:
		o = OutTimeExceeded
	default:
		o = OutICMPUnreach
	}
	c.complete(a, o)
}

func (c *Core) invalidate(f *Flow, r InvalidReason) {
	if f.invalid == ValidFlow {
		f.invalid = r
		c.ev.flowInvalid(f)
	}
}
