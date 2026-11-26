package core

import "github.com/hotid/mpmtr/internal/wire"

// Focus: one port traced in full every interval.
//
// Normally the hops of every measured port are refreshed one TTL at a time,
// one probe per interval, so a hop of a path of N routers gets a fresh
// number every N intervals. With a port in focus all its TTLs are probed
// together every interval, and the hop refresh of the other ports pauses
// (their TCP measurements go on unchanged; their hop rows turn stale).

// SetFocus puts the port sport of endpoint ep in focus (sport 0: nobody).
// It reports whether the focus is on a port now.
func (c *Core) SetFocus(ep EndpointID, sport wire.Port) bool {
	c.focus = nil
	if sport == 0 || ep < 0 || ep >= EndpointID(len(c.eps)) {
		return false
	}
	f := c.eps[ep].byPort[sport]
	if f == nil || f.invalid != ValidFlow {
		return false
	}
	c.focus = f
	f.focusAt = 0
	c.enqueue(f)
	return true
}

// focusSweep starts the next full trace of the focused port when it is due
// and ends the one whose TTLs have all been probed. wait > 0: not due yet.
func (c *Core) focusSweep(f *Flow) (wait Mono) {
	if sw := f.sw; sw != nil {
		if sw.focus && sw.burstDone && sw.ttl > sw.limit {
			f.sw = nil // the routers are done; the destination has its own probes
		} else {
			return 0
		}
	}
	iv := c.cfgDur(c.cfg.Interval)
	if f.focusAt != 0 && c.now-f.focusAt < iv {
		return f.focusAt + iv - c.now
	}
	f.focusAt = c.now
	limit := c.cfg.MaxTTL
	if d := f.route.distance; d > 1 {
		limit = d - 1
	}
	f.sw = &sweep{class: ClassRefresh, pass: 1, passes: 1, ttl: 1, limit: limit, focus: true}
	return 0
}
