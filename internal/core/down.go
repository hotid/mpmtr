package core

import (
	"math"
	"time"

	"github.com/hotid/mpmtr/internal/stats"
)

// A run of consecutive failures means DOWN only when it is improbable under
// the flow's own background loss. On a path that loses 10–30% of its probes
// independently, five failures in a row happen several times a day per
// flow; a fixed threshold of 5 would call each of them an outage and,
// through the recovery epoch, also wipe the flow's LOSS evidence. So the
// threshold k is the shortest run whose chance
// under the background is at most downRunAlpha: P(run reaches k | it
// started) = q^(k-1), q = P(fail | previous valid outcome failed), taken at
// its 95% upper bound. A clean flow keeps DownAfter (5); with no history yet
// (right after start) it is DownAfter too, so a dead target is DOWN after
// five probes.

const (
	downRunAlpha = 1e-5             // chance that a run which began under the background reaches k
	downBGHalf   = 30 * time.Minute // half-life of the background statistics
	downMinBG    = 10               // failures needed to estimate q itself (else q = loss rate)
)

// downBG is the flow's background loss: exponentially decayed counts of
// valid outcomes outside DOWN periods. A failure run is added when it ends
// without becoming DOWN; a run that became DOWN and the DOWN period itself
// are not background.
type downBG struct {
	n, fails, ff float64 // valid outcomes, failures, failures followed by a failure
	at           Mono
	run          int // failures of the current run not yet added
}

func (b *downBG) decay(now Mono) {
	if b.at != 0 && now > b.at {
		f := math.Exp2(-float64(now-b.at) / float64(downBGHalf))
		b.n, b.fails, b.ff = b.n*f, b.fails*f, b.ff*f
	}
	b.at = now
}

// endRun adds the pending run of r failures, each but the last followed by
// a failure.
func (b *downBG) endRun() {
	if r := float64(b.run); r > 0 {
		b.n += r
		b.fails += r
		b.ff += r - 1
	}
	b.run = 0
}

// q is the background chance that a failure follows a failure (95% upper
// bound) and ok=false while there is too little history to judge.
func (b *downBG) q(minValid int) (q float64, ok bool) {
	if b.n < float64(minValid) {
		return 0, false
	}
	_, p := stats.WilsonF(b.fails, b.n)
	if b.fails < downMinBG {
		return p, true
	}
	_, q = stats.WilsonF(b.ff, b.fails)
	return q, true
}

// downNeed is the number of consecutive failures that make the flow DOWN.
func (c *Core) downNeed(f *Flow) int {
	base := c.cfg.DownAfter
	q, ok := f.sm.bg.q(c.cfg.LossMinValid)
	if !ok || q <= 0 {
		return base
	}
	limit := 4 * base
	if q >= 1 {
		return limit
	}
	k := 1 + int(math.Ceil(math.Log(downRunAlpha)/math.Log(q)))
	return min(max(k, base), limit)
}

// rates are the point estimates of the background loss and of P(fail |
// previous fail), for display (0 while unknown).
func (b *downBG) rates() (p, q float64) {
	if b.n > 0 {
		p = b.fails / b.n
	}
	if b.fails > 0 {
		q = b.ff / b.fails
	}
	return p, q
}
