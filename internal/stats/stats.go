// Package stats holds the small, allocation-free statistical primitives used
// by the measurement core: Wilson score intervals, order statistics on small
// samples, RTT summaries and token buckets.
package stats

import (
	"math"
	"slices"
)

// Wilson returns the 95% Wilson score interval for k successes out of n.
// For n == 0 it returns (0, 1) — i.e. "anything is possible"; callers must
// treat n == 0 as UNKNOWN rather than reading the bounds.
//
// The interval assumes independent Bernoulli trials. Packet loss is often
// bursty/correlated, so the interval is optimistic in that case; it is used
// as a conservative onset criterion only, never as a recovery criterion.
func Wilson(k, n int64) (lo, hi float64) { return WilsonF(float64(k), float64(n)) }

// WilsonF is Wilson for non-integer counts (exponentially decayed sums).
func WilsonF(k, n float64) (lo, hi float64) {
	if n <= 0 {
		return 0, 1
	}
	const z = 1.959963984540054
	p := k / n
	nf := n
	den := 1 + z*z/nf
	c := p + z*z/(2*nf)
	h := z * math.Sqrt(p*(1-p)/nf+z*z/(4*nf*nf))
	lo = (c - h) / den
	hi = (c + h) / den
	if lo < 0 {
		lo = 0
	}
	if hi > 1 {
		hi = 1
	}
	// Exact endpoints for degenerate samples.
	if k == 0 {
		lo = 0
	}
	if k == n {
		hi = 1
	}
	return lo, hi
}

// Rate returns k/n and ok=false when n == 0 (UNKNOWN, never 0% or 100%).
func Rate(k, n int64) (float64, bool) {
	if n <= 0 {
		return 0, false
	}
	return float64(k) / float64(n), true
}

// Quantile returns the q-quantile (0..1) of v using linear interpolation
// between closest ranks. v is sorted in place. Returns 0 for empty v.
func Quantile(v []uint32, q float64) uint32 {
	if len(v) == 0 {
		return 0
	}
	slices.Sort(v)
	return quantileSorted(v, q)
}

func quantileSorted(v []uint32, q float64) uint32 {
	if q <= 0 {
		return v[0]
	}
	if q >= 1 {
		return v[len(v)-1]
	}
	pos := q * float64(len(v)-1)
	i := int(pos)
	f := pos - float64(i)
	if i+1 >= len(v) {
		return v[i]
	}
	return uint32(float64(v[i])*(1-f) + float64(v[i+1])*f + 0.5)
}

// Median of v (sorted in place).
func Median(v []uint32) uint32 { return Quantile(v, 0.5) }

// Summary describes a set of RTT samples in microseconds.
type Summary struct {
	N                          int
	Min, Median, P95, P99, Max uint32
	Mean                       float64
	HasP99                     bool
}

// Summarize computes a Summary over v (sorted in place). P99 is reported
// only with at least 100 samples.
func Summarize(v []uint32) Summary {
	s := Summary{N: len(v)}
	if len(v) == 0 {
		return s
	}
	slices.Sort(v)
	var sum float64
	for _, x := range v {
		sum += float64(x)
	}
	s.Mean = sum / float64(len(v))
	s.Min, s.Max = v[0], v[len(v)-1]
	s.Median = quantileSorted(v, 0.5)
	s.P95 = quantileSorted(v, 0.95)
	if len(v) >= 100 {
		s.P99 = quantileSorted(v, 0.99)
		s.HasP99 = true
	}
	return s
}

// Jitter is the RFC 3550 interarrival-jitter style smoothed mean absolute
// difference between consecutive RTT samples (microseconds).
type Jitter struct {
	last float64
	J    float64
	n    int
}

// Add records a sample.
func (j *Jitter) Add(us uint32) {
	x := float64(us)
	if j.n > 0 {
		d := math.Abs(x - j.last)
		j.J += (d - j.J) / 16
	}
	j.last = x
	j.n++
}

// Valid reports whether at least two samples were seen.
func (j *Jitter) Valid() bool { return j.n >= 2 }

// Ring is a fixed-size ring of samples.
type Ring[T any] struct {
	buf  []T
	next int
	full bool
}

// NewRing creates a ring with capacity n.
func NewRing[T any](n int) Ring[T] { return Ring[T]{buf: make([]T, n)} }

// Add appends a value, overwriting the oldest one when full.
func (r *Ring[T]) Add(v T) {
	if len(r.buf) == 0 {
		return
	}
	r.buf[r.next] = v
	r.next++
	if r.next == len(r.buf) {
		r.next = 0
		r.full = true
	}
}

// Len returns the number of stored values.
func (r *Ring[T]) Len() int {
	if r.full {
		return len(r.buf)
	}
	return r.next
}

// Do calls f on stored values from oldest to newest.
func (r *Ring[T]) Do(f func(T)) {
	if r.full {
		for _, v := range r.buf[r.next:] {
			f(v)
		}
	}
	for _, v := range r.buf[:r.next] {
		f(v)
	}
}

// Last returns the newest value.
func (r *Ring[T]) Last() (T, bool) {
	var z T
	if r.Len() == 0 {
		return z, false
	}
	i := r.next - 1
	if i < 0 {
		i = len(r.buf) - 1
	}
	return r.buf[i], true
}

// Reset empties the ring.
func (r *Ring[T]) Reset() { r.next, r.full = 0, false }

// TokenBucket is a classic token bucket on an int64 nanosecond clock.
type TokenBucket struct {
	Rate   float64 // tokens per second; <= 0 means unlimited
	Burst  float64
	tokens float64
	last   int64
	init   bool
}

// NewTokenBucket returns a full bucket.
func NewTokenBucket(rate, burst float64) TokenBucket {
	if burst < 1 {
		burst = 1
	}
	return TokenBucket{Rate: rate, Burst: burst}
}

func (b *TokenBucket) refill(now int64) {
	if !b.init {
		b.tokens, b.last, b.init = b.Burst, now, true
		return
	}
	if now > b.last {
		b.tokens += float64(now-b.last) * b.Rate / 1e9
		if b.tokens > b.Burst {
			b.tokens = b.Burst
		}
		b.last = now
	}
}

// Available reports whether one token can be taken at now.
func (b *TokenBucket) Available(now int64) bool {
	if b.Rate <= 0 {
		return true
	}
	b.refill(now)
	return b.tokens >= 1
}

// Take consumes one token; returns false if none is available.
func (b *TokenBucket) Take(now int64) bool {
	if b.Rate <= 0 {
		return true
	}
	b.refill(now)
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// NextAt returns the time at which one token will be available.
func (b *TokenBucket) NextAt(now int64) int64 {
	if b.Rate <= 0 {
		return now
	}
	b.refill(now)
	if b.tokens >= 1 {
		return now
	}
	return now + int64((1-b.tokens)*1e9/b.Rate) + 1
}

// Tokens returns the current token count (refilled to now).
func (b *TokenBucket) Tokens(now int64) float64 {
	if b.Rate <= 0 {
		return b.Burst + 1e9
	}
	b.refill(now)
	return b.tokens
}

// Level compares the newest samples of v (oldest first) with the ones
// before them. shift: the median of the last `recent` samples stands above
// the median of the earlier ones by more than five times their spread.
// spike: only the last sample does. The spread is the median absolute
// deviation scaled to a standard deviation, and never taken smaller than
// 5 % of the earlier median or 50 µs, so that a very steady series does
// not turn every flicker into an anomaly. ok is false with fewer than
// 3·recent samples: too little history to say.
func Level(v []uint32, recent int) (shift, spike, ok bool) {
	if recent < 1 || len(v) < 3*recent {
		return false, false, false
	}
	base := slices.Clone(v[:len(v)-recent])
	slices.Sort(base)
	bm := float64(quantileSorted(base, 0.5))
	dev := make([]uint32, len(base))
	for i, x := range base {
		dev[i] = uint32(math.Abs(float64(x) - bm))
	}
	slices.Sort(dev)
	spread := max(1.4826*float64(quantileSorted(dev, 0.5)), 0.05*bm, 50)
	last := slices.Clone(v[len(v)-recent:])
	slices.Sort(last)
	shift = float64(quantileSorted(last, 0.5))-bm > 5*spread
	spike = !shift && float64(v[len(v)-1])-bm > 5*spread
	return shift, spike, true
}
