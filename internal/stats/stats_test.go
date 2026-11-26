package stats

import (
	"math"
	"testing"
)

func near(a, b, eps float64) bool { return math.Abs(a-b) < eps }

func TestWilson(t *testing.T) {
	// Reference values (Wilson 95%): k=0,n=30 → hi≈0.1135; k=3,n=100 → (0.0103,0.0845)
	lo, hi := Wilson(0, 30)
	if lo != 0 || !near(hi, 0.1135, 0.001) {
		t.Fatal(lo, hi)
	}
	lo, hi = Wilson(3, 100)
	if !near(lo, 0.0103, 0.001) || !near(hi, 0.0845, 0.001) {
		t.Fatal(lo, hi)
	}
	lo, hi = Wilson(10, 10)
	if hi != 1 || !near(lo, 0.7225, 0.001) {
		t.Fatal(lo, hi)
	}
	if lo, hi := Wilson(0, 0); lo != 0 || hi != 1 {
		t.Fatal("n=0")
	}
	if _, ok := Rate(0, 0); ok {
		t.Fatal("rate with n=0 must be unknown")
	}
}

func TestQuantiles(t *testing.T) {
	v := []uint32{5, 1, 4, 2, 3}
	if Median(v) != 3 {
		t.Fatal("median")
	}
	s := Summarize([]uint32{10, 20, 30, 40})
	if s.Min != 10 || s.Max != 40 || s.Median != 25 || s.Mean != 25 || s.HasP99 {
		t.Fatalf("%+v", s)
	}
	big := make([]uint32, 200)
	for i := range big {
		big[i] = uint32(i + 1)
	}
	s = Summarize(big)
	if !s.HasP99 || s.P95 < 189 || s.P95 > 191 || s.P99 < 197 {
		t.Fatalf("%+v", s)
	}
	if Summarize(nil).N != 0 {
		t.Fatal("empty")
	}
}

func TestJitter(t *testing.T) {
	var j Jitter
	j.Add(1000)
	if j.Valid() {
		t.Fatal("one sample")
	}
	for i := 0; i < 200; i++ {
		if i%2 == 0 {
			j.Add(1000)
		} else {
			j.Add(3000)
		}
	}
	if !near(j.J, 2000, 50) {
		t.Fatal(j.J)
	}
}

func TestRing(t *testing.T) {
	r := NewRing[int](3)
	for i := 1; i <= 5; i++ {
		r.Add(i)
	}
	var got []int
	r.Do(func(v int) { got = append(got, v) })
	if len(got) != 3 || got[0] != 3 || got[2] != 5 {
		t.Fatal(got)
	}
	if l, _ := r.Last(); l != 5 {
		t.Fatal(l)
	}
}

func TestTokenBucket(t *testing.T) {
	b := NewTokenBucket(2, 2)
	now := int64(0)
	if !b.Take(now) || !b.Take(now) || b.Take(now) {
		t.Fatal("burst")
	}
	if at := b.NextAt(now); at < 4.9e8 || at > 5.1e8 {
		t.Fatal(at)
	}
	now += 5e8
	if !b.Take(now) || b.Take(now) {
		t.Fatal("refill")
	}
	// No accumulation beyond burst after a long idle period: no catch-up burst.
	now += 100e9
	n := 0
	for b.Take(now) {
		n++
	}
	if n != 2 {
		t.Fatal("burst after idle", n)
	}
}
