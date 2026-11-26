package core

import (
	"fmt"
	"net/netip"
	"runtime"
	"testing"
	"time"

	"github.com/hotid/mpmtr/internal/wire"
)

// Synthetic performance benchmarks of the measurement core on the
// simulated network (no syscalls): they measure the core's own CPU cost,
// allocations and scheduler lag per simulated second. Network I/O cost is
// measured separately (see docs/TESTING.md, netns throughput run).
//
//	go test -run xxx -bench Core -benchtime 1x ./internal/core

func benchCore(b *testing.B, flows int, loss float64, discovery bool, simSecs int) {
	cfg := simpleCfg()
	cfg.PPS = float64(flows) * 3
	cfg.EndpointPPS = 1000
	cfg.MaxInflight = flows * 4
	p := linear(8, 20*time.Millisecond)
	p.loss = loss
	eps := flows / 16
	for i := 0; i < b.N; i++ {
		s := newSim(&testing.T{}, cfg, func(*Flow, Mono) *simPath { return p })
		s.c.cfg.Discovery = discovery
		s.c.cfg.ResponderPPS = 1e6
		var ps []wire.Port
		for k := 0; k < 256; k++ {
			ps = append(ps, wire.Port(20000+k))
		}
		for e := 0; e < eps; e++ {
			addr := netip.AddrFrom4([4]byte{198, 18, byte(e >> 8), byte(e)})
			if _, err := s.c.AddEndpoint(fmt.Sprintf("ep%d", e), addr, 443, ps); err != nil {
				b.Fatal(err)
			}
		}
		s.run(2 * time.Second) // warm up
		var m0, m1 runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&m0)
		sent0 := s.sent
		t0 := time.Now()
		s.run(time.Duration(simSecs) * time.Second)
		el := time.Since(t0)
		runtime.ReadMemStats(&m1)
		probes := float64(s.sent - sent0)
		b.ReportMetric(el.Seconds()/float64(simSecs)*1000, "cpu-ms/sim-s")
		b.ReportMetric(probes/float64(simSecs), "probes/sim-s")
		b.ReportMetric(float64(m1.Mallocs-m0.Mallocs)/probes, "allocs/probe")
		b.ReportMetric(float64(m1.HeapAlloc)/1e6, "heap-MB")
		b.ReportMetric(float64(s.c.M.LagMax)/1e6, "lag-max-ms(sim)")
		b.ReportMetric(float64(s.c.M.SchedSkips), "skips")
	}
}

func BenchmarkCore320(b *testing.B)           { benchCore(b, 320, 0, false, 10) }
func BenchmarkCore3200(b *testing.B)          { benchCore(b, 3200, 0, false, 10) }
func BenchmarkCore32000(b *testing.B)         { benchCore(b, 32000, 0, false, 5) }
func BenchmarkCore32000Storm(b *testing.B)    { benchCore(b, 32000, 1, false, 5) } // timeout storm
func BenchmarkCore3200Discovery(b *testing.B) { benchCore(b, 3200, 0, true, 20) }  // many RouteObservations

// Mass PathGroup recomputation: one endpoint with 256 observed flows on
// 64 branches.
func BenchmarkRegroup256(b *testing.B) {
	s, ep := groupingCore(&testing.T{})
	for i := 0; i < 256; i++ {
		obsFlow(s.c, ep, []string{"10.0.0.1", fmt.Sprintf("10.1.%d.1", i%64), fmt.Sprintf("10.2.%d.1", i%32), "10.3.0.1"}, 5)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.c.regroup(ep)
	}
}
