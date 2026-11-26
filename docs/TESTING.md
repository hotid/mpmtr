# Tests and performance

[Русская версия](TESTING.ru.md) · [README](../README.md)

What the tests cover, how to run them, and benchmark figures.

## Tests

```bash
make test           # unit + deterministic scenario tests (simulated network, virtual clock)
make race           # same with -race
make vet            # go vet and gofmt
make integration    # root: network namespaces, veth, ECMP, tc netem (≈20 min)
make bench          # synthetic core benchmarks
make man-check      # the man pages render without warnings
```

The core has no I/O: probes go out through a `Transport`, packets and
capture watermarks come in through methods, time through a `Clock`. The
simulated network in `internal/core/sim_test.go` (per-flow paths, per-hop
ICMP loss, transit loss, RTT, unreachable, missing RST, capture drops) runs
the scenarios and the invariants in milliseconds:

* one dead flow of 16,
* zero valid probes,
* fast DOWN,
* 12 DOWN + 4 UNKNOWN,
* recovery epochs,
* absolute and relative RTT degradation,
* hidden-hop branches,
* wildcard non-transitivity,
* capture drops,
* late SYN/ACK,
* event deduplication (one main event for a group, recovery never
  suppressed),
* hop deferral under a saturated E2E schedule,
* all discovery stop reasons,
* localization with and without controls,
* route changes,
* ICMP rate limiting,
* weak/duplicate/late/quote-fallback matching,
* local NAT,
* untransmitted SYNs,
* scheduler starvation,
* hop budget starvation,
* LOSS recovery reachability,
* statistics reset,
* monotonic ISNs,
* routes of different lengths traced with parallel TTLs,
* hops taken from other ports are marked as assumed,
* an outage on a flow with background loss is DOWN at the threshold the
  background gave before it began,
* the server census: equal and light servers, clocks that cannot be told
  apart, a server that dies after the census, one that leaves the pool, a
  made-up server, a real server with one foreign port,
* application checks: counted apart from TCP, a dead and a flaky
  application, TCP and the application recovering each on its own,
* an application plugin that never answers is stopped.

Integration tests (`integration/`, build tag `integration`) use the topology
in `integration/topo.sh`: `src ═ R0 ═ ECMP R1..R4 ═ RD ─ dst`, L4-hash
multipath both ways, IPv4+IPv6. Before discovery is checked, tcpdump on the
four arms confirms that the source ports really spread over the arms. The
tests cover:

* one-arm loss,
* loss on the common segment,
* one-arm and common RTT increase (baseline),
* destination down,
* routers silent to ICMP,
* ICMP rate limiting,
* route change in a live run,
* local SNAT,
* port conflict,
* capture drops (a tiny ring under load),
* wrong ACK from a middlebox,
* late SYN/ACK,
* IPv6 raw SYN with flow label/traffic class on the wire,
* bound-only reservation and kernel RST (IPv4/IPv6),
* kernel TX/RX timestamps against netem delay,
* discover mode,
* local ECMP,
* a conntrack middlebox on the path,
* one arm three routers longer than the others,
* an application that answers nonsense while TCP answers,
* hop-information plugins.

Not covered by a test: a server added to the balancer's pool after the
census (it is not looked for, see [ANYCAST.md](ANYCAST.md)), a server whose
clock offset changes while it stays the same machine, and a path that
passes the SYN but drops the data of the application check (the check then
fails like any other; nothing tells the two apart).

They need root and network namespaces, so CI runs the unit and scenario
tests only; without root `make integration` fails instead of skipping.

## Performance

Synthetic core benchmarks (`make bench`, no syscalls, includes the cost of the
simulator itself; i7, 8 threads, Go 1.26):

| flows | probes/s (sim) | core CPU per second | allocs/probe | heap |
|---:|---:|---:|---:|---:|
| 320 | 320 | 1.7 ms | 14.5 | 2.4 MB |
| 3 200 | 3 200 | 17.6 ms | 14.5 | 15 MB |
| 32 000 | 32 000 | 143 ms | 14.0 | 198 MB |
| 32 000, timeout storm | 31 900 | 84 ms | 8.0 | 154 MB |
| 3 200 + discovery | 5 760 | 35 ms | 11.9 | 80 MB |

Regrouping 256 observed flows on 64 routes takes 0.35 ms. The simulator steps
in 10 ms, so its scheduler-lag figure is the step size and is not reported.

Real sockets, netns fabric on the same 8-thread laptop
(`integration/bench_throughput.sh EPS FLOWS COUNT`, E2E only, 1 probe/s per
flow; the routers, the destination kernel answering every SYN and our kernel
sending every RST all share the same CPU):

| flows | E2E probes | matched SYN/ACK | timeouts | capture drops | skipped slots | sched lag avg / max | CPU (user+sys) | max RSS |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 3 200 (25×128) | 128 000 in 40 s | 128 000 | 0 | 0 | 47 (0.04 %) | 0.47 / 41 ms | 8.0 s / 40 s (20 % of a core) | 108 MB |
| 32 000 (125×256) | 640 000 in 21 s (≈30 000/s) | 640 000 | 0 | 0 | 3 646 (0.6 %, global PPS budget at start-up) | 0.80 / 135 ms | 16.9 s / 21.8 s (78 % of a core, ⅔ in syscalls) | 612 MB |

32 000 flows are measured in this setup with no measurement loss.
The bottleneck is the per-packet `sendmsg` and ring processing in the kernel
(system time), followed by memory: ~6 KB of core state per flow, plus the
final JSON snapshot of all flows in report mode.

Discovery and hop probing add hop state per (flow, TTL); at 32 000 flows
they are limited by the per-responder budget, not by CPU. These figures come
from one machine and a virtual fabric; they are not a guarantee for other
hardware.
