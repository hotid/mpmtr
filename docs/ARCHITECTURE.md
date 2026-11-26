# Scheduler, source ports and routing

[Русская версия](ARCHITECTURE.ru.md) · [README](../README.md)

How probes are scheduled and limited, how source ports are chosen and reserved, and how the local route of each flow is found.

## Scheduler and rate limits

One central scheduler (no goroutine or ticker per flow) with a timer heap and
bounded queues. E2E slots are deterministic per flow (hashed phase, ±5 %
jitter). Overdue slots are `skipped`, never caught up in a burst. When the
previous probe ends within the jitter budget, the slot waits for it instead
of skipping.

Classes: E2E > incident trace > topology refresh > discovery, with deficit
round robin among the hop classes and a 10 % PPS reserve so they never
starve.

**Limits**:

* **`--pps`** — global (E2E may use 90 %).
* **`--endpoint-pps`** — hop probes get the share left after the E2E demand
  of the ports measured now, at least 10 %.
* **`--max-inflight`**.
* **per-flow serialization** — one active probe per 4-tuple across all
  classes. The one exception is discovery: TTLs below the shortest path
  length known so far are probed together and do not take the flow's slot;
  their ICMP replies are matched by the quoted sequence number. When the
  port's own path is shorter and some of them reach the destination, see
  [DISCOVERY.md](DISCOVERY.md).
* **`--responder-pps`** (default 100/s) — how many hop probes a second one
  router gets. The limit is shared by all the endpoints measured: routers
  limit the rate of their ICMP answers themselves, and probes above it would
  go unanswered. A hop whose router has not answered yet is counted by its
  place: interface, gateway, TTL and previous hop.

  The limit keeps mpmtr's own probes down; it does not promise answers. A
  router's limit is not known, may be lower, and is shared with everybody
  else who probes it. A hop that looks limited is flagged `icmp-limit?`.

A hop probe is sent only when it can finish before the flow's next E2E slot.
Otherwise it is deferred and the hop goes `stale`, never shown as 100 % loss.

When E2E takes the whole interval (a failing flow), incident traces
explicitly take every third slot (`yield_incident`), and a DOWN flow gives
every second slot to its hop probes (`yield_trace`, as many as fit the
slot), so the route of a failing flow stays fresh.

Shared prefixes of confirmed routes are refreshed by fewer flows
(deduplication is a budget optimisation only; no measurement is copied
between flows).

## Source ports

Ports come from `--sport-range` (default 20000–20255, outside the usual
ephemeral range) and are used **in order**, or from `--src-ports`. A run
with the same range, on a host where none of its ports is taken, uses the
same ports as the run before, and so the same paths for as long as the
routing and the routers' hashing stay as they are. A port that is taken is
skipped, and a second mpmtr running at the same time moves to the next free
block (below): the ports then differ, and the report names the ones used.
Before the first probe:

1. Ports already used by other local TCP sockets (except TIME_WAIT) are
   skipped — silently for the range, with one note for `--src-ports`; the
   next free ports are used. Startup fails only when (almost) no port is free.
   Overlap with `ip_local_port_range` is fine thanks to step 2.
2. Every used (src IP, port) is reserved with a TCP socket that is **bound but
   not listening**. Integration-tested for IPv4 and IPv6: the kernel no longer
   hands the port to `connect()`, a `SO_REUSEADDR` bind cannot take it, and
   incoming SYN/ACKs still get the kernel's RST.
3. Instances: bound-only sockets are invisible in `/proc/net/tcp`, so each
   instance also claims its port block with an abstract unix socket
   (`@mpmtr/ports16/N` for every 16 ports, per network namespace, released on
   exit).
   * With the default range, a second instance moves to the next free block
     (20256–20511, …) and says so.
   * With an explicit range it stops with the PID of the holder.

sysctls are never changed.

## Routing and local ECMP

The source address and egress are looked up per flow over rtnetlink
(`RTM_GETROUTE` with protocol TCP, source and destination ports, TOS, fwmark,
source and output interface where given), not by a UDP connect.

Raw `IP_HDRINCL` packets are routed by destination only, so with a local
multipath route raw SYNs could pin to one nexthop although real TCP sockets
would spread. mpmtr therefore sends every flow with `IP_PKTINFO` on the
interface from its own port-aware lookup and checks the captured egress
interface of every probe.

* **Verified** (integration test `TestLocalECMP`, kernel 7.3.4): a local
  multipath default route over two interfaces with L4 hash. Flows spread over
  both links and each flow's SYNs appear only on its own link.
* **Not supported**: nexthops that share one interface (different gateways on
  one link) cannot be selected this way. mpmtr warns: "local multipath
  detected …: raw SYN may pin to a single nexthop; observed ECMP branching
  may be absent or incomplete".

Route, address and link changes (rtnetlink notifications) trigger a fresh
lookup. A flow whose source, interface or gateway changed is retired
(`local_route_changed`) with its statistics, and a new flow takes over the
port. Measurements before and after the change are never mixed.
