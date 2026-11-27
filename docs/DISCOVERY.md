# Route discovery and localization

[Русская версия](DISCOVERY.ru.md) · [README](../README.md)

How routes are found and grouped, what happens when they change, and how a failure is narrowed down to a segment.

## Discovery, routes and PathGroups

Discovery runs alongside E2E monitoring as a pipeline: up to 32 ports are
traced at a time, and every finished port immediately updates the routes
and the stop rule and is replaced by the next port of the range (at most
the whole `--sport-range`, 256 ports by default).

A trace is one pass. Once a path length is known — the shortest one of the
ports traced so far, or an estimate from the TTL of the destination's reply
to the first SYN (minus a 2-hop margin) — all TTLs below it are probed **in
parallel** (replies are matched by the quoted sequence number), in rounds
until each TTL answered or ran out of tries: 2 tries, 1 for a TTL that
nobody ever answered at. The destination TTL is then probed serially.

Routes may differ in length, so the port being traced may have a shorter
path than every port before it. Several SYNs of one round then reach the
destination together; it answers some and resets others, in any order. The
port's length is the lowest TTL the destination answered at, and that TTL is
probed once more on its own.

The destination's answer to a TTL-limited SYN sets the distance (strict
correlation). Once the first trace of a route is over, a *shorter* distance
needs two answers (route change).

With `--shared-hops`, ports also skip the first TTLs once ≥ 8 ports saw the
same single router there (every 8th port still traces them).

The time discovery takes is set by `--endpoint-pps` and by the hops that
never answer: each costs its tries times `--hop-timeout`.

A hop is:

* **known** — after one reply when it is the only responder seen there (the
  quote proves it answered our SYN);
* **silent** — when unanswered;
* **unstable** — with several recurring responders.

A TTL where every answering port saw the same single router (≥ 3 ports)
counts as that router for ports whose probe there was not answered (ICMP
rate limiting); a TTL nobody ever answered at is silent for everyone and
does not make a trace incomplete.

This is an assumption, not an observation: a port that got no answer may
pass another router there, one that does not answer. Without the assumption
the port would be on the same route all the same (an unanswered hop matches
any router), only as an incomplete trace. So the assumption never joins
routes that would otherwise stay apart. What it changes is the level
(`confirmed` instead of `tentative`), and it is marked: the port's
`assumed_hops` in JSON lists such TTLs, the port's own hop rows still show
that nothing answered, and when such a port fails the localization says so
in its limitations.

**Routes** are clusters of compatible traces: `*`/unanswered matches any
router, but the number of hops must match; a router mismatch at one TTL (or
different lengths) proves two routes different. Traces are taken best-first
(complete, then most known hops). A trace:

* joins the one route it fits and fills that route's unknown hops;
* founds a new route only when proven different from every route;
* when it fits several it waits (`ambiguous`, shown as "not yet assigned …
  fits B or D" for measured ports; a port left half-traced when discovery
  stopped is not probed again and not listed) and is re-checked until
  nothing changes.

Grouping is a pure function of the observations (order-independent, tested).

Levels:

* **`confirmed`** — a complete trace (complete as observed: the name does
  not say the physical path is the only one behind it);
* **`partial_distinct`** — incomplete but different from all others;
* **`tentative`** — an incomplete trace on a confirmed route;
* **`ambiguous`** — an incomplete trace that fits several routes;
* **`unresolved`** — not traced far enough to say.

**Stop reasons** (JSON `reason`; the screen says them in words):

* **`stability_limit`** — no new route among the last max(32, 8 × routes)
  explored ports and no resolvable ambiguity. With k equally likely routes
  the chance that a given one of them got none of those ports is about
  (1−1/k)^(8k) ≈ 0.03 %; a route that gets a smaller share of the ports than
  the others is missed more easily: one that gets 1/64 of them next to 11
  equal routes is missed about 15 % of the time. The rule cannot tell such a
  route is there, and no estimate from the routes found can either: a route
  that no port reached leaves no trace in them. A wider `--sport-range`
  helps only where discovery runs out of ports before the rule stops it
  (`budget_exhausted`).
* **`max_flows`**.
* **`budget_exhausted`** — no more ports.
* **`deadline`**.
* **`insufficient_data`**.

None of them means all physical paths were found: LAG, MPLS, tunnels and
per-packet balancing stay invisible, and one signature does not prove one
physical path.

**Measured set**:

* The first port is measured from the start.
* Every route that discovery proves distinct (`confirmed` or
  `partial_distinct`) gets `--flows` (default 1) of its own ports measured,
  lowest port first, as soon as it is found.
* A measured port is **never swapped for another**: if its path changes it
  keeps being measured on its new route (`ROUTE_CHANGED`).
* Only when two routes turn out to be one, the ports above `--flows` stop
  being measured (listed as stopped flows).
* With `--no-discovery` the first `--flows` ports are measured.

One port per route answers "which route fails". With `--flows 2` or more,
ports of one route that disagree show that the cause is below the visible
route (a LAG member, state on a middlebox). Ports that agree do not prove
the opposite: all of them may sit on the same faulty member.

Route changes need two consecutive agreeing new responders at a TTL (or a
re-confirmed distance). The old route version is archived with its own E2E
statistics (JSON `route_history` of the flow; the single-flow view lists the
earlier versions).

A responder that changes for the third time in 5 minutes is flapping: the
hop is marked unstable instead of starting one more version.
`ROUTE_CHANGED` is never loss.

A confirmed new responder also means the topology moved there: every port
that is only traced (not measured, so never refreshed) and still shows the
old responder at that TTL is traced again from scratch (`retraced` in the
measurer metrics). Otherwise an upstream switch would leave routes that no
longer exist, and a trace cut by the switch would mix both paths into one.

A topology that keeps moving cannot make this endless: a port is traced
again at most once a minute, the traces go through the same rate limits as
all hop probes, and a hop whose responder keeps changing becomes unstable
and starts no further versions.

## Localization

Failing groups B and healthy groups G (all monitored members failing or
healthy):

`candidates = ∩ segments(B) − ∪ segments(G)`

Segments are links between consecutive known responders (wildcards break
them). All remaining candidates are listed, none is picked arbitrarily.

Levels:

* **`CONFIRMED_FLOW_FAILURE`**;
* **`CORRELATED_PATH_FAILURE`** — all routes fail; no healthy control, so no
  segment is named;
* **`SUSPECTED_SEGMENT`**;
* **`FORWARD_PATH_NOT_DISTINGUISHED`** — failing and healthy flows share the
  same visible route;
* **`ROUTE_AMBIGUITY`**;
* **`INCONCLUSIVE`**;
* **`APPLICATION_FAILURE`** — TCP answers on every failing port and only
  the application checks (`--app`) fail. The SYN probes found nothing wrong
  on the path, so no segment is named. That does not clear the network: a
  path may pass a SYN and still drop what follows (larger packets, a
  filtered protocol). Where the cause is stays open. For the SYN probes a
  port in that state is a healthy control when other ports fail at TCP.

Hop loss analysis reports `suspected_loss_start_ttl` only when elevated
apparent loss on an answering hop persists on every later answering hop
(and says so when the later hops gave no data either way); a hop whose
loss a later hop significantly does not have is `icmp-limit?`, and is not
where loss starts. A hop that never answers neither starts loss nor
confirms it: a router may simply not answer ICMP. The exception is a port
that is DOWN with no answer at all from some TTL on, the destination
included: the loss is reported to start there.

Every result lists supporting and contradicting observations and its
limitations. No numeric confidence is invented.

An incident (flows failing or degrading) triggers up to 5 rounds of TTL
sweeps on the failing flows and up to 3 healthy controls (same route first)
at elevated priority.
