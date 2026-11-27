<!-- Generated from man/mpmtr.1 by "make man-md": edit the man page, not this file. -->

[Русская версия](mpmtr.ru.md)

# NAME

mpmtr - multipath TCP MTR: trace and measure every ECMP route to a TCP
endpoint

# SYNOPSIS

**mpmtr** \[*options*\] *target*\[:*port*\] \[*target*\[:*port*\]...\]

**mpmtr -r** \[**-c** *N*\] \[**--json**\] \[*options*\] *target*...

**mpmtr --discover** \[**--json**\] \[*options*\] *target*...

# DESCRIPTION

**mpmtr** is a console tool in the spirit of **mtr**(8) for networks
with ECMP or other per-flow load balancing. Routers that balance per
connection hash the addresses and ports of a packet, so different TCP
source ports take different routes. **mpmtr** sends TCP SYN probes from
many source ports and, for every route it finds, measures both the
route's hops (like **mtr**) and the end-to-end TCP result (SYN answered
by SYN/ACK or RST).

A source port that is measured continuously is a *flow*, named F1, F2,
... in probing order. All probes of a flow carry exactly the same header
identity except TTL, IPv4 IP ID, TCP sequence number and checksums
(Paris-traceroute style), so a flow stays on one route.

What it does, in order:

1.  **Discovery.** Source ports are traced in order (20000, 20001, ...)
    with TTL-limited SYNs, up to 32 at a time, until new ports keep
    landing on routes already known: no new route among the last max(32,
    8 × routes) ports traced. With k equally likely routes the chance
    that a given one of them got none of those ports is about
    (1-1/k)^(8k), i.e. 0.03 %; a route that gets a smaller share of the
    ports is missed more easily.

2.  **Routes.** Traces that do not contradict each other are one route;
    a different router at one TTL, or a different length, proves two
    routes different. Routes get letters (A, B, ...) per session; JSON
    carries stable group IDs. When a measured port confirms a new router
    at some TTL, every traced port that still shows the old router there
    is traced again, so a moved topology leaves no routes behind that no
    longer exist.

3.  **Measuring.** The first port is measured from the start; every
    route found gets **--flows** (default 1) of its own ports measured
    end to end, one SYN per **--interval** (default 1 s), plus
    continuous hop probes. A measured port is never swapped out: if its
    path changes it keeps being measured on its new route.

4.  **Judging.** Every flow, route and endpoint gets a state (OK, LOSS,
    DOWN, UNKNOWN) from statistics with confidence intervals; partial
    failures (some routes failing, others fine) are reported as such,
    and failing routes are compared with healthy ones to name a
    suspected segment.

**mpmtr** does not report missing data, or the measurement problems it
detects, as network loss. When something cannot be shown, the result is
UNKNOWN or INCONCLUSIVE.

With **--anycast** it also finds the servers behind one address (see
**ANYCAST SERVERS**), and with **--app** it checks every measured server
at the application level through a plugin (see **APPLICATION CHECKS**).

**mpmtr** needs the **CAP_NET_RAW** capability (see **PERMISSIONS**). It
changes no sysctl and writes no files except those named on the command
line and the **--ix** cache in *~/.cache/mpmtr*.

# TARGETS

A target is a host name, an IPv4 address or an IPv6 address, optionally
with a port (default 443):

``` text
example.com
example.com:80
192.0.2.10:443
'[2001:db8::1]:443'
```

Several targets are measured at once, each as its own endpoint; **Tab**
switches between them on the live screen. A host name is resolved once
at start; **-4** or **-6** selects the address family.

# OPTIONS

Durations (*D*) are seconds ( **0.2**, **5**) or Go durations with units
( **200ms**, **1m30s**).

## Modes

**-r**, **--report**  
Measure **-c** probes per flow, print a report and exit with a status
code (see **EXIT STATUS**).

**-c**, **--count** *N*  
End-to-end probes per flow. Report mode default: 100. In live mode: stop
after *N* probes per flow and print the final report. Counts probes
actually executed (sent and resolved), not scheduled slots. A flow needs
30 valid probes before it can be called OK or LOSS (DOWN is detected
earlier, by a run of failures), so a report with **-c** below 30 ends
with status 3 unless a flow is DOWN.

**--json**  
Print the report as JSON (with **--report** or **--discover**).

**--discover**  
Only discover the routes, print the route tree and the groups, exit.
**-c** has no meaning here and is ignored.

**--events** *FILE*  
Write state changes as JSON lines to *FILE*; an existing file is
appended to. **-** writes them to standard output and disables the
interactive screen; it cannot be combined with **-r** or **--discover**,
whose report goes there.

**--report-timeout** *D*  
Deadline for report and discover mode (default 5m). When it is reached,
a partial report with the real counts and an INCOMPLETE mark is printed.

## Probing

**-i**, **--interval** *D*  
End-to-end probe interval per flow (default 1s).

**--timeout** *D*  
Reply deadline, at most the interval (default 1s, or the interval if
shorter).

**--hop-timeout** *D*  
Hop probe deadline (default min(timeout, interval/2)).

**--flows** *N*  
Source ports measured per route (default 1). One port per route answers
"which route fails"; 2 or more also separate a route problem from a
problem of a single 5-tuple (one LAG member, state on a middlebox). With
**--no-discovery**: ports measured in total.

**--sport-range** *A-B*  
Source ports, used in order; at most this many ports are traced (default
20000-20255; with **--anycast** 20000-22047). The same range gives the
same ports and therefore the same paths in every run. If another
**mpmtr** instance holds the default block, the next free block
(20256-20511, ...) is taken and a note is printed; with an explicit
range, **mpmtr** stops and names the PID of the holder.

**--src-ports** *LIST*  
Explicit source ports, e.g. **20001,20007,20023**.

**--max-ttl** *N*  
Maximum TTL for traces (default 30). End-to-end probes are sent with TTL
64, or 255 when *N* is 64 or more.

**--no-discovery**  
End to end only: no route discovery and no hop probes.

**--trace-on-failure=false**  
No extra traces when flows degrade. By default, an incident (flows
failing or degrading) triggers up to 5 rounds of TTL sweeps on the
failing flows and on up to 3 healthy controls.

**--shared-hops**  
Share hop work between ports: a hop that several measured ports see at
the same TTL (same router) is probed from one of them only, and
discovery does not re-trace the first hops once 8 or more ports saw the
same single router there (every 8th port still does). Off by default.

## Rate limits

**--pps** *N*  
Global probe rate (default 1000/s). End-to-end probes may use 90 % of
it.

**--endpoint-pps** *N*  
Probe rate per endpoint (default 500/s); hop probes get what is left
after the end-to-end demand.

**--responder-pps** *N*  
Hop probes a second that one router gets (default 100/s). The limit is
shared by all the endpoints measured: routers limit the rate of their
ICMP answers themselves, and probes above it would go unanswered. A hop
whose router has not answered yet is counted by its place: interface,
gateway, TTL and previous hop.

**--max-inflight** *N*  
Probes in flight (default derived from the rates).

## Servers and applications

**--anycast**  
Find the servers behind the address by their TCP timestamp clocks (a
census of one SYN per port) and measure every server through its own
port. See **ANYCAST SERVERS**.

**--app** *"NAME \[ARGS\]"*  
Application check of every measured server by the plugin
<b>mpmtr-app-</b><i>NAME</i> (next to **mpmtr** or in **PATH**; a path
also works), with its own arguments; an argument with spaces goes in
single quotes inside. See **APPLICATION CHECKS**.

**--app-interval** *D*  
Application check interval per measured port (default 10s, at least 1s).

**--app-timeout** *D*  
Application check timeout (default 5s, less than the interval).

## Addressing

**-4**, **-6**  
IPv4 or IPv6 only (host name resolution).

**--src** *ADDR*  
Source address.

**--interface** *IF*  
Egress interface.

**--tos** *N*  
IPv4 TOS or IPv6 traffic class (0-255, fixed per flow).

**--flow-label** *N*  
IPv6 flow label (0-1048575, fixed for all probes).

**--fwmark** *N*  
Firewall mark for the route lookup and **SO_MARK**; needs
**CAP_NET_ADMIN**.

**-n**, **--no-dns**  
No reverse DNS (default).

**--dns**  
Reverse DNS names of the hops.

**--no-quote-fallback**  
Never match an ICMP reply whose quoted TCP sequence number differs from
the probe's (see **HOW REPLIES ARE MATCHED**).

## Hop annotations

The network of each hop, shown at the end of its FLAGS where it changes
along the route (a hop in the same network as the one above it shows
nothing). All sources are off by default.

**--asn**  
The origin AS of the hop address, e.g. **AS15169 GOOGLE**, from the Team
Cymru bulk whois (**whois.cymru.com**, TCP port 43, one query per batch
of new hops). This sends the public hop addresses to that service;
private, shared (CGNAT), link-local, documentation and reserved
addresses are never sent.

**--ix**  
<b>IX:</b><i>name</i> on a hop whose address is on an Internet exchange
peering LAN, followed by <b>member AS</b><i>number name</i> when
PeeringDB lists the address as an IX member's, e.g. **IX:DE-CIX
Frankfurt member AS15169 Google LLC**. The address belongs to the IX's
LAN, the router to that member: neither **--asn** nor registry whois
names the member, which is the network the path enters there. The prefix
and member lists come from PeeringDB (five API requests, about 7 MB),
are cached for a day in *~/.cache/mpmtr/peeringdb-ix.json* and an older
copy is used when the download fails. PeeringDB limits clients that ask
often without an account (HTTP 429, for up to an hour): a list it
refused is asked again after an hour, not on every run, and a warning
says why it failed, when it is asked again and what is shown meanwhile
(no IX marks without the prefixes, no member without the member list).

**--geoip** <i>FILE</i><b>\[,</b><i>FILE</i><b>...\]</b>  
Offline lookups in MaxMind DB files: country and city from a GeoIP
database (GeoLite2 Country/City, DB-IP lite), shown as **(DE,
Frankfurt)**; the AS from an ASN database (GeoLite2 ASN, DB-IP ASN lite)
without **--asn** and without sending anything. The location of a router
address is often just where its network is registered.

The JSON report lists what is known about every hop address in
**ip_info**.

**--hop-info** *NAME* <b>\[</b><i>ARGS</i><b>\]</b>  
What a plugin (<b>mpmtr-hop-</b><i>NAME</i> next to **mpmtr** or in
PATH, or a path) knows about each hop address: a name, shown in place of
the bare address, and a note in the **PLUGIN** column (present with this
option, and with **--app** when its plugin notes something about the
answers). May be given several times: the plugins run side by side, the
first name wins, the notes are joined. In JSON: **hop_info**. **mpmtr**
itself sends nothing for this; hop addresses come from the network, so
what may be asked is decided by the plugin's own configuration.
**mpmtr-hop-snmp** comes with **mpmtr**: **--hop-info "snmp FILE"** asks
the router for its name and the interface that owns the answering
address (**"snmp --descr FILE"**: with the interface's description;
**"snmp --errors FILE"**: with its receive errors, **crc:**N or
**err:**N), and never sends a packet to an address outside the prefixes
listed in FILE (lines of **PREFIX community=...** or **PREFIX user=...
auth=PROTO:PASS priv=PROTO:PASS**; the file must not be readable by
group or others). See **docs/PLUGINS.md**.

**--hop-info-interval** *D*  
Ask the plugins again about an address still shown when their answer is
this old (at least 1s; default 0: each address is asked once). The old
answer stays until the new one is in. With **mpmtr-hop-snmp --errors**
the counters then also show their growth since the first look
(**crc:1532 +12**).

## Other

**-h**, **--help**  
Print the option summary.

**--version**  
Print the version.

# THE LIVE SCREEN

Without **-r** or **--discover**, **mpmtr** shows a continuously updated
screen, like **mtr**. The terminal is restored on **q**, Ctrl-C and
SIGTERM. When standard output is not a terminal, plain-text summaries
without escape codes are printed every 10 seconds instead.

## Keys

**q**  
Quit.

**p**  
Pause the screen; measuring continues.

**r**  
Reset the statistics: a new measurement epoch with a fresh warmup.

**d**  
Next view: route tree, flow table, one flow, servers (with
**--anycast**).

**s**, **← →**  
Flow table and server list: sort by the next / previous column (source
port or server number by default). The header marks the column; numbers
sort largest first, states worst first.

**f**  
One flow: focus. This port's whole route is traced every interval, so
its hop rows are fresh; the hop refresh of the other ports waits
meanwhile (their TCP measurements go on, their hop rows turn **stale**).
Leaving the view turns focus off.

**↑ ↓**, **j k**  
Select a row (tree, servers) or a flow (flow table).

**PgUp PgDn**  
Scroll.

**Enter**  
Tree: fold or unfold the selected hop (a folded subtree becomes one line
that summarises the routes below it); opening a hop also opens the chain
below it down to the next fork. On a DST row or a server row: open that
route's (or server's) measured flow. Flow table: open the selected flow;
Esc or Enter goes back. Servers view: open the route to the selected
server.

**Esc**  
Back to where Enter came from.

**- +**  
Tree: fold all, unfold all.

**\***  
Tree: one line per route — every fork stays open, each part that no
longer branches is folded into one line.

**Tab**, **n**  
Next endpoint.

**Ctrl-L**  
Redraw the whole screen (after another program wrote over it).

**?**, **h**  
Help.

## Reading the tree view

``` text
✔ OK: 0 of 589 probes failed (95% CI 0.0–0.6%) on 5 source ports, 5 routes.
example.com 192.0.2.10:443  OK  │ flows 5: 5 ok │ E2E fail 0.0% n=589 ...
  routes found 5 · discovery done: no new route among the last 40 ports ...
TTL   HOST                     Loss%  Snt   Last    Med    P95   Best   Wrst  Jttr
1     172.16.100.1              0.0%   17   1.63   1.89   2.95   1.56   3.10  0.10
2     ├─ 172.16.200.1           0.0%    6  153.9  153.6  154.2  153.2  154.3  0.11
3     │ └─ 203.0.113.218        0.0%    3  165.9  174.5  181.4  165.9  182.1  1.46
4-5   │    * no reply (2 hops) 100.0%    9
12    │    DST 192.0.2.10        0.0%   41  173.0  159.6  172.1  158.2  173.0  0.92 ▸ route B OK
```

**Verdict line**  
The first line: the conclusion in one sentence, with the number of
failed probes and its 95 % confidence interval. It is never stronger
than the states below it.

**Endpoint line**  
Target, address, state (with scope: PARTIAL, ALL), flows by state,
end-to-end failure rate with n and the confidence interval, median RTT.
Below it: the routes found and the state of discovery, in words.

**Tree**  
Hops shared by several routes are printed once; the tree branches where
flows take different routes. A branch ends with the DST row of its
route: the end-to-end result of that route's measured ports (route
letter, state). The DST row's Loss% is the route's loss.

**Hop columns**  
**Loss%** is the share of unanswered ICMP probes to that hop (shown with
3 or more probes). It is *apparent* loss: routers rate-limit their ICMP
replies, so hop loss is not transit loss unless it persists on the later
hops and end to end. **Snt** is probes sent; **Last**, **Med**, **P95**,
**Best**, **Wrst** are RTT in ms, **Jttr** is the jitter: the smoothed
difference of consecutive RTTs (RFC 3550).

**Hop rows**  
**\* no reply** — the hop has answered none of the probes sent to it;
**? no reply yet** — too few probes to tell; **~ a \| b** — several
responders (per-packet balancing); **? only later hops answer: X** —
only routers of later TTLs of the same path answered at this TTL, so who
is here is not known.

**Flags**  
**also answered by later hop X** — the router of this TTL answers an
expiring probe and lets the same packet go on, so the routers after it
answer it too (a probe sent with TTL 3 is then answered by the routers
of TTL 3, 4 and 5). A router answers only probes sent with a TTL up to
its position, so the largest TTL it answered is its place; the TTL and
order of the answers are not used. Not another route, not a route
change, not an unstable hop; the row's timing comes from the hop's own
router; **icmp-limit?** — the router limits its ICMP replies: a later
hop of the same route loses significantly less (the 95 % intervals do
not overlap), which points to ICMP rate limiting rather than to loss of
forwarded traffic (the row is dimmed; on the live screen a hop's
**Loss%** is red when the loss goes on at every answering hop after it,
on every branch, down to a destination that loses end to end, and
**Last** and **Med** are yellow when the round-trip time stands above
the row's own history at that hop, every hop after it and the
destination; JSON: **loss_persists_downstream**, **rtt_shift**,
**rtt_spike**); **stale** — the row's ports have not probed this hop for
three statistics buckets (30 s at **-i 1**). Ports that share a router
with other ports still probe it themselves at least every two buckets,
so the mark is not a side effect of sharing. It does appear when the hop
budget is short (a low **--pps** or **--endpoint-pps** with many routes)
and while one port is in focus (**f**): the others' hop refresh waits. A
DOWN flow gives every second E2E slot to its hop probes, so its route
stays fresh; **mpls:** — the MPLS labels the router reported (RFC 4950):
**a/b** is one label stack, outermost first; **a,b** are different
stacks reported for different ports of this row; **unstable** — the
responder at this TTL changes; **qseq:N** — replies matched by the
fallback rule; **unreach** — ICMP unreachable seen; **AS15169 GOOGLE**,
**IX:name**, **(DE, Frankfurt)** — the hop's network where it changes
(see **Hop annotations**).

**Lines under the tree**  
**not yet assigned** — measured ports whose trace still fits several
routes (a hop has not answered yet); **stopped measuring** — ports
stopped because another port already measures that route or server;
problem flows with their reason; the plugin state (with **--app**).

**measurer line**  
Probe rates and the measurer's own counters: **capture drops** (kernel
or userspace), **skipped slots** (a probe could not be sent on time;
never counted as loss), **late** (answers after the deadline: the probe
counted as lost, the answer noted), **unexpected** (packets on our ports
that answer none of our probes — another program or prober using the
same source port; a port flooded by them becomes INVALID), **local
errors**.

## Flow table and flow view

The flow table lists every measured port: state, route, **TRACED** (how
sure its route is: **yes** — traced and repeated; **partly** —
incomplete but provably different; **probably** — fits one route;
**ambiguous**; **not yet**), probes executed and valid, timeouts,
unreachables, the failure rate over 5 minutes with its interval, and RTT
last, min, median, p95, max, jitter. **WARMUP** means fewer than 30
results yet; **RTT-UP** means its RTT rose against its own baseline or
against the other flows.

The flow view (Enter) shows one port: its counters, RTT statistics,
flags, route and the full hop table of its own path.

# STATES

Flows, routes and endpoints have an availability state and a quality
state.

**OK**  
Enough valid probes (30 or more) and no confirmed problem. An endpoint
is OK only with at least 75 % of its flows covered.

**LOSS**  
Statistically confirmed failures: over 5 minutes, 30 or more valid
probes and the lower bound of the 95 % Wilson interval of the failure
rate above 2 %, held for 3 evaluations 10 s apart. It clears when the
last 60 s show at most 0.5 % failures with 30 or more valid probes and
30 consecutive answers.

**DOWN**  
5 consecutive valid failures without an answer in between, recent in
time, measurer healthy. On a flow that already loses probes, more: the
run must be improbable under the flow's own background loss (q =
P(failure \| previous failure) outside DOWN periods, 95 % upper bound,
half-life 30 min; k failures in a row with q^(k-1) ≤ 10^-5; the run
itself is not part of the background, so an outage does not raise its
own threshold): 7–8 at 10 % background, 9 at 18 %, 11–12 at 30 %, at
most 20; 5 with less than 30 valid probes of history. The flow view
shows it: **(DOWN at 9: background loss 18%)**. It clears after 5
consecutive answers. An endpoint is DOWN only when all of its flows are
confirmed DOWN.

**UNKNOWN**  
Not enough trustworthy data yet (WARMUP), or the data cannot decide.

**MEASUREMENT_INVALID**  
The port's measurement cannot be trusted and is excluded: replies not
matching our probes dominate, a local NAT rewrites the port, a middlebox
rewrites sequence numbers, the local route changed, or probes leave by
another interface than routed.

Endpoint scopes: **LOSS/PARTIAL** — some flows work; **LOSS/ALL** — all
measured flows degrade but answer. Further flags: **STALE**,
**MEASUREMENT_IMPAIRED** (the measurer lost packets or the remote TCP
state interfered; no DOWN is confirmed meanwhile), **RTT_DEGRADED**
(1.5× and +10 ms against the other flows or against the flow's own
baseline, for three 10-second periods).

Skipped probes, local errors, capture impairment and cancelled probes
never count as failures, and none of them completes a DOWN run.

The thresholds are numbers of probes, so the windows hold as many probes
at any **--interval**: the 5 min, 60 s and 10 s above are 300, 60 and 10
probe intervals when the interval is longer than one second (with **-i
5s** they are 25 min, 5 min and 50 s, and a hop is stale after 150 s
instead of 30 s). The reports keep the names 5m and 60s; JSON gives the
real lengths in **window_long_seconds** and **window_short_seconds**.

# OUTPUT

## Report

**-r** prints a text report of every endpoint: the verdict, the route
tree with hop statistics, the flows, the routes, localization and
warnings. With **--json** the same data is one JSON object: **tool**,
**version**, **started**, **finished**, **complete** (false when the
report was cut short, with the reasons in **incomplete_reasons**),
**exit_code**, **parameters** and **result** (endpoints with flows,
routes, tree, servers, localization; metrics of the measurer), plus the
recent **events**. Field names are stable; numbers are raw counts, RTT
in microseconds.

Both formats include a **pcap filter** (JSON:
**parameters.pcap_filter**; also on the help screen of the live view)
for **tcpdump**(1): the probes, their answers and the ICMP errors about
them, for this run's endpoints and source ports, e.g. to attach a
capture to a ticket:

``` text
tcpdump -w mpmtr.pcap '(tcp and host 192.0.2.1 and port 443 and
  portrange 20000-20255) or (icmp and icmp[24:4] = 0xc0000201)'
```

## Events

**--events** writes one JSON object per line on every state change:
FLOW_DOWN / FLOW_RECOVERED, FLOW_LOSS / FLOW_LOSS_CLEARED,
PATHGROUP_DOWN / PATHGROUP_LOSS / PATHGROUP_RECOVERED, ENDPOINT_DOWN /
ENDPOINT_LOSS / ENDPOINT_RECOVERED, PARTIAL_PATH_FAILURE, ROUTE_CHANGED,
RTT_DEGRADATION / RTT_RECOVERED, MONITORING_IMPAIRED /
MONITORING_RECOVERED, LOCALIZATION_RESULT.

Each event has a stable **key** (entity and incident number); a recovery
carries the key of the incident it ends. Simultaneous transitions of
several flows are reported once, at the highest level that describes
them, with the flows listed. Recoveries are never suppressed.

Every event has **time** and **type**; **endpoint** (the target),
**state**, **prev_state** and **scope** of the endpoint or route it is
about, **group** (the route), **flows** (each with its name, source port
and its own transition) and **details** (counts, reasons, and for
LOCALIZATION_RESULT the suspected segments) are present where they
apply.

A measured port whose measurement cannot be trusted (a local NAT
rewrites it, its local route changed, most packets on it are not answers
to the probes) is reported as MONITORING_IMPAIRED with **details.scope**
"flow" and the reason; its key names the port and has no incident
number.

# EXIT STATUS

In report mode, and in live mode with **-c**:

**0**  
All endpoints OK.

**1**  
LOSS or a partial failure, no DOWN.

**2**  
Confirmed DOWN.

**3**  
Not enough trustworthy data: UNKNOWN; an OK endpoint where more than 25
% of the measured ports have no verdict or cannot be measured; or an
incomplete report (deadline, interrupt, a stopped plugin) with nothing
confirmed DOWN.

**4**  
Invalid parameters or a runtime error (for example a missing capability,
or the packet capture failing during the run: the report is still
printed, marked INCOMPLETE).

Across endpoints the worst wins: error, then DOWN, then UNKNOWN, then
LOSS, then OK.

**--discover** measures nothing end to end; its status is about the
route list: 0 when discovery ran to its own stop rule, 3 when it was cut
short (deadline, interrupt) or found no route, 4 on an error.

# ANYCAST SERVERS

Many services answer one address from many servers; a load balancer
picks the server by hashing the connection's addresses and ports, so a
source port keeps reaching the same server. **--anycast** tells those
servers apart by their TCP timestamp clocks and measures each one it can
tell apart.

**Telling servers apart**  
Every SYN carries the TCP timestamp option and the SYN/ACK returns the
server's clock. The clock's offset against our time is constant per
server, so answers cluster by server. Rates of 1000, 250 and 100 Hz are
tried. A cluster is a server only when it is narrow, comes from at least
2 ports with at least 3 answers, and its answers are spread in time.

**Census**  
One SYN from each port of the range (default 20000-22047), 64 in flight,
until no new server appeared among the last max(64, 8 × servers) ports;
ports whose answer fitted no server are asked twice more. Servers are
named S1, S2, ... by clock.

**Measuring**  
Every server gets **--flows** measured ports of its own, besides the
ports measuring the routes. Every answer of a measured port is checked
against its server's clock; a port answering three times in a row on
another server's clock moves to it, and the server it leaves gets its
next port measured. A server that no answer ever confirmed is taken off
the list when the last of its ports has gone this way: the census put
answers of other servers together, or the server left the balancer's
pool before it was measured. A server that only stops answering stays on
the list and is DOWN. No second census runs: a server added later is
found by a new run.

**Screen**  
Servers are listed under the DST row of the route their port takes, each
with its own end-to-end numbers; the servers view (**d**) lists them
all. Enter on a server shows the route to that server.

**Limits**  
A Linux server with **net.ipv4.tcp_timestamps=1** (the default) adds a
random offset to its clock. Kernels with commit 165573e4 (March 2026,
CVE-2026-23247, also in the stable series) compute that offset per
connection: every port looks like its own clock, and the servers cannot
be told apart. **mpmtr** then says so and invents no servers. Where the
offset is computed per pair of addresses (kernels without that commit,
as a rule) or there is none, the census works. There is no census either
when replies carry no timestamp (**tcp_timestamps=0**).

**Servers you run**  
Set **net.ipv4.tcp_timestamps=2** on the servers (not on the host that
runs **mpmtr**): timestamps stay on, without the random offset, so every
machine shows one clock, whatever its kernel. The setting acts on new
connections at once; nothing is restarted.

``` text
sysctl -w net.ipv4.tcp_timestamps=2    # for the diagnosis
sysctl -w net.ipv4.tcp_timestamps=1    # back to the default
```

The price: the timestamp then shows the machine's clock as it is, so
anyone can read how long the machine has been up. Hence a setting for a
diagnosis, not for good.

# APPLICATION CHECKS

TCP tells whether a server accepts connections; a plugin can tell
whether it actually works. With **--app** *NAME* every measured port
gets an application check every **--app-interval** over a real kernel
TCP connection opened from that same source port, with the probes' TOS
and IPv6 flow label, so a load balancer leads it to the same server. The
connected socket is handed to the plugin
<b>mpmtr-app-</b><i>NAME</i><b>,</b> which speaks the protocol and
answers ok or failed; the connection is then closed with RST.

The checks are counted apart from the TCP probes. For TCP a check whose
connection was made, or refused, is an answer (a passed check gives an
RTT sample: the connection's handshake), and one whose SYN got no answer
is a timeout; a plugin problem is a local error and counts as neither.
The verdicts have counters and a rate of their own (**app_checks**,
**app_failed**, **app_failure_rate** in JSON; the flag
<b>app-failed:</b><i>N</i><b>/</b><i>M),</i> and a state of their own:
three failed checks in a row make the port DOWN (reason **app_down**)
although TCP answers, two passed in a row bring it back, and checks that
fail now and then make it LOSS. **-c** counts TCP probes only; the
checks come on top, as real connections outside the **--pps** limits.
The plugin runs with the privileges **mpmtr** has (root under sudo): use
only programs you trust. If it dies, the report is INCOMPLETE and says
so. While a check runs, the port's raw probes pause (those slots are
skipped, not lost) and the connection's packets are not taken for probe
replies. Checks wait until discovery and the census are over, and each
one starts right after an answered end-to-end probe of its port (a
TTL-limited probe can leave the 4-tuple half-open on a stateful NAT).

**mpmtr-app-http** (an HTTP HEAD check, over TLS on port 443) comes with
**mpmtr**. A plugin may add a short note to its verdict (the HTTP status
of that plugin): it is shown in the **PLUGIN** column of the row with
the port's end-to-end numbers, and is **app_note** of the flow in JSON.
The plugin protocol (one JSON message per packet over a unix
SOCK_SEQPACKET socket on fd 3, the connected socket passed with
SCM_RIGHTS) and the Go SDK are described in **docs/PLUGINS.md** of the
source tree.

# HOW REPLIES ARE MATCHED

Replies are captured from one AF_PACKET socket with a kernel BPF filter.
A SYN/ACK or RST\|ACK is an answer when the reversed 4-tuple matches and
ACK = sequence + 1. An ICMP error is matched by the quoted 4-tuple and
sequence number; without a sequence match it is accepted only when
exactly one probe can explain it and the IPv4 IP ID (or IPv6 flow label)
also matches ( **--no-quote-fallback** disables this). A TCP reply whose
ACK does not fit while one probe could explain it is a *weak* reply
(possible sequence translation by a middlebox): counted, never a
success. Late and duplicate answers are counted as such and never
credited to a newer probe. Our own SYN must be seen leaving: if it is
not, the probe is a local error, not a loss; if it leaves with another
source address or port (local NAT), the flow is invalid.

A timeout is declared only after the capture reported all packets up to
the probe's deadline; a timeout that overlaps a capture drop is a
measurement impairment, not a loss. RTT is the kernel receive timestamp
of the reply minus the kernel timestamp of our own captured SYN.

Sequence numbers are built like RFC 6528 (a 4 μs clock plus a fixed hash
of the 4-tuple), so for a 4-tuple they move forward, within a run and,
while the system clock is not set back, across runs: a stateful NAT
drops a re-sent SYN whose sequence number moved backwards.

# SOURCE PORTS

Ports come from **--sport-range** (used in order) or **--src-ports**.
Before the first probe, ports used by other local TCP sockets are
skipped (silently for the range). Every used port is then reserved with
a TCP socket that is bound but not listening: the kernel no longer hands
it to **connect**(2) and still answers incoming SYN/ACKs with RST. Each
instance also claims its port block with an abstract unix socket
(**@mpmtr/ports16/**N for every 16 ports), so a second instance moves to
the next block.

The source address and egress interface are looked up per flow over
rtnetlink with the flow's ports, TOS and mark, and every probe's egress
interface is checked. A local multipath route over several interfaces is
followed; nexthops that share one interface cannot be selected and
**mpmtr** warns about it. A flow whose local route changes is retired
with its statistics and a new flow takes over the port.

# PERMISSIONS

Raw sockets and AF_PACKET need **CAP_NET_RAW**; **--fwmark** also needs
**CAP_NET_ADMIN**. Run as root, or grant the capabilities to the binary
once (repeat after every rebuild — a new file has none):

``` text
sudo setcap cap_net_raw,cap_net_admin+ep /usr/local/bin/mpmtr
```

Without the capability **mpmtr** exits with status 4 and prints this
command with the path of the binary that was run. A systemd unit with
**RestrictAddressFamilies** blocks AF_PACKET even when the capability is
present.

# ENVIRONMENT

**MPMTR_DEBUG_PKT**  
When set, every captured packet is printed to standard error.

**MPMTR_DEBUG_APP**  
When set, every application check is printed to standard error.

**MPMTR_DEBUG_ANYCAST**  
A file name: the census answers are written there as JSON on exit.

# EXAMPLES

Live screen, like **mtr**:

``` text
mpmtr example.com
```

Two endpoints at once (Tab switches):

``` text
mpmtr 192.0.2.1:80 198.51.100.7:443
```

A report after 100 probes per flow, as JSON, for a script:

``` text
mpmtr -r -c 100 --json example.com > report.json; echo $?
```

Only find the routes:

``` text
mpmtr --discover example.com
```

Two measured ports per route, probes every 200 ms:

``` text
mpmtr --flows 2 -i 0.2 example.com
```

Monitoring with events and no screen:

``` text
mpmtr --events - example.com | jq -c .
```

Every server behind an anycast address, each checked over HTTP:

``` text
mpmtr --anycast --app http example.com:80
```

IPv6 with a port, fixed flow label:

``` text
mpmtr --flow-label 12345 '[2001:db8::1]:443'
```

Name the networks along the routes (AS, Internet exchanges) and the
country from an offline GeoLite2 file:

``` text
mpmtr --asn --ix --geoip GeoLite2-Country.mmdb example.com
```

# LIMITATIONS

- Linux only, IPv4 and IPv6.

- The routes found are the routes observed through ICMP and TCP: LAG
  members, MPLS tunnels and per-packet balancing stay invisible, one
  signature does not prove one physical path, and ICMP may return on
  another path than TCP. None of the discovery stop reasons proves that
  all paths were found.

- Hop Loss% describes ICMP replies, not transit traffic.

- An external NAT is not detected; when its mapping expires it may
  re-map the port, which shows as a route change beyond the NAT, not as
  loss. A local NAT on the measuring host is detected.

- Probing one 4-tuple repeatedly interacts with middlebox and server TCP
  state. **mpmtr** detects what it can see and excludes it from loss,
  but an invisible middlebox policy can still bias results.

- One of those exclusions delays DOWN in a rare case. When the RST that
  ends a probe's handshake is lost, the server keeps the half-open
  connection and repeats its SYN/ACK at growing intervals (1 s, 3 s, 7 s
  ... after the first). For 3 s after each repeat (three timeouts, if
  that is longer) an unanswered probe of that port is not counted as
  lost: a server that holds state for the 4-tuple may leave a new SYN
  unanswered. If only the forward direction fails right then, the
  repeats keep arriving, and the run of failures that makes the flow
  DOWN starts later. An outage of both directions is not affected: no
  repeats arrive.

- The confidence intervals assume independent losses and are optimistic
  for bursty loss.

- The port reservation protects against **connect**(2) and other binds,
  not against another privileged process that sends raw packets from the
  same ports.

- **--ix** depends on PeeringDB, which throttles anonymous clients:
  several first downloads in a short time (several hosts behind one
  address, a cleared cache) can be refused for up to an hour. Until then
  IX hops are not marked (or are marked from an older cache, or without
  the member network); the warning gives the time of the next try.

# SEE ALSO

**mpmtr-app-http**(1), **mpmtr-hop-snmp**(1), **mtr**(8),
**traceroute**(8), **tcptraceroute**(8), **packet**(7), **raw**(7),
**ip-route**(8), **setcap**(8)

Paris traceroute; RFC 6528 (TCP ISN generation), RFC 4950 (ICMP MPLS
extensions), RFC 9293 (TCP).

Source, issues and the full description of the method:
[](https://github.com/hotid/mpmtr)

# LICENSE

MIT.
