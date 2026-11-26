package cli

// usageText is printed by --help. Keep it in sync with the flag set.
const usageText = `mpmtr — multipath TCP MTR

Routers that balance traffic per connection (ECMP) send different source
ports along different routes. mpmtr traces source ports in order (20000,
20001, ...) with TTL-limited SYNs (Paris-traceroute style) until new ports
keep landing on routes it already knows, and measures --flows ports of every
route found end to end (TCP SYN once per second). The first port is measured
from the start; a measured port is never swapped out. A measured source port
is a "flow" (F1, F2, ... in probing order). It needs CAP_NET_RAW.

USAGE
  mpmtr [options] target[:port] [target[:port]...]      (default port 443)

EXAMPLES
  sudo mpmtr example.com                 live screen (like mtr), q to quit
  sudo mpmtr 192.0.2.10:80 example.net   several endpoints, Tab switches
  sudo mpmtr -r -c 100 example.com       100 probes per flow, text report
  sudo mpmtr -r -c 100 --json example.com > report.json
  sudo mpmtr --discover example.com      only find the routes, print the tree
  sudo mpmtr --events events.jsonl example.com   live screen + JSONL events
  sudo mpmtr --events - example.com      events to stdout, no screen
  sudo mpmtr '[2001:db8::1]:443'         IPv6 with port

READING THE RESULT
  The first line is the verdict. States: OK, LOSS (statistically confirmed
  failures), DOWN (5+ consecutive failures on every flow; more on a flow
  that already loses probes, so that the run is not chance), UNKNOWN (not
  enough trustworthy data yet — a flow needs 30 valid probes to be called OK
  or LOSS, ~30 s at the default interval; DOWN is detected earlier). Hop
  Loss% is the share of unanswered ICMP probes to that hop; it is NOT
  transit loss unless it persists on later hops and E2E.
  Exit codes (report): 0 OK, 1 loss/partial, 2 down, 3 not enough data or
  an incomplete report, 4 error. --discover: 0 complete, 3 cut short.
  With --interval above 1s the 5 min / 60 s windows stretch to 300 / 60
  probe intervals (the thresholds are numbers of probes).

MODES
  -r, --report            run -c probes per flow, print a report, exit
  -c, --count N           E2E probes per flow (report default 100; in live
                          mode: stop after N and print the final report)
      --json              JSON report (with --report or --discover)
      --discover          only discover routes, print the tree, exit
      --events FILE       write JSONL events (state changes); '-' = stdout
                          (no screen; not with -r or --discover)
      --report-timeout D  deadline for report/discover (default 5m); a
                          partial report with real counts is printed

PROBING                   (D = seconds like 0.2 or 5, or units: 200ms, 1m30s)
  -i, --interval D        E2E interval per flow (default 1s)
      --timeout D         reply deadline, <= interval (default: 1s, or the
                          interval if shorter)
      --hop-timeout D     hop probe deadline (default min(timeout, interval/2))
      --flows N           source ports measured per route (default 1);
                          with --no-discovery: ports measured in total
      --sport-range A-B   source ports, used in order; at most this many are
                          traced (default 20000-20255; if another mpmtr
                          instance uses them, the next free block is taken)
      --src-ports LIST    explicit source ports, e.g. 20001,20007,20023
      --max-ttl N         maximum TTL for traces (default 30)
      --no-discovery      E2E only: no route discovery, no hop probing
      --trace-on-failure=false   no extra traces when flows degrade

RATE LIMITS
      --pps N             global probe rate (default 1000/s)
      --endpoint-pps N    per endpoint (default 500/s)
      --responder-pps N   hop probes per router (ICMP responder), shared by
                          all endpoints (default 100/s)
      --max-inflight N    probes in flight (default: from --pps and --timeout)
      --shared-hops       share hop work between ports: a hop that several
                          measured ports see at the same TTL (same router) is
                          probed from one of them only, and discovery does not
                          re-trace the first hops once >= 8 ports saw the same
                          single router there (every 8th port still does).
                          Off by default

SERVERS AND APPLICATIONS
      --anycast           servers behind the address: a census (one SYN per
                          port) tells them apart by their TCP timestamp
                          clocks, then every server is measured through its
                          own port and shown after its route's DST. Default
                          ports 20000-22047. Not possible where servers use a
                          clock per connection (then it says so)
      --app "NAME [ARGS]" application check of every measured server by a plugin
                          (mpmtr-app-NAME): a real connection from the port's
                          own source port, the plugin speaks the protocol.
                          Counted apart from the TCP probes; three failed
                          checks in a row make the server DOWN
                          (docs/PLUGINS.md; example: --app http, which
                          also shows the HTTP status in the PLUGIN column)
      --app-interval D    per measured port (default 10s)
      --app-timeout D     (default 5s)

ADDRESSING
  -4, -6                  IPv4 / IPv6 only (hostname resolution)
      --src ADDR          source address
      --interface IF      egress interface
      --tos N             IPv4 TOS / IPv6 traffic class (fixed per flow)
      --flow-label N      IPv6 flow label (fixed for all probes)
      --fwmark N          fwmark for route lookup and SO_MARK
  -n, --no-dns            no reverse DNS (default)
      --dns               reverse DNS of hops
      --no-quote-fallback never match ICMP quotes whose TCP seq differs

HOP ANNOTATIONS           (shown in FLAGS where they change along a route)
      --asn               origin AS of each hop ("AS15169 GOOGLE"): asks
                          whois.cymru.com about the public hop addresses
                          (never private, shared or documentation ones)
      --ix                "IX:name" on hops on an Internet exchange peering
                          LAN (PeeringDB prefix list, downloaded once a day
                          and cached in ~/.cache/mpmtr)
      --geoip FILE[,FILE] offline .mmdb databases (MaxMind GeoLite2, DB-IP
                          lite): country/city ("(DE, Frankfurt)"); an ASN
                          database gives the AS without --asn, offline
      --hop-info "NAME [ARGS]"
                          what a plugin (mpmtr-hop-NAME) knows about each hop
                          address: a name and a note in the PLUGIN column of
                          the hop's row. May be given several times. mpmtr
                          itself sends nothing; the plugin asks only what its
                          own configuration allows
                          (docs/PLUGINS.md; --hop-info "snmp [--descr]
                          [--errors] FILE": the router's name and interface
                          over SNMP; --descr adds the interface's description,
                          --errors its receive errors, crc:N or err:N)
      --hop-info-interval D
                          ask the plugins again about an address still shown
                          when their answer is this old (default 0: once)

OTHER
  -h, --help              this text
      --version           print the version

INTERACTIVE KEYS
  q quit · p pause screen (measuring continues) · r reset statistics ·
  d next view (route tree / flow table / one flow / servers with --anycast) ·
  s ← → sort the flow table or the servers ·
  f focus: trace the open flow every interval ·
  ↑↓ j k select · PgUp PgDn scroll · Enter open or fold · Esc back ·
  - + fold / unfold the tree · * one line per route · Tab n next endpoint ·
  Ctrl-L redraw · ? h help

See README.md and docs/ for the method, the statistics and the limitations.
`
