# Plugins

[Русская версия](PLUGINS.ru.md)

To write a plugin of your own, see [WRITING_PLUGINS.md](WRITING_PLUGINS.md).
The plugins that come with mpmtr have man pages: `man mpmtr-app-http`,
`man mpmtr-hop-snmp`.

Two kinds of plugins, both separate executables started by mpmtr:
[application checks](#application-check-plugins) (`--app`) and
[hop information](#hop-information-plugins) (`--hop-info`).

## Application-check plugins

mpmtr measures paths and servers with TCP only. A plugin adds an
application-level check of every measured server: `mpmtr --app NAME` runs
the executable `mpmtr-app-NAME` (next to mpmtr or in `PATH`; `--app PATH`
also works); `--app "NAME ARGS..."` passes the plugin its own arguments. Every `--app-interval` (default 10 s) and for each measured
port, mpmtr

1. opens a real kernel TCP connection **from that port** — the same
   4-tuple its TCP probes use, with the same TOS and IPv6 flow label, so a
   load balancer leads it to the same server (with `--anycast`: exactly the
   server it measures);
2. hands the connected socket to the plugin, which speaks its protocol;
3. closes the connection with RST (no TIME_WAIT; the server and stateful
   middleboxes drop the state before the next probe).

While a check runs, the port's raw probes pause (those slots count as
skipped, never as loss) and the connection's packets are not taken for
probe replies. Outcomes, in the port's (and its server's) statistics:

| outcome | for TCP | for the application |
|---|---|---|
| protocol passed | an answer (RTT = the connection's handshake) | a passed check |
| protocol failed (connected, or refused) | an answer | a failed check |
| no answer to the SYN | a timeout | — |
| plugin problem (crash, no answer, local error) | a local error: neither | — |

The checks are counted apart from the TCP probes: `app_checks`,
`app_failed` and `app_failure_rate` in JSON, the flag `app-failed:N/M` on the
flow, "application checks: N of M failed" in the verdict. They are far fewer
than the probes (one per `--app-interval`), so they are never pooled with
them, and they have a state of their own:

* three failed checks in a row make the port **DOWN** (reason `app_down`)
  although TCP answers; two passed in a row bring it back;
* checks that fail now and then make it **LOSS**, by the same test as for
  the probes, on the checks alone.

`-c` counts TCP probes only; the checks come on top, outside the `--pps`
limits. Checks wait until discovery and the census are over, and each one
starts right after an answered end-to-end probe of its port: a TTL-limited
probe leaves the 4-tuple half-open on stateful NATs (SYN_SENT with our
sequence), and a real connection opened then stalls whenever the kernel's
ISN happens to be lower.

The plugin runs with the privileges mpmtr has (root under sudo), so it must
be a program you trust; if it dies, the report is INCOMPLETE and says so.

### Protocol

fd 3 of the plugin is a unix `SOCK_SEQPACKET` socket; every message is one
JSON object in one packet.

```
plugin → mpmtr  {"type":"hello","name":"http","version":"1"}
mpmtr → plugin  {"type":"check","id":7,"src":"192.0.2.1","sport":20031,
                 "dst":"192.0.2.10","dport":443,"server":"S7","timeout_ms":5000}
                 + the connected TCP socket (SCM_RIGHTS)
plugin → mpmtr  {"type":"result","id":7,"ok":false,"stage":"handshake",
                 "error":"eof","ms":12.5}
```

* `hello` first, within 5 s.
* Checks may arrive concurrently; answer each with its `id`.
* Close your copy of the socket before answering; mpmtr closes the last one.
* Answer within `timeout_ms`; mpmtr gives up a second later (local error).
  A plugin that leaves three checks in a row unanswered is stopped, so that
  the connections it still holds are closed; the report is then INCOMPLETE.
* `stage` names where the check failed, in your words; `stage:"plugin"`
  marks a plugin-side problem (local error, not the server's fault).
* `server` is mpmtr's name of the server behind the address (`--anycast`).
* stderr is kept for diagnostics (shown when the plugin dies).

### Go SDK

Package `github.com/hotid/mpmtr/plugin` implements the protocol:

```go
plugin.Serve("http", "1", func(ctx context.Context, c net.Conn, req plugin.Request) plugin.Result {
	fmt.Fprintf(c, "HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n", req.Dst.Addr())
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		return plugin.Result{Stage: "answer", Err: err}
	}
	return plugin.Result{OK: strings.HasPrefix(line, "HTTP/")}
})
```

`cmd/mpmtr-app-http` is this example as a complete plugin. It passes when
the server answers with an HTTP status line, whatever the status: a 503 is a
pass. It shows that something speaks HTTP on that server, not that the
service works; a check of your service belongs in a plugin of your own.

## Hop-information plugins

`mpmtr --hop-info NAME` runs the executable `mpmtr-hop-NAME` (next to mpmtr
or in `PATH`; `--hop-info PATH` also works); `--hop-info "NAME ARGS..."`
passes the plugin its own arguments. The option may be given several times:
the plugins run side by side.

mpmtr gives each plugin the address of every hop it shows, once, and the
plugin answers with what it knows. With `--hop-info-interval D` (at least
1 s; default 0) an address still on the screen is asked again when its
answer is that old: the old answer stays until the new one is in, and a new
answer that says nothing does not erase it. An address that got no answer
is retried at the same interval. The answers:

* `name` — shown as the hop's host name, `name (address)`. The first plugin
  (in command-line order) that names an address wins; a plugin's name comes
  before the reverse-DNS one.
* `note` — a short text in the `PLUGIN` column of the hop's row (the column
  is there only with `--hop-info`); the notes of all plugins stand side by
  side. A tab in a note separates columns: mpmtr pads them so that the same
  column starts at the same place on every row (`Port-Channel37 err:0` over
  `Vlan754        err:0`).

Both go to the JSON report as `hop_info`: address → plugin → `name`, `note`.

mpmtr itself sends nothing anywhere for this. Whether an address is looked
up, where and with what credentials is the plugin's business and its own
configuration; mpmtr has no option for any of it. Hop addresses come from
the network: a router anywhere on the path chooses the address it answers
with, so a plugin that asks the device itself must be told which addresses
it may ask. A plugin that fails or dies never affects the measurement: there
is a warning, and its annotations stop.

### Protocol

JSON objects, one per line: requests on the plugin's stdin, answers on its
stdout.

```
plugin → mpmtr  {"type":"hello","name":"snmp","version":"1"}
mpmtr → plugin  {"type":"hop","id":4,"addr":"192.0.2.1"}
plugin → mpmtr  {"type":"info","id":4,"name":"core1","note":"Eth1/2"}
```

* `hello` first, within 5 s.
* Requests may be answered in any order; answer each with its `id`, with
  empty `name` and `note` when nothing is known.
* An answer later than 30 s is ignored; a final report waits for answers at
  most 10 s.
* `name` is cut at 64 characters and each column of `note` at 120; control characters are
  dropped.
* mpmtr closes stdin when it is done. stderr is kept for diagnostics.

### Go SDK

```go
plugin.ServeHops("rack", "1", 8, func(ctx context.Context, a netip.Addr) plugin.HopInfo {
	return plugin.HopInfo{Note: racks[a]}
})
```

### mpmtr-hop-snmp

`mpmtr --hop-info "snmp FILE"` asks a hop's router for its name (`sysName`)
and for the interface that owns the address that answered (`ifName`): at
most two GET requests per address, no table walks. With `--descr`
(`--hop-info "snmp --descr FILE"`) the interface's description (`ifAlias`)
follows in «».

```
HOST                         …  PLUGIN
core1.example (192.0.2.1)    …  Ethernet1/2
core1.example (192.0.2.1)    …  Ethernet1/2 «to spine 3»     with --descr
```

FILE says which addresses may be asked and how. An address in no prefix is
never sent a packet; the longest matching prefix wins. The file must not be
readable by group or others (`chmod 600`).

```
# SNMPv2c: the community travels in clear text to every address asked
10.0.0.0/8      community=public
# SNMPv3
192.0.2.0/24    user=monitor auth=sha256:secret-one priv=aes:secret-two
# options, on any line: port=161 timeout=1s retries=1
```

`auth`: md5, sha, sha224, sha256, sha384, sha512; `priv`: des, aes, aes192,
aes256; passphrases of at least 8 characters, without spaces.

`--errors` (`--hop-info "snmp --errors FILE"`, with or without `--descr`)
adds the interface's receive errors, in the same request:

* `crc:N` — frames that failed the checksum (`dot3StatsFCSErrors`);
* `err:N` — all input errors (`ifInErrors`), where the interface has no
  checksum counter (a port-channel, a VLAN interface);
* nothing, if the device gives neither.

The counters run since the device booted. When mpmtr asks again
(`--hop-info-interval`), the growth since the plugin's first look is added:
`crc:1532 +12`. A counter that went back (the device restarted) starts the
count anew.

The interface is the one that owns the answering address — usually the one
the probe came in through, but a router may answer from another interface
or a loopback. The interface the traffic leaves through is not told.
