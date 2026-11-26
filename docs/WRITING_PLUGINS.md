# Writing plugins

[Русская версия](WRITING_PLUGINS.ru.md) · reference: [PLUGINS.md](PLUGINS.md)

A plugin is a separate program that mpmtr starts and talks to. There are two
kinds, with different jobs and different channels:

| | hop information (`--hop-info`) | application check (`--app`) |
|---|---|---|
| answers | "what is this hop address?" | "does this server really work?" |
| executable | `mpmtr-hop-NAME` | `mpmtr-app-NAME` |
| how many at once | several | one |
| channel | JSON lines on stdin / stdout | JSON packets on a unix socket, fd 3 |
| asked | once per address (or every `--hop-info-interval`) | every `--app-interval` per measured port |
| affects the result | no, only what is shown | yes: failed checks make the server LOSS or DOWN |

Any language will do. For Go there is an SDK,
`github.com/hotid/mpmtr/plugin`; the two examples in `examples/` are written
in Python without it.

## Common to both

- **Name and place.** `--hop-info NAME` runs `mpmtr-hop-NAME`, `--app NAME`
  runs `mpmtr-app-NAME`: next to the mpmtr binary first, then in `PATH`. A
  name with a `/` is taken as a path.
- **Arguments.** Everything after the name is yours:
  `--hop-info "static /etc/inventory.txt"` starts
  `mpmtr-hop-static /etc/inventory.txt`. Arguments are split at spaces; there
  is no quoting.
- **One process for the whole run.** mpmtr starts the plugin once. Keep what
  is worth keeping (connections, caches) in memory.
- **Say hello first, within 5 seconds.** Check your arguments and files
  before it: if you exit instead, mpmtr does not start and shows your stderr.
- **stderr is yours.** mpmtr keeps the last 20 lines and shows them when the
  plugin dies. Never write anything but protocol messages to the channel.
- **Stay compatible.** Ignore message types and fields you do not know.
- **Privileges.** The plugin runs as the user mpmtr runs as, often root. Do
  not trust what you read from the network more than you have to.

## A hop-information plugin

### What happens

1. mpmtr starts every `--hop-info` plugin and waits for each `hello`.
2. When a row with an address is first drawn, mpmtr sends that address to
   every plugin: hop addresses and the destination.
3. The plugin answers with a `name`, a `note`, both or neither.
4. `name` is shown as `name (address)`, `note` in the `PLUGIN` column. With
   several plugins the first name (in command-line order) wins and the notes
   are joined with a space.
5. With `--hop-info-interval D` the same address comes again when your answer
   is that old, for as long as the row is on the screen.
6. At the end mpmtr closes your stdin. Exit then.

### Messages

One JSON object per line. Requests on stdin, answers on stdout.

```
plugin → mpmtr  {"type":"hello","name":"static","version":"1"}
mpmtr → plugin  {"type":"hop","id":4,"addr":"192.0.2.1"}
plugin → mpmtr  {"type":"info","id":4,"name":"core1","note":"rack 12"}
```

### Rules

- **Answer every request**, with empty `name` and `note` when you know
  nothing. A final report waits for the answers it still misses (up to 10 s).
- **Any order.** Requests may be answered out of order; the `id` ties them.
- **30 seconds.** A later answer is ignored.
- **Flush after every line.** stdout is a pipe: a buffered answer does not
  arrive.
- **Keep it short.** `name` is cut at 64 characters, each column of `note` at 120, control
  characters are dropped. The column is at most 40 wide.
- **Columns.** If your note has parts (an interface and a counter), put a
  tab between them: `"note":"Ethernet1/2\terr:0"`. mpmtr lines each part up
  down the screen. Keep the number of parts the same on every row; send an
  empty part rather than leaving one out. At most 6.
- **An empty answer does not erase.** On a refresh, an empty answer leaves
  what you said before on the screen. To withdraw a note, say something else.
- **Addresses come from the network.** A router anywhere on the path chooses
  the address it answers with. If you look an address up somewhere, and above
  all if you send credentials with the lookup, decide from your own
  configuration which addresses you may ask. mpmtr will hand you all of them.
- **Do not be slow for everyone.** Requests arrive in a burst when a trace
  finishes. Work on several at once, but with a limit.

### In Go, with the SDK

```go
package main

import (
	"context"
	"fmt"
	"net/netip"
	"os"

	"github.com/hotid/mpmtr/plugin"
)

func main() {
	racks := map[netip.Addr]string{netip.MustParseAddr("192.0.2.1"): "rack 12"}
	err := plugin.ServeHops("rack", "1", 8, func(ctx context.Context, a netip.Addr) plugin.HopInfo {
		return plugin.HopInfo{Note: racks[a]}
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "mpmtr-hop-rack:", err)
		os.Exit(1)
	}
}
```

`ServeHops` says hello, reads the requests, runs at most 8 lookups at once
(the third argument), gives each a context with a 20-second deadline and
returns when mpmtr closes stdin. `cmd/mpmtr-hop-snmp` is a complete plugin
built on it.

### Without the SDK

`examples/mpmtr-hop-static` (Python) reads names and notes from a text file.
Its whole protocol part:

```python
say({"type": "hello", "name": "static", "version": "1"})
for line in sys.stdin:                       # ends when mpmtr closes stdin
    req = json.loads(line)
    if req.get("type") != "hop":
        continue
    name, note = known.get(req["addr"], ("", ""))
    say({"type": "info", "id": req["id"], "name": name, "note": note})
```

where `say` writes one line and flushes.

### Trying it by hand

A hop plugin needs no mpmtr to be tried: feed it requests.

```bash
printf '%s\n' '{"type":"hop","id":1,"addr":"192.0.2.1"}' | ./mpmtr-hop-static inventory.txt
{"type": "hello", "name": "static", "version": "1"}
{"type": "info", "id": 1, "name": "core1", "note": "rack 12, row B"}
```

Then with mpmtr: `mpmtr -r -c 5 --json --hop-info "./mpmtr-hop-static inventory.txt" TARGET`
and look at `hop_info` in the output.

## An application-check plugin

### What happens

1. mpmtr starts the plugin and waits for its `hello`.
2. Every `--app-interval` (default 10 s), for every measured port, mpmtr
   opens a real TCP connection **from that port** to the target. A load
   balancer therefore leads it to the server that port's probes measure.
3. If the connection is refused or the SYN is not answered, mpmtr records
   that itself and you are not called.
4. Otherwise mpmtr hands you the connected socket with a `check` message.
5. You speak your protocol over the socket, close your copy and answer
   with a `result`.
6. mpmtr closes the last copy with RST and records your verdict for that
   port and its server.

### Messages

Descriptor 3 is a unix `SOCK_SEQPACKET` socket. Every message is one JSON
object in one packet. A `check` carries the connected TCP socket as
ancillary data (`SCM_RIGHTS`).

```
plugin → mpmtr  {"type":"hello","name":"banner","version":"1"}
mpmtr → plugin  {"type":"check","id":7,"src":"192.0.2.1","sport":20031,
                 "dst":"192.0.2.10","dport":443,"server":"S7","timeout_ms":5000}
                 + the connected TCP socket
plugin → mpmtr  {"type":"result","id":7,"ok":false,"stage":"handshake",
                 "error":"eof","ms":12.5}
```

- `server` is mpmtr's name of the server behind the address (`--anycast`),
  empty otherwise.
- `timeout_ms` is what is left of `--app-timeout` after the connect.
- `ms` is how long your part took; informational.

### The verdict

| you answer | counted as |
|---|---|
| `"ok":true` | a passed check |
| `"ok":false`, any `stage` but `"plugin"` | a failed check of that server (three in a row: DOWN) |
| `"ok":false,"stage":"plugin"` | a local error: neither passed nor failed |
| nothing within `timeout_ms` + 1 s, or the plugin died | a local error |
| nothing to three checks in a row | the plugin is stopped (its sockets close), the report is INCOMPLETE |

So the choice of `stage` matters:

- The server did not speak the protocol, answered wrongly, or was silent
  until the deadline: that is its failure. Name the step in your own words
  (`"handshake"`, `"banner"`, `"auth"`); it is shown with the failure.
- You could not do your part (no socket in the message, a bug, a missing
  file, a dependency of yours is down): answer `"stage":"plugin"`. A plugin
  problem must never look like a loss on the network.

### Rules

- **Checks run in parallel.** One arrives per measured port; answer each
  with its `id`, in any order. One slow server must not hold the others.
- **Finish by the deadline.** Set `timeout_ms` on the socket. mpmtr gives up
  a second after it and counts a local error.
- **Close your copy before you answer.** mpmtr closes the last one, and that
  must be the one that sends the RST.
- **Close sockets you will not use**: a message you do not understand may
  still carry one.
- **One conversation per check.** The socket is a fresh connection every
  time; do not keep it.
- **Be light.** The check repeats every interval on every measured port, and
  the port's probes pause while it runs.

### In Go, with the SDK

```go
package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/hotid/mpmtr/plugin"
)

func main() {
	err := plugin.Serve("http", "1", func(ctx context.Context, c net.Conn, req plugin.Request) plugin.Result {
		if _, err := fmt.Fprintf(c, "HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n", req.Dst.Addr()); err != nil {
			return plugin.Result{Stage: "send", Err: err}
		}
		line, err := bufio.NewReader(c).ReadString('\n')
		if err != nil {
			return plugin.Result{Stage: "answer", Err: err}
		}
		if !strings.HasPrefix(line, "HTTP/") {
			return plugin.Result{Stage: "answer", Err: errors.New("not an HTTP status line")}
		}
		return plugin.Result{OK: true}
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "mpmtr-app-http:", err)
		os.Exit(1)
	}
}
```

`Serve` says hello, receives the sockets, runs every check in its own
goroutine with the deadline already set on the connection and in `ctx`,
closes the plugin's copy and sends the result. `cmd/mpmtr-app-http` is this with a `User-Agent` header.

The example passes on any HTTP status line, a 503 included: it tells that
the server speaks HTTP, not that the service is well. A real check looks at
what your service must answer.

### Without the SDK

`examples/mpmtr-app-banner` (Python) expects a greeting line that starts
with a given text (`--app "banner SSH-2.0"`). The part that is not obvious
is receiving the socket:

```python
chan = socket.socket(fileno=3)
chan.send(json.dumps({"type": "hello", "name": "banner", "version": "1"}).encode())
while True:
    data, fds, _, _ = socket.recv_fds(chan, 65536, 4)   # the message and its sockets
    if not data:
        break                                            # mpmtr is gone
    conn = socket.socket(fileno=fds[0])
    ...
    conn.close()                                         # before the answer
    chan.send(json.dumps({"type": "result", "id": req["id"], "ok": ok}).encode())
```

In C the same is `recvmsg` with a control buffer and `CMSG_DATA`.

### Trying it

An application plugin cannot be piped by hand: it needs the socket on
descriptor 3. Run it under mpmtr:

```bash
MPMTR_DEBUG_APP=1 mpmtr -r -c 30 --app "./mpmtr-app-banner SSH-2.0" example.com:22
```

`MPMTR_DEBUG_APP=1` prints one line per check on stderr: the port, whether
the connection was made, your verdict, the stage and the time. In the report
a failed check shows as `app-failed:N/M` on the flow (N of M checks failed).

## Checklist

- [ ] hello first, within 5 s; arguments checked before it
- [ ] only protocol messages on the channel; diagnostics on stderr
- [ ] every request answered, with its `id`
- [ ] unknown message types and fields ignored
- [ ] hop plugin: output flushed per line; lookups limited to addresses your
      configuration allows
- [ ] app plugin: deadline honoured; own socket copy closed before the
      answer; `"stage":"plugin"` for your own problems only
- [ ] exits when the channel closes
