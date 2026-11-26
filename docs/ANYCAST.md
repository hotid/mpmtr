# Servers behind one address

[Русская версия](ANYCAST.ru.md) · [README](../README.md)

What `--anycast` does and where it cannot work.

## Servers behind an anycast address (`--anycast`)

Many services answer one address from many servers; a load balancer picks
the server by hashing the connection's addresses and ports, so a source
port keeps reaching the same server. `--anycast` tells those servers apart
by their TCP timestamp clocks and measures each one it can tell apart; two
servers whose clocks cannot be distinguished count as one.

* **Telling servers apart.** Every SYN carries the TCP timestamp option;
  the server's SYN/ACK returns its clock (TSval). `TSval − t·Hz (mod 2³²)`
  is constant per server, so answers cluster by server. Rates 1000, 250 and
  100 Hz are tried; tolerance 50 ms plus half a SYN-cookie quantum (64
  ticks — a SYN cookie keeps only the upper bits of the clock).

  A cluster is a server only when:
  * it is narrow (every offset within tolerance of the centre),
  * it comes from ≥ 2 ports with ≥ 3 answers,
  * its answers are spread in time (2 × tolerance / gap to the nearest other
    rate — close answers fit a clock of any rate).
* **Census.** One SYN from each port of the range (default 20000–22047 in
  this mode), 64 in flight, until neither a new server nor an answer on a
  clock nobody has (a server the balancer gives few ports to) appeared
  among the last max(64, 8 × servers) ports; then the ports whose answer
  fitted no server are asked twice more. Server
  numbers (S1, S2, …) are kept by clock.
* **Measuring.** Every server gets `--flows` measured ports (lowest first),
  besides the ports measuring the routes. Each E2E answer of a measured port
  is checked against its server's clock; a port answering three times in a
  row on another known server's clock moves to it, and the server it leaves
  gets its next port measured: one port that was not its own says nothing
  about the others. A server that no answer ever confirmed is taken off the
  list (`phantom_servers_dropped`) when the last of its ports has gone this
  way: either the census put answers of other servers together into a clock
  nobody has, or the server left the balancer's pool before it was measured
  and its ports went to others. The two cannot be told apart from here.
  Until then it stays on the list, about three probe intervals per port.

  A server that only stops answering is never taken off: silence does not
  say it was not there. It stays on the list and is DOWN.
* **After the census.** No second census runs. A server added to the pool
  later is not found: answers of measured ports on a clock no known server
  has are only counted (`answers_from_unknown_clock`). A new run finds it.
* **Screen.** Servers are listed under the DST row of the route their
  measured port takes, each with its own end-to-end numbers; Enter opens it.
  `d` also offers `view: servers` — every server in one list (end-to-end
  numbers, state, measured port, ports, route, application checks); Enter
  shows the route to the selected server, Esc returns to the list.
  The endpoint line shows the census (`servers behind the address: 44 …`).
* **Where it cannot work.** A Linux server with `net.ipv4.tcp_timestamps=1`
  (the default) adds a random offset to its clock.
  * Kernels with commit 165573e4 (March 2026, CVE-2026-23247, also in the
    stable series) compute that offset per connection: every port looks like
    its own clock. mpmtr then says the servers cannot be told apart and
    invents none.
  * Where the offset is computed per pair of addresses (kernels without
    that commit, as a rule) or there is none, the census works.

  Also no census when replies carry no timestamp (`tcp_timestamps=0`).
* **Servers you run.** Set `net.ipv4.tcp_timestamps=2` **on the servers**
  (not on the host that runs mpmtr): timestamps stay on, without the random
  offset, so every machine shows one clock, whatever its kernel. Two
  machines whose clocks happen to coincide still count as one. The setting
  acts on new connections at once; nothing is restarted.

  ```bash
  sudo sysctl -w net.ipv4.tcp_timestamps=2    # for the diagnosis
  sudo sysctl -w net.ipv4.tcp_timestamps=1    # back to the default
  ```

  The price: the timestamp then shows the machine's clock as it is, so
  anyone can read how long the machine has been up. Hence a setting for a
  diagnosis, not for good.

The census sees a server only through the ports the balancer gives it: a
server that gets very few ports of the range may be missed, and another
port range may then find it.
