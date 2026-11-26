# How mpmtr measures

[Русская версия](MEASUREMENT.ru.md) · [README](../README.md)

Probes, how replies are matched to them, what counts as a result, and how results become states.

## Probes and identity

One flow = (family, src IP, src port, dst IP, dst port, TCP, TOS, IPv6 flow
label, routing context).

* All probes of a flow share every header field except TTL/hop limit, IPv4
  IP ID, the TCP sequence number and checksums.
* The SYN has a fixed 40-byte TCP header with MSS, SACK-permitted, timestamp
  and window scale options (unit-tested byte by byte).
* IPv4 uses `IPPROTO_RAW` (`IP_HDRINCL`); IPv6 uses `IPPROTO_RAW` (implicit
  `IPV6_HDRINCL`). The flow label and traffic class are verified on the wire
  by an integration test.
* One SYN is one probe: no kernel retransmissions.

**Sequence numbers** are built like RFC 6528: `ISN = 4 µs clock +
F(4-tuple) + jitter`, so for a 4-tuple they move forward, within a run and
across runs. "Forward" is in sequence-number arithmetic: the 32-bit counter
wraps about every 4 h 46 min. Across runs it rests on the system clock: set
back, it breaks the order until the clock passes the old value. F is a fixed
function of the 4-tuple, not the keyed one the RFC prescribes: it has to
give the same value in every run, and the probes open no connection.

A stateful NAT or firewall on the path accepts a re-sent SYN on a 4-tuple
still in `SYN_SENT` only when its sequence number is after the previous one,
and drops the others as conntrack INVALID. With random per-probe ISNs most
probes would be lost to that device, and a healthy server would look DOWN.

## Capture and correlation

Replies come from one AF_PACKET `SOCK_RAW` socket (ETH_P_ALL, so our own
outgoing SYNs and the kernel's RSTs are visible too) with a `PACKET_RX_RING`
TPACKET_V3 ring and a classic BPF filter in the kernel:

* TCP in our port range,
* every outgoing pure SYN,
* ICMP/ICMPv6 unreachable and time exceeded.

Ethernet/VLAN, IPv4, IPv6 extension headers, ICMP quotes (short quotes, RFC
4884 lengths, RFC 4950 MPLS) are parsed allocation-free. A fragment, a
truncated packet or a bad checksum is never matched.

* SYN/ACK or RST|ACK is a **strict** reply when the reversed 4-tuple matches and
  ACK = seq+1. RST without ACK is an unexpected reply, not a success.
* ICMP is matched by the quoted 4-tuple and seq. Without a seq match it is
  accepted only when exactly one probe can explain it and the IPv4 IP ID (or
  IPv6 flow label) also matches; such a match is marked `quote_seq_mismatch`.
  `--no-quote-fallback` disables this.
* **Weak reply**: a TCP reply whose ACK does not fit, while exactly one probe
  could explain it (possible seq translation by a middlebox). Counted
  separately, never a success, never in RTT/loss. When weak/unexpected replies
  dominate, the flow becomes `MEASUREMENT_INVALID`.
* Completed probes stay in a guard window, so a late reply is counted as
  `late` and a duplicate as `duplicate`. Neither is credited to a newer probe.
* **Our own SYN must be seen leaving.** If it is not, the probe is
  `local_error`, not a loss. If it leaves with a different source
  address/port (local SNAT), the flow is `MEASUREMENT_INVALID`. If it leaves
  through another interface than the flow's route lookup chose, the egress
  mismatch is counted and the flow is invalidated.
* **Remote state**: when our RST is lost on the way, the server keeps the
  4-tuple in SYN_RECV and may ignore the next SYN or answer it with a
  challenge ACK. A probe without reply while such evidence exists is
  `remote_state_conflict`, a TCP-state artifact of reusing the 4-tuple and
  not network loss; the flow is flagged `MEASUREMENT_IMPAIRED`.
  Some servers keep such a connection for a minute or more whatever RSTs
  follow, and answer every SYN of that port with an ACK of the old probe.
  Each flow remembers the last probes the server answered, so that ACK is
  recognised however old the probe is. The flow stays impaired while it
  lasts and measures again afterwards; it is not `MEASUREMENT_INVALID`,
  which is for packets that answer no probe of ours.

**Timestamps.** RTT = kernel RX timestamp of the reply − kernel timestamp of
our captured outgoing SYN (same AF_PACKET socket, same clock). This is the
timestamp at the capture tap, not physical transmission. When the TX capture
timestamp is missing or implausible, the userspace send time is used and
counted as `tx_ts_fallback`. All scheduling uses the monotonic clock.

**Capture integrity.** A timeout is declared only after the capture side
reports a *watermark* past the probe deadline, i.e. after all packets up to
that time have been delivered. `PACKET_STATISTICS` (kernel ring drops) and
userspace queue overflow are reported with each watermark.

A timeout whose wait interval overlaps a drop period becomes
`capture_impaired`. While the measurer is impaired, no DOWN is confirmed
(`DOWN_HELD_IMPAIRED`) and the screen shows `MONITORING_IMPAIRED`. Zero
reported drops does not prove a lossless receive path.

## Outcomes and statistics

E2E outcomes: `syn_ack`, `rst`, `icmp_unreachable`, `timeout`, `weak_reply`,
`unexpected_reply`, `local_error`, `capture_impaired`,
`remote_state_conflict`, `measurement_invalid`, `skipped`, `cancelled`, plus
late/duplicate counters.

```
valid        = syn_ack + rst + icmp_unreachable + timeout
timeout_rate = timeout / valid
failure_rate = (timeout + icmp_unreachable) / valid
reply_rate   = (syn_ack + rst) / valid        (valid = 0 → UNKNOWN, never 0 % or 100 %)
```

With `--app` the connection of every application check is one more TCP
result (an answer, or a timeout when its SYN got none). The verdicts of the
checks are not in these rates: they have `app_checks`, `app_failed` and
`app_failure_rate` of their own, see [PLUGINS.md](PLUGINS.md).

Per flow there are:

* lifetime counters,
* 10-second buckets with 60 s and 5 min windows,
* loss episodes (count, max/mean run),
* RTT last/min/mean/median/p95/max/jitter (p99 with ≥100 samples) from
  strict positive replies only,
* a 95 % Wilson interval for failure_rate, always shown with n. The interval
  assumes independent losses and is optimistic for bursty loss. It is used
  only as an onset criterion, never for recovery.

Groups and endpoints aggregate by summing counts, never by averaging
percentages; worst flow, fully failed flows and the share of failing flows
are shown, so one bad flow out of 16 stays visible.

**Heterogeneity** (5 min, n ≥ 30): a flow (or group) is an outlier when its
failure rate is ≥5 percentage points above the pooled rest *and* its Wilson
lower bound is above the rest's upper bound. Results: `heterogeneous`,
`no_detected_heterogeneity`, `insufficient_data`.

**RTT degradation**: the median of each of the last three 10 s periods is
≥1.5× and ≥+10 ms above the reference, with ≥20 samples in the three periods
together and at least one in each. Recovery has hysteresis, 1.25×/+5 ms.

* **relative** — compares a flow with the median of the other flows;
* **absolute** — compares it with its own baseline.

The baseline starts after 60 healthy samples and then rolls over the last
hour of healthy minutes. It is frozen during loss, degradation or
impairment, so a lasting degradation does not become the new normal. Without
a baseline the flow shows `BASELINE_UNKNOWN`.

## State machine

Flow: `UNKNOWN`, `OK`, `LOSS`, `DOWN` (+ `STALE`, `MEASUREMENT_IMPAIRED`,
`MEASUREMENT_INVALID`, `RTT_DEGRADED`). Availability and quality are kept
separately.

* **DOWN**: 5 consecutive valid failures without a positive reply in between,
  the series fresh in time (a gap > 3×interval+timeout restarts it), measurer
  healthy. It does not wait for the 30-sample warmup.

  On a flow that already loses probes, a run of 5 is chance, not an outage
  (at 18% random loss it happens about 13 times a day per flow), so the run
  must be improbable under the flow's own background: with q = P(failure |
  previous failure) outside DOWN periods (95% upper bound, half-life 30 min),
  DOWN needs k failures in a row with q^(k−1) ≤ 10⁻⁵.

  A run of failures enters the background only when it ends, and not at all
  when it ended in DOWN. So an outage does not raise the threshold it is
  judged by.

  10⁻⁵ is how sensitive the rule is, not a promised rate of false alarms: it
  is the chance that a run which has begun reaches k if failures follow each
  other no more often than q says. Losses that come in longer bursts than
  the history shows break that, and the number of false DOWNs grows with the
  number of measured flows.

  Clean flow: 5; 10% background: 7–8; 18%: 9; 30%: 11–12 (at most 20). With
  fewer than 30 valid probes of history it is 5.

  JSON: `down_after_failures`, `background_loss`, `fail_after_fail`; the flow
  view says `(DOWN at 9: background loss 18%)`.
* **Leaving DOWN**: 5 consecutive strict positives. A new recovery epoch starts,
  quality stays UNKNOWN (`RESPONDING_QUALITY_PENDING`) until enough
  post-recovery data exists, and the DOWN period cannot trigger a LOSS.
* **LOSS**: 5 min window, ≥30 valid, Wilson lower bound > 2 %, held for 3
  evaluations (10 s apart; overlapping windows are persistence, not
  independent confirmation). While loss evidence is pending, an UNKNOWN flow
  does not become OK.
* **Leaving LOSS**: 60 s failure ≤ 0.5 % with ≥30 valid and ≥30 consecutive
  positives; old failures are then excluded from onset detection.
* Skipped, local_error, capture_impaired and cancelled probes never count as
  failures, and none of them completes a DOWN run.
* **Windows and `--interval`.** The thresholds are numbers of probes, so the
  windows never hold fewer probes than at 1 s: the statistics bucket is 10 s
  or ten probe intervals, whichever is longer. From 1 s up the number of
  probes in a window is the same; below 1 s there are more.

  With the default 1 s (and below) the windows are the 5 min, 60 s and 10 s
  above; with `-i 5s` they are 25 min, 5 min and 50 s, and a hop is `stale`
  after 150 s instead of 30 s.

  The reports keep the names "5m" and "60s" and print the real lengths
  (`window_long_seconds`, `window_short_seconds` in JSON).
* **Invalid ports.** A port that cannot be measured (local NAT rewrites it,
  wrong egress interface, weak replies dominate) is `MEASUREMENT_INVALID`: it
  is left out of the states and of the coverage, and with discovery the route
  gets another port. It still counts as missing data for the exit code (the
  25 % rule above).

PathGroup, from the states of its measured ports:

| measured ports | route |
|---|---|
| none | `UNKNOWN` |
| all DOWN | `DOWN` |
| some DOWN or LOSS, the others OK or UNKNOWN | `LOSS`, marked partial |
| all DOWN or LOSS, not all DOWN | `LOSS` |
| all OK | `OK` |
| some OK, the others still warming up (newly measured ports) | `OK` |
| anything else (UNKNOWN for another reason: stale, impaired, loss pending) | `UNKNOWN` |

`INTRAGROUP_HETEROGENEITY` is set when ports of one route disagree: some OK,
some DOWN or LOSS.

Endpoint, from all its measured ports (invalid ones aside):

| measured ports | endpoint |
|---|---|
| all DOWN | `DOWN` |
| some DOWN or LOSS, some OK | `LOSS/PARTIAL` |
| all DOWN or LOSS, not all DOWN | `LOSS/ALL` |
| some LOSS, none DOWN, none OK, the rest UNKNOWN | `LOSS/ALL` (the unknown rest is in the counts) |
| some DOWN, none OK, the rest UNKNOWN | `LOSS/UNKNOWN` (12 DOWN + 4 UNKNOWN is not DOWN) |
| none DOWN or LOSS, ≥75 % of them OK | `OK` |
| anything else | `UNKNOWN` |
