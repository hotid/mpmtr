#!/usr/bin/env bash
# Real-socket throughput run in the netns topology (needs root):
#   bench_throughput.sh <endpoints> <flows-per-endpoint> <count> [extra mpmtr args]
# Adds <endpoints> destination addresses 10.20.1.N behind the ECMP fabric,
# runs mpmtr in report mode with E2E only and prints resource usage.
set -euo pipefail
cd "$(dirname "$0")"
EPS=${1:-25}; FLOWS=${2:-128}; COUNT=${3:-20}; shift 3 || true
BIN=${MPMTR_BIN:-../mpmtr}
./topo.sh up
x() { ip netns exec "$1" "${@:2}"; }
for i in $(seq 1 "$EPS"); do x mpdst ip addr add 10.20.1.$i/32 dev lo; done
x mprd ip route add 10.20.1.0/24 via 10.20.0.2
for i in 1 2 3 4; do x mpr$i ip route add 10.20.1.0/24 via 10.12.$i.2; done
x mpr0 ip route add 10.20.1.0/24 nexthop via 10.11.1.2 nexthop via 10.11.2.2 nexthop via 10.11.3.2 nexthop via 10.11.4.2
x mpdst sysctl -qw net.ipv4.tcp_max_syn_backlog=65536 net.core.somaxconn=65535
ip netns exec mpdst python3 -c "
import socket,time
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind(('0.0.0.0',443)); s.listen(65535)
time.sleep(100000)" >/dev/null 2>&1 &
SRV=$!
sleep 1
TARGETS=$(for i in $(seq 1 "$EPS"); do printf '10.20.1.%d:443 ' "$i"; done)
PPS=$(( EPS * FLOWS * 2 + 1000 ))
OUT=$(mktemp)
/usr/bin/time -v -o "$OUT.time" ip netns exec mpsrc "$BIN" -r -c "$COUNT" --json --no-discovery \
	--flows "$FLOWS" --pps "$PPS" --endpoint-pps $(( FLOWS * 3 )) --report-timeout 10m "$@" $TARGETS > "$OUT" || true
kill "$SRV" 2>/dev/null || true
python3 - "$OUT" <<'EOF'
import json,sys
d=json.load(open(sys.argv[1])); s=d['result']; m=s['metrics']
fl=[f for e in s['endpoints'] for f in e['flows']]
c=lambda k: sum(f['counters'][k] for f in fl)
dur=(s['uptime_ms'])/1000
print(f"flows {len(fl)}  duration {dur:.1f}s  complete {d['complete']}  exit {d['exit_code']}")
print(f"E2E sent {c('sent')}  ({c('sent')/dur:.0f}/s)  syn_ack {c('syn_ack')}  timeout {c('timeout')}  skipped {c('skipped')}  local_err {c('local_err')}  impaired {c('impaired')}  remote_state {c('remote_state_conflict')}")
print(f"capture drops {m['capture_drops']} user drops {m['user_drops']}  sched lag avg {m['lag_sum']/max(1,m['lag_n'])/1e6:.2f}ms max {m['lag_max']/1e6:.1f}ms  skip_by {m['skip_by']}")
states={}
for e in s['endpoints']: states[e['state']]=states.get(e['state'],0)+1
print("endpoint states", states)
EOF
grep -E "User time|System time|Maximum resident|Elapsed" "$OUT.time"
rm -f "$OUT" "$OUT.time"
./topo.sh down
