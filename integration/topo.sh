#!/usr/bin/env bash
# Test topology for mpmtr integration tests (needs root):
#
#   mpsrc ══ mpr0 ═╦═ mpr1 ═╗
#                  ╠═ mpr2 ═╣
#                  ╠═ mpr3 ═╬═ mprd ── mpdst
#                  ╚═ mpr4 ═╝
#
# mpr0 and mprd do ECMP on the 5-tuple for IPv4 and IPv6 in both directions.
# The hash is computed from the packet's own fields (policy 3): with policy 1
# the kernel reuses the hash the sending socket put on the packet, which
# survives a veth, so every SYN/ACK of a server would take an arm of its own.
# Neighbours on the links are permanent, so that loss put on one direction of
# a link does not also stop the other by losing its ARP or ND answers.
# ICMP rate limiting is disabled by default.
#
#   topo.sh up | down
set -euo pipefail
NS=(mpsrc mpr0 mpr1 mpr2 mpr3 mpr4 mprd mpdst)
x() { ip netns exec "$1" "${@:2}"; }

down() {
	for n in "${NS[@]}"; do ip netns del "$n" 2>/dev/null || true; done
}

link() { # nsA devA addrA4 addrA6 nsB devB addrB4 addrB6
	ip link add "$2" netns "$1" type veth peer name "$6" netns "$5"
	x "$1" ip addr add "$3" dev "$2"; x "$1" ip -6 addr add "$4" dev "$2" nodad
	x "$5" ip addr add "$7" dev "$6"; x "$5" ip -6 addr add "$8" dev "$6" nodad
	x "$1" ip link set "$2" up; x "$5" ip link set "$6" up
	local ma mb
	ma=$(x "$1" cat "/sys/class/net/$2/address"); mb=$(x "$5" cat "/sys/class/net/$6/address")
	x "$1" ip neigh replace "${7%/*}" lladdr "$mb" dev "$2" nud permanent
	x "$1" ip -6 neigh replace "${8%/*}" lladdr "$mb" dev "$2" nud permanent
	x "$5" ip neigh replace "${3%/*}" lladdr "$ma" dev "$6" nud permanent
	x "$5" ip -6 neigh replace "${4%/*}" lladdr "$ma" dev "$6" nud permanent
}

up() {
	down
	for n in "${NS[@]}"; do
		ip netns add "$n"
		x "$n" ip link set lo up
		x "$n" sysctl -qw net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1
		x "$n" sysctl -qw net.ipv4.icmp_ratelimit=0 net.ipv6.icmp.ratelimit=0
		# source and destination address, protocol, source and destination port
		x "$n" sysctl -qw net.ipv4.fib_multipath_hash_fields=0x37 net.ipv6.fib_multipath_hash_fields=0x37
		x "$n" sysctl -qw net.ipv4.fib_multipath_hash_policy=3 net.ipv6.fib_multipath_hash_policy=3
		x "$n" sysctl -qw net.ipv6.conf.all.accept_dad=0 net.ipv6.conf.default.accept_dad=0
	done
	link mpsrc s0 10.10.0.2/24 fd10::2/64 mpr0 r0s 10.10.0.1/24 fd10::1/64
	# second source link, used by the local-ECMP test
	link mpsrc s1 10.10.1.2/24 fd10:1::2/64 mpr0 r0t 10.10.1.1/24 fd10:1::1/64
	for i in 1 2 3 4; do
		link mpr0 r0b$i 10.11.$i.1/24 fd11:$i::1/64 mpr$i r${i}a 10.11.$i.2/24 fd11:$i::2/64
		link mpr$i r${i}b 10.12.$i.1/24 fd12:$i::1/64 mprd rd$i 10.12.$i.2/24 fd12:$i::2/64
		x mpr$i ip route add 10.20.0.0/24 via 10.12.$i.2
		x mpr$i ip route add 10.10.0.0/16 via 10.11.$i.1
		x mpr$i ip -6 route add fd20::/64 via fd12:$i::2
		x mpr$i ip -6 route add fd10::/16 via fd11:$i::1
		# ICMP errors from mprd use the address of its egress interface;
		# make those sources routable so loose rp_filter keeps them.
		x mpr$i ip route add 10.12.0.0/16 via 10.12.$i.2
		x mpr$i ip -6 route add fd12::/16 via fd12:$i::2
	done
	link mprd rdd 10.20.0.1/24 fd20::1/64 mpdst d0 10.20.0.2/24 fd20::2/64
	x mpsrc ip route add default via 10.10.0.1
	x mpsrc ip -6 route add default via fd10::1
	x mpdst ip route add default via 10.20.0.1
	x mpdst ip -6 route add default via fd20::1
	x mpr0 ip route add 10.20.0.0/24 nexthop via 10.11.1.2 nexthop via 10.11.2.2 nexthop via 10.11.3.2 nexthop via 10.11.4.2
	x mprd ip route add 10.10.0.0/16 nexthop via 10.12.1.1 nexthop via 10.12.2.1 nexthop via 10.12.3.1 nexthop via 10.12.4.1
	x mpr0 ip -6 route add fd20::/64 nexthop via fd11:1::2 nexthop via fd11:2::2 nexthop via fd11:3::2 nexthop via fd11:4::2
	x mpr0 ip route add 10.12.0.0/16 nexthop via 10.11.1.2 nexthop via 10.11.2.2 nexthop via 10.11.3.2 nexthop via 10.11.4.2
	x mpr0 ip -6 route add fd12::/16 nexthop via fd11:1::2 nexthop via fd11:2::2 nexthop via fd11:3::2 nexthop via fd11:4::2
	x mprd ip -6 route add fd10::/16 nexthop via fd12:1::1 nexthop via fd12:2::1 nexthop via fd12:3::1 nexthop via fd12:4::1
}

"$@"
