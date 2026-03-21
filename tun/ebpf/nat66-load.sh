#!/bin/sh
set -eu

usage() {
	echo "Usage: $0 <wan_iface> <wan_ipv6_addr> <ula_prefix/48>"
	echo
	echo "  wan_iface      WAN interface, e.g. eth0"
	echo "  wan_ipv6_addr  WAN's own IPv6 address, e.g. 2001:db8:face::1"
	echo "  ula_prefix/48  ULA /48 prefix, e.g. fdf7:0fa8:ed0c::/48"
	echo
	echo "Public /64 is derived from the WAN address."
	exit 1
}

[ $# -lt 3 ] && usage

WAN="$1"
WAN_ADDR="$2"
ULA_ARG="$3"
OBJ="$(dirname "$0")/nat66.o"

if [ ! -f "$OBJ" ]; then
	echo "Error: $OBJ not found. Build with: make" >&2
	exit 1
fi

# ── Helpers ──────────────────────────────────────────────────────────────

# Substring: substr STRING OFFSET LENGTH (0-based offset).
substr() {
	echo "$1" | cut -c"$(($2 + 1))"-"$(($2 + $3))"
}

# Expand IPv6 address to full 32 hex chars (no colons).
expand_ipv6() {
	printf '%s\n' "${1%%/*}" | awk '{
		gsub(/\/.*/, "")
		if (index($0, "::")) {
			split($0, h, "::")
			lc = 0; if (h[1] != "") lc = split(h[1], _, ":")
			rc = 0; if (h[2] != "") rc = split(h[2], _, ":")
			mid = ""
			for (i = 0; i < 8 - lc - rc; i++)
				mid = mid (mid == "" ? "" : ":") "0"
			s = ""
			if (h[1] != "") s = h[1]
			if (mid != "") s = s (s == "" ? "" : ":") mid
			if (h[2] != "") s = s (s == "" ? "" : ":") h[2]
			n = split(s, g, ":")
		} else {
			n = split($0, g, ":")
		}
		r = ""
		for (i = 1; i <= n; i++)
			r = r sprintf("%04s", g[i])
		gsub(/ /, "0", r)
		print r
	}'
}

# Convert hex string to space-separated 0xNN bytes for bpftool.
hex_to_bytes() {
	echo "$1" | fold -w2 | while read -r byte; do
		printf '0x%s ' "$byte"
	done
}

# ── Parse WAN address ────────────────────────────────────────────────────

WAN_HEX=$(expand_ipv6 "$WAN_ADDR")
if [ "$(echo "$WAN_HEX" | wc -c)" -ne 33 ]; then  # 32 chars + newline
	echo "Error: failed to parse WAN address '$WAN_ADDR'" >&2
	exit 1
fi

# Public /64 = first 16 hex chars.
PUB64_HEX=$(substr "$WAN_HEX" 0 16)

# ── Parse ULA /48 ───────────────────────────────────────────────────────

ULA_PREFIX="${ULA_ARG%%/*}"
ULA_LEN="${ULA_ARG#*/}"

if [ "$ULA_LEN" != "48" ]; then
	echo "Error: ULA prefix must be /48, got /$ULA_LEN" >&2
	exit 1
fi

ULA_HEX=$(expand_ipv6 "$ULA_PREFIX")
ULA48_HEX=$(substr "$ULA_HEX" 0 12)

# ── Summary ──────────────────────────────────────────────────────────────

echo "WAN interface: $WAN"
echo "WAN address:   $WAN_ADDR"
echo "Public /64:    $(substr "$PUB64_HEX" 0 4):$(substr "$PUB64_HEX" 4 4):$(substr "$PUB64_HEX" 8 4):$(substr "$PUB64_HEX" 12 4)::/64"
echo "ULA /48:       $(substr "$ULA48_HEX" 0 4):$(substr "$ULA48_HEX" 4 4):$(substr "$ULA48_HEX" 8 4)::/48"
echo

# ── Attach BPF ───────────────────────────────────────────────────────────

tc qdisc del dev "$WAN" clsact 2>/dev/null || true
tc qdisc add dev "$WAN" clsact
tc filter add dev "$WAN" egress  bpf da obj "$OBJ" sec tc/egress
tc filter add dev "$WAN" ingress bpf da obj "$OBJ" sec tc/ingress

echo "BPF programs attached."

# ── Populate maps ────────────────────────────────────────────────────────

bpftool map update name pub_prefix \
	key  0x00 0x00 0x00 0x00 \
	value $(hex_to_bytes "$PUB64_HEX")

echo "  pub_prefix set."

bpftool map update name ula_prefix48 \
	key  0x00 0x00 0x00 0x00 \
	value $(hex_to_bytes "${ULA48_HEX}0000")

echo "  ula_prefix48 set."

bpftool map update name wan_addrs \
	key  $(hex_to_bytes "$WAN_HEX") \
	value 0x00

echo "  wan_addrs set."

echo
echo "NAT66 active on $WAN."
echo "New LANs auto-allocate on first packet."
