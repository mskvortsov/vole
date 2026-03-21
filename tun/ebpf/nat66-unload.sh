#!/bin/sh
set -eu

usage() {
	echo "Usage: $0 <wan_iface>"
	echo
	echo "Removes NAT66 BPF programs and maps from the specified interface."
	echo "All active NAT66 sessions will be dropped immediately."
	exit 1
}

[ $# -lt 1 ] && usage

WAN="$1"

# Removing clsact detaches both ingress and egress BPF programs.
# Maps are not pinned, so the kernel frees them when program refcount
# reaches zero — no manual map cleanup needed.

if tc qdisc del dev "$WAN" clsact 2>/dev/null; then
	echo "NAT66 removed from $WAN."
else
	echo "No clsact qdisc found on $WAN (already clean)."
fi
