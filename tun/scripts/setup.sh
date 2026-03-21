#!/bin/sh -ex

# https://www.jool.mx/en/documentation.html
# apt install jool-dkms jool-tools

# you have to to change these settings:

# interface connected to the Internet
EXT_IFACE=eth0
# and its public IPv4 address
EXT_IPV4=192.0.2.1
# tunnel interface created by tun server
TUN_IFACE=dtls0
# should align with tun.address6 from vole config
TUN_IPV6=fdf7:0fa8:ed0c:ffff::1/64
# should align with lan.address6
VOLE_LAN_PREFIX=fdf7:0fa8:ed0c:0::/64
# curl --silent http://10.0.0.2/api/status | jq .wan.address
VOLE_WAN_SUBNET=192.168.1.0/24
VOLE_WAN_IPV4=192.168.1.100

if [ "$EXT_IPV4" = "192.0.2.1" ]; then
    echo "Please edit the settings first"
    exit 1
fi

# you most probably don't need to change these:

# https://datatracker.ietf.org/doc/html/rfc6052
NAT64_PREFIX=64:ff9b::/96
# arbitrary name for jool instance
JOOL_NAME="vole-nat64"

uname -a
jool --version
nft --version

# Forwarding

sysctl -w net.ipv4.conf.all.forwarding=1
sysctl -w net.ipv6.conf.all.forwarding=1

# Routing

ip -6 address add $TUN_IPV6        dev $TUN_IFACE
ip -6 route   add $VOLE_LAN_PREFIX dev $TUN_IFACE
ip -4 route   add $VOLE_WAN_SUBNET dev $TUN_IFACE

# NAT64

modprobe jool

jool instance add "$JOOL_NAME" --netfilter --pool6 $NAT64_PREFIX
jool --instance "$JOOL_NAME" instance display

jool --instance "$JOOL_NAME" pool4 add --tcp  $EXT_IPV4 61000-63000
jool --instance "$JOOL_NAME" pool4 add --udp  $EXT_IPV4 61000-63000
jool --instance "$JOOL_NAME" pool4 add --icmp $EXT_IPV4 1-65535
jool --instance "$JOOL_NAME" pool4 display

# NAT66

nft -f - <<EOF
create table ip6 vole_lan_masq {
    chain postrouting {
        type nat hook postrouting priority srcnat;
        oifname $EXT_IFACE ip6 saddr $VOLE_LAN_PREFIX ip6 daddr != $NAT64_PREFIX masquerade
    }
}
EOF

# Source NAT for accessing vole's WAN from the server side

nft -f - <<EOF
create table ip vole_wan_snat {
    chain postrouting {
        type nat hook postrouting priority srcnat;
        oifname $TUN_IFACE ip daddr $VOLE_WAN_SUBNET snat to $VOLE_WAN_IPV4
    }
}
EOF
