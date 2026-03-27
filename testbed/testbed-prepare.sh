#!/bin/sh
set -eux

# Prepares a Raspberry Pi 4B for running a network emulation test

# run once

apt install -y uv uhubctl \
    hostapd dnsmasq wpasupplicant dhcpcd5 \
    jool-dkms jool-tools \
    tcpdump iperf3 netperf fping
uv sync

systemctl mask hostapd dnsmasq dhcpcd wpa_supplicant

cat >/etc/NetworkManager/conf.d/unmanaged.conf <<EOF
[keyfile]
unmanaged-devices=interface-name:wlan0;interface-name:uap0
EOF

cat >/etc/sysctl.d/00-forwarding.conf <<EOF
net.ipv4.conf.all.forwarding = 1
net.ipv6.conf.all.forwarding = 1
EOF

echo jool >/etc/modules-load.d/jool.conf

# apply without reboot

nmcli general reload
sysctl -p /etc/sysctl.d/00-forwarding.conf
modprobe jool
