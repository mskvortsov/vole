STA_IFACE = "wlan0"
STA_MAC = "02:00:00:00:00:02"
STA_SSID = "vole"
STA_PSK = "volevole"

AP_IFACE = "uap0"
AP_IP = "192.168.4.1"
AP_PFX = 24
AP_MAC = "02:00:00:00:00:01"
AP_SSID = "wan-test-ap"
AP_PSK = "testtest"

VOLE_WAN_IP = "192.168.4.100"
VOLE_WAN_SUBNET = "192.168.4.0/24"

TUN_IFACE = "dtls0"
TUN_MTU = 1430
TUN_PROTO = "tls13-aes128-ccm-8-sha256"
TUN_PSK = "2QN39+8hAnpByw1WhKnYlg=="
TUN_PORT = 12345
TUN_TIMEOUT = 33

ULA_PREFIX = "fdf7:0fa8:ed0c"

VOLE_LAN_IPV6_PREFIX = f"{ULA_PREFIX}:0000"
VOLE_LAN_IPV6 = f"{VOLE_LAN_IPV6_PREFIX}::1"
VOLE_LAN_IPV6_PFX = 64
TUN_IPV6_PREFIX = f"{ULA_PREFIX}:ffff"
SERVER_TUN_IPV6 = f"{TUN_IPV6_PREFIX}::1"
VOLE_TUN_IPV6 = f"{TUN_IPV6_PREFIX}::2"
TUN_IPV6_PFX = 64

SERVER_TUN_IPV4 = "10.0.0.1"
VOLE_TUN_IPV4 = "10.0.0.2"
TUN_IPV4_PFX = 30

# NVS storage partition offsets for the esp32c6_devkitc partition layout
NVS_OFFSET = 0x3B0000
NVS_SIZE = 0x30000

EXT_IFACE = "eth0"
NAT64_PREFIX = "64:ff9b::/96"
JOOL_NAME = "vole-nat64"

# Namespaces
WIFI_NS = "wifi"  # wlan0 + uap0 + hostapd + dnsmasq + wpa_supplicant
SERVER_NS = "server"  # macvlan internet + tun server + jool + nft

# Simulated internet: isolated veth pair between the two namespaces
INET_VETH_WIFI = "veth-ws"  # in wifi ns
INET_VETH_SRV = "veth-sw"  # in server ns
INET_WIFI_IP = "10.1.0.1"
INET_SRV_IP = "10.1.0.2"
INET_PFX = 24

# Server's real internet interface (for NAT64 pool4 and IPv6 masquerade)
NS_EXT_IFACE = "macvlan-server"

# IPv6 address added to dtls0 for end-to-end reachability test
# wifi ns has no direct route to this — only path is via wlan0 → vole → tun
TEST_IPV6 = "2001:db8::1"


vole_conf = f"""
[lan]
ssid = "vole"
psk = "volevole"
address6 = "{VOLE_LAN_IPV6}/{VOLE_LAN_IPV6_PFX}"
dns6 = [ "2606:4700:4700::64", "2001:4860:4860::64" ]

[wan]
ssid = "{AP_SSID}"
psk = "{AP_PSK}"
http = false

[tun]
mtu = {TUN_MTU}
endpoint = "{INET_SRV_IP}:{TUN_PORT}"
local_port = 54321
address4 = "{VOLE_TUN_IPV4}/{TUN_IPV4_PFX}"
peer4 = "{SERVER_TUN_IPV4}"
address6 = "{VOLE_TUN_IPV6}/{TUN_IPV6_PFX}"
peer6 = "{SERVER_TUN_IPV6}"
cipher_suite = "{TUN_PROTO}"
psk = "{TUN_PSK}"
keepalive = 15
"""

tun_server_conf = f"""
role = "server"
proto = "{TUN_PROTO}"
endpoint = "{INET_SRV_IP}:{TUN_PORT}"
tun = "{TUN_IFACE}"
mtu = {TUN_MTU}
address = "{SERVER_TUN_IPV4}/{TUN_IPV4_PFX}"
psk = "{TUN_PSK}"
timeout = {TUN_TIMEOUT}
"""

hostapd_conf = f"""
interface={AP_IFACE}
driver=nl80211
ssid={AP_SSID}
hw_mode=g
channel=6
ieee80211n=1
wmm_enabled=1
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
wpa=2
wpa_passphrase={AP_PSK}
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
"""

wpa_conf = f"""
ctrl_interface=/run/wpa_supplicant
update_config=1
network={{
    ssid="{STA_SSID}"
    psk="{STA_PSK}"
    key_mgmt=WPA-PSK
}}"""


def dnsmasq_conf(bssid: str) -> str:
    return f"""
port=0
interface={AP_IFACE}
bind-interfaces
except-interface=lo
listen-address={AP_IP}
dhcp-range=192.168.4.10,192.168.4.50,12h
dhcp-host={bssid},{VOLE_WAN_IP}
"""
