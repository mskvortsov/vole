import json
import subprocess
import time

import testbed.config as cfg
from testbed.device import ts
from testbed.net import output, start


def start_sta() -> subprocess.Popen:
    wpa = start("wpa_supplicant", "-i", cfg.STA_IFACE, "-c", "/dev/stdin", ns=cfg.WIFI_NS, stdin=subprocess.PIPE, text=True)
    assert wpa.stdin is not None
    wpa.stdin.write(cfg.wpa_conf)
    wpa.stdin.close()
    return wpa


def start_tun(tun_executable: str) -> subprocess.Popen:
    tun = start(tun_executable, "-", ns=cfg.SERVER_NS, stdin=subprocess.PIPE, text=True)
    assert tun.stdin is not None
    print(ts(), cfg.tun_server_conf)
    tun.stdin.write(cfg.tun_server_conf)
    tun.stdin.close()
    return tun


def start_ap(vole_wan_bssid: str) -> tuple[subprocess.Popen, subprocess.Popen]:
    hostapd = start("hostapd", "/dev/stdin", ns=cfg.WIFI_NS, stdin=subprocess.PIPE, text=True)
    assert hostapd.stdin is not None
    hostapd.stdin.write(cfg.hostapd_conf)
    hostapd.stdin.close()
    dnsmasq = start("dnsmasq", "--keep-in-foreground", "--conf-file=/dev/stdin", ns=cfg.WIFI_NS, stdin=subprocess.PIPE, text=True)
    assert dnsmasq.stdin is not None
    dnsmasq.stdin.write(cfg.dnsmasq_conf(vole_wan_bssid))
    dnsmasq.stdin.close()
    return hostapd, dnsmasq


def get_status(timeout: int = 30) -> dict:
    url = f"http://[{cfg.VOLE_LAN_IPV6}]/api/status"
    for _ in range(timeout):
        try:
            data = output("curl", "-sf", url, ns=cfg.WIFI_NS)
            print(ts(), data)
            return json.loads(data)
        except (subprocess.CalledProcessError, json.JSONDecodeError):
            time.sleep(1)
    raise RuntimeError("vole: HTTP API not reachable")


def post_config(config: str) -> None:
    url = f"http://[{cfg.VOLE_LAN_IPV6}]/api/config"
    print(ts(), config)
    result = subprocess.run(
        ("ip", "netns", "exec", cfg.WIFI_NS, "curl", "-sf", "-X", "POST", "--data-binary", "@-", url),
        input=config,
        text=True,
        check=True,
        capture_output=True,
    )
    print(ts(), result.stdout)


def wait_sta_associated(timeout: int = 15) -> None:
    for _ in range(timeout):
        out = output("wpa_cli", "-i", cfg.STA_IFACE, "status", ns=cfg.WIFI_NS)
        for line in out.splitlines():
            if line.startswith("wpa_state="):
                if line.split("=", 1)[1] == "COMPLETED":
                    return
        time.sleep(1)
    raise RuntimeError("STA: association timed out")


def wait_slaac(timeout: int = 30) -> None:
    for _ in range(timeout):
        all_global = output("ip", "-6", "addr", "show", "dev", cfg.STA_IFACE, "scope", "global", ns=cfg.WIFI_NS)
        tentative = output("ip", "-6", "addr", "show", "dev", cfg.STA_IFACE, "scope", "global", "tentative", ns=cfg.WIFI_NS)
        addrs = [line.split()[1] for line in all_global.splitlines() if "inet6" in line]
        if addrs and not tentative.strip():
            print(ts(), f"STA IPv6: {', '.join(addrs)}", flush=True)
            return
        time.sleep(1)
    raise RuntimeError("STA: IPv6 SLAAC timed out")


def wait_ap_associated(bssid: str, timeout: int = 30) -> None:
    for _ in range(timeout):
        out = output("hostapd_cli", "-i", cfg.AP_IFACE, "sta", bssid, ns=cfg.WIFI_NS)
        if "FAIL" not in out:
            return
        time.sleep(1)
    raise RuntimeError("AP: vole association timed out")


def wait_ipv6_reachable(timeout: int = 30) -> None:
    for _ in range(timeout):
        result = subprocess.run(
            ("ip", "netns", "exec", cfg.WIFI_NS, "ping6", "-c1", "-W1", "-I", cfg.STA_IFACE, cfg.TEST_IPV6),
            capture_output=True,
        )
        if result.returncode == 0:
            print(ts(), f"tun reachable: {cfg.STA_IFACE} -> {cfg.TEST_IPV6}", flush=True)
            return
        time.sleep(1)
    raise RuntimeError(f"tun: {cfg.TEST_IPV6} not reachable via {cfg.STA_IFACE}")
