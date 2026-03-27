import json
import os
import subprocess
import time
from contextlib import ExitStack

import testbed.config as cfg
from testbed.device import ts
from testbed.net import output, run, start


def start_sta(output_dir: str) -> ExitStack:
    stack = ExitStack()
    with stack:
        wpa = start(
            "wpa_supplicant",
            "-i",
            cfg.STA_IFACE,
            "-c",
            "/dev/stdin",
            ns=cfg.WIFI_NS,
            log=os.path.join(output_dir, "wpa_supplicant.log"),
            stdin=subprocess.PIPE,
        )
        assert wpa.stdin is not None
        wpa.stdin.write(cfg.wpa_conf)
        wpa.stdin.close()
        stack.callback(wpa.terminate)
        stack.callback(run, "ip", "addr", "flush", "dev", cfg.STA_IFACE, ns=cfg.WIFI_NS)
        return stack.pop_all()


def start_tun(tun_executable: str, output_dir: str) -> ExitStack:
    stack = ExitStack()
    with stack:
        print(ts(), cfg.tun_server_conf)
        tun = start(tun_executable, "-", ns=cfg.SERVER_NS, log=os.path.join(output_dir, "tun.log"),
                    stdin_data=cfg.tun_server_conf, wait_for="listening")
        stack.callback(tun.terminate)
        return stack.pop_all()


def start_ap(vole_wan_bssid: str, output_dir: str) -> ExitStack:
    stack = ExitStack()
    with stack:
        hostapd = start("hostapd", "/dev/stdin", ns=cfg.WIFI_NS, log=os.path.join(output_dir, "hostapd.log"), stdin=subprocess.PIPE)
        assert hostapd.stdin is not None
        hostapd.stdin.write(cfg.hostapd_conf)
        hostapd.stdin.close()
        stack.callback(hostapd.terminate)
        dnsmasq = start(
            "dnsmasq",
            "--keep-in-foreground",
            "--conf-file=/dev/stdin",
            ns=cfg.WIFI_NS,
            log=os.path.join(output_dir, "dnsmasq.log"),
            stdin=subprocess.PIPE,
        )
        assert dnsmasq.stdin is not None
        dnsmasq.stdin.write(cfg.dnsmasq_conf(vole_wan_bssid))
        dnsmasq.stdin.close()
        stack.callback(dnsmasq.terminate)
        stack.callback(run, "iw", "dev", cfg.AP_IFACE, "del", ns=cfg.WIFI_NS)
        return stack.pop_all()


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
        out = output("wpa_cli", "-i", cfg.STA_IFACE, "status", check=False, ns=cfg.WIFI_NS)
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
        out = output("hostapd_cli", "-i", cfg.AP_IFACE, "sta", bssid, check=False, ns=cfg.WIFI_NS)
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
