import subprocess
import threading
import time
from contextlib import ExitStack

import testbed.config as cfg
from testbed.device import ts


def _ns_cmd(ns: str | None, cmd: tuple[str, ...]) -> tuple[str, ...]:
    return ("ip", "netns", "exec", ns) + cmd if ns else cmd


def run(*cmd: str, check: bool = True, ns: str | None = None) -> None:
    cmd_full = _ns_cmd(ns, cmd)
    print(ts(), "+", *cmd_full, flush=True)
    subprocess.run(cmd_full, check=check)


def _log_output(proc: subprocess.Popen, path: str, ready: threading.Event | None = None, wait_for: str | None = None) -> None:
    assert proc.stdout is not None
    with open(path, "w") as f:
        for line in proc.stdout:
            f.write(ts() + " " + line)
            f.flush()
            if ready is not None and wait_for in line:
                ready.set()
                ready = None


def start(
    *cmd: str, ns: str | None = None, log: str | None = None, wait_for: str | None = None, stdin_data: str | None = None, **kwargs
) -> subprocess.Popen:
    cmd_full = _ns_cmd(ns, cmd)
    print(ts(), "+", *cmd_full, flush=True)
    if log is not None:
        kwargs["stdout"] = subprocess.PIPE
        kwargs["stderr"] = subprocess.STDOUT
        kwargs["text"] = True
    if stdin_data is not None:
        kwargs["stdin"] = subprocess.PIPE
    proc = subprocess.Popen(cmd_full, **kwargs)
    if stdin_data is not None:
        assert proc.stdin is not None
        proc.stdin.write(stdin_data)
        proc.stdin.close()
    if log is not None:
        ready = threading.Event() if wait_for is not None else None
        threading.Thread(target=_log_output, args=(proc, log, ready, wait_for), daemon=True).start()
        if ready is not None:
            ready.wait()
    return proc


def output(*cmd: str, check: bool = True, ns: str | None = None) -> str:
    cmd_full = _ns_cmd(ns, cmd)
    return subprocess.run(cmd_full, capture_output=True, text=True, check=check).stdout


def nft(rules: str, *, ns: str) -> None:
    cmd_full = _ns_cmd(ns, ("nft", "-f", "-"))
    print(ts(), "+", *cmd_full, flush=True)
    subprocess.run(cmd_full, input=rules, text=True, check=True)


# ┌──────────────────────────wifi─┐         ┌───────────────────────server─┐   ┌───host─┐
# │ wlan0 (STA → vole LAN)        │         │              macvlan-server =├───┤= eth0 =├─── Internet
# │ uap0  (AP  ← vole WAN)        │         │  ./tun → dtls0               │   └────────┘
# │ SNAT vole WAN → veth-ws       │         │  jool, nft                   │
# │         10.1.0.1/24  veth-ws =├─────────┤= veth-sw  10.1.0.2/24        │
# └───────────────────────────────┘  inet   └──────────────────────────────┘


def setup_netns() -> ExitStack:
    stack = ExitStack()
    with stack:
        run("ip", "netns", "add", cfg.WIFI_NS)
        stack.callback(run, "ip", "netns", "del", cfg.WIFI_NS)

        run("ip", "netns", "add", cfg.SERVER_NS)
        stack.callback(run, "ip", "netns", "del", cfg.SERVER_NS)

        # Simulated internet: isolated veth pair, no connection to host eth0
        with ExitStack() as pre_move:
            run("ip", "link", "add", cfg.INET_VETH_WIFI, "type", "veth", "peer", "name", cfg.INET_VETH_SRV)
            pre_move.callback(run, "ip", "link", "del", cfg.INET_VETH_WIFI)
            run("ip", "link", "set", cfg.INET_VETH_WIFI, "netns", cfg.WIFI_NS)
            run("ip", "link", "set", cfg.INET_VETH_SRV, "netns", cfg.SERVER_NS)
            pre_move.pop_all()

        run("ip", "link", "set", cfg.INET_VETH_WIFI, "up", ns=cfg.WIFI_NS)
        run("ip", "addr", "add", f"{cfg.INET_WIFI_IP}/{cfg.INET_PFX}", "dev", cfg.INET_VETH_WIFI, ns=cfg.WIFI_NS)
        run("ip", "link", "set", cfg.INET_VETH_SRV, "up", ns=cfg.SERVER_NS)
        run("ip", "addr", "add", f"{cfg.INET_SRV_IP}/{cfg.INET_PFX}", "dev", cfg.INET_VETH_SRV, ns=cfg.SERVER_NS)

        # Server namespace: macvlan on eth0 for real internet (NAT64 pool, IPv6 masquerade)
        with ExitStack() as pre_move:
            run("ip", "link", "add", cfg.NS_EXT_IFACE, "link", cfg.EXT_IFACE, "type", "macvlan", "mode", "bridge")
            pre_move.callback(run, "ip", "link", "del", cfg.NS_EXT_IFACE)
            run("ip", "link", "set", cfg.NS_EXT_IFACE, "netns", cfg.SERVER_NS)
            pre_move.pop_all()

        run("ip", "link", "set", cfg.NS_EXT_IFACE, "up", ns=cfg.SERVER_NS)
        run("dhcpcd", "--config", "/dev/null", "--nohook", "resolv.conf", "--hostname=testbed", cfg.NS_EXT_IFACE, ns=cfg.SERVER_NS)
        stack.callback(run, "dhcpcd", "--release", cfg.NS_EXT_IFACE, ns=cfg.SERVER_NS)

        return stack.pop_all()


def setup_interfaces() -> None:
    with ExitStack() as pre_move:
        links = output("ip", "link", "show", cfg.AP_IFACE, check=False)
        if cfg.AP_IFACE not in links:
            run("iw", "dev", cfg.STA_IFACE, "interface", "add", cfg.AP_IFACE, "type", "__ap")
            pre_move.callback(run, "iw", "dev", cfg.AP_IFACE, "del")

        run("ip", "link", "set", cfg.STA_IFACE, "address", cfg.STA_MAC)
        run("ip", "link", "set", cfg.AP_IFACE, "address", cfg.AP_MAC)
        with open(f"/sys/class/net/{cfg.STA_IFACE}/phy80211/name") as f:
            phy = f.read().strip()
        run("iw", "phy", phy, "set", "netns", "name", cfg.WIFI_NS)
        pre_move.pop_all()

    run("ip", "link", "set", cfg.AP_IFACE, "up", ns=cfg.WIFI_NS)
    run("ip", "addr", "replace", f"{cfg.AP_IP}/{cfg.AP_PFX}", "dev", cfg.AP_IFACE, ns=cfg.WIFI_NS)


def setup_network() -> ExitStack:
    stack = ExitStack()
    with stack:
        run("ip", "-6", "address", "add", f"{cfg.SERVER_TUN_IPV6}/{cfg.TUN_IPV6_PFX}", "dev", cfg.TUN_IFACE, ns=cfg.SERVER_NS)
        run("ip", "-6", "address", "add", f"{cfg.TEST_IPV6}/128", "dev", cfg.TUN_IFACE, ns=cfg.SERVER_NS)
        run("ip", "-6", "route", "add", f"{cfg.VOLE_LAN_IPV6_PREFIX}::/{cfg.VOLE_LAN_IPV6_PFX}", "dev", cfg.TUN_IFACE, ns=cfg.SERVER_NS)

        ext_ipv4 = None
        for _ in range(30):
            tokens = output("ip", "-4", "-o", "addr", "show", "dev", cfg.NS_EXT_IFACE, ns=cfg.SERVER_NS).split()
            ext_ipv4 = next((t.split("/")[0] for t in tokens if "/" in t and t[0].isdigit()), None)
            if ext_ipv4:
                break
            time.sleep(1)
        if not ext_ipv4:
            addr_out = output("ip", "addr", "show", "dev", cfg.NS_EXT_IFACE, ns=cfg.SERVER_NS)
            raise RuntimeError(f"dhcpcd: {cfg.NS_EXT_IFACE} did not get an IPv4 address\n{addr_out}")

        run("jool", "instance", "add", cfg.JOOL_NAME, "--netfilter", "--pool6", cfg.NAT64_PREFIX, ns=cfg.SERVER_NS)
        stack.callback(run, "jool", "instance", "remove", cfg.JOOL_NAME, ns=cfg.SERVER_NS)
        run("jool", "instance", "display", ns=cfg.SERVER_NS)
        run("jool", "--instance", cfg.JOOL_NAME, "pool4", "add", "--tcp", ext_ipv4, "61000-63000", ns=cfg.SERVER_NS)
        run("jool", "--instance", cfg.JOOL_NAME, "pool4", "add", "--udp", ext_ipv4, "61000-63000", ns=cfg.SERVER_NS)
        run("jool", "--instance", cfg.JOOL_NAME, "pool4", "add", "--icmp", ext_ipv4, "1-65535", ns=cfg.SERVER_NS)
        run("jool", "--instance", cfg.JOOL_NAME, "pool4", "display", ns=cfg.SERVER_NS)

        # IPv6 masquerade for vole LAN traffic going to real internet via macvlan
        nft(
            f"""
            create table ip6 vole_lan_masq {{
                chain postrouting {{
                    type nat hook postrouting priority srcnat;
                    oifname "{cfg.NS_EXT_IFACE}"
                        ip6 saddr {cfg.VOLE_LAN_IPV6_PREFIX}::/{cfg.VOLE_LAN_IPV6_PFX}
                        ip6 daddr != {cfg.NAT64_PREFIX}
                        masquerade;
                }}
            }}
            """,
            ns=cfg.SERVER_NS,
        )
        stack.callback(run, "nft", "delete", "table", "ip6", "vole_lan_masq", ns=cfg.SERVER_NS)

        # SNAT vole's WAN traffic onto the simulated internet
        nft(
            f"""
            create table ip vole_wan_snat {{
                chain postrouting {{
                    type nat hook postrouting priority srcnat;
                    oifname "{cfg.INET_VETH_WIFI}" masquerade;
                }}
            }}
            """,
            ns=cfg.WIFI_NS,
        )
        stack.callback(run, "nft", "delete", "table", "ip", "vole_wan_snat", ns=cfg.WIFI_NS)

        return stack.pop_all()
