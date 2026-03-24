import os
import subprocess
import sys
import threading
import time
from contextlib import ExitStack

import esptool

import testbed.config as cfg
import testbed.device as dev
import testbed.net as net
import testbed.proc as proc


def main() -> None:
    if len(sys.argv) != 4:
        print("usage: python -m testbed path/to/tun-executable /dev/ttyPORT firmware.bin")
        sys.exit(1)

    tun_executable = sys.argv[1]
    device = sys.argv[2]
    firmware_path = sys.argv[3]

    try:
        _ = subprocess.run((tun_executable, "genpsk"), stdout=subprocess.DEVNULL, check=True)
    except FileNotFoundError:
        print(f"{tun_executable} doesn't exist or not found in PATH")
        sys.exit(1)
    except PermissionError:
        print(f"{tun_executable} exists but not executable")
        sys.exit(1)

    if not os.path.isfile(firmware_path):
        print(f"{firmware_path} file doesn't exist")
        sys.exit(1)

    with esptool.detect_chip(device) as esp:
        esp = esptool.run_stub(esp)
        esptool.attach_flash(esp)
        # write flash only if a digest differs
        with open(firmware_path, "rb") as firmware_file:
            try:
                esptool.verify_flash(esp, [(0, firmware_file)])
            except esptool.FatalError:
                esptool.write_flash(esp, [(0, firmware_file)])
        # erase Zephyr's storage partition
        esptool.erase_region(esp, cfg.NVS_OFFSET, cfg.NVS_SIZE)

    device_fd = dev.open_device(device)
    log_thread = threading.Thread(target=dev.read_device_log, args=(device_fd,), daemon=True)
    dev.reset_device(device_fd, on_release=log_thread.start)

    try:
        with ExitStack() as stack:
            net.setup_netns()
            stack.callback(net.run, "ip", "netns", "del", cfg.SERVER_NS)
            stack.callback(net.run, "ip", "netns", "del", cfg.WIFI_NS)
            stack.callback(net.run, "dhcpcd", "-k", cfg.NS_EXT_IFACE, ns=cfg.SERVER_NS)

            net.setup_interfaces()
            wpa = proc.start_sta()
            tun = proc.start_tun(tun_executable)
            stack.callback(tun.terminate)
            stack.callback(wpa.terminate)
            stack.callback(net.run, "ip", "addr", "flush", "dev", cfg.STA_IFACE, ns=cfg.WIFI_NS)

            net.setup_network()
            proc.wait_sta_associated()
            proc.wait_slaac()

            vole_wan_bssid = proc.get_status()["wan"]["bssid"]
            hostapd, dnsmasq = proc.start_ap(vole_wan_bssid)
            stack.callback(net.run, "iw", "dev", cfg.AP_IFACE, "del", ns=cfg.WIFI_NS)
            stack.callback(hostapd.terminate)
            stack.callback(dnsmasq.terminate)

            tcpdump_ap = net.start("tcpdump", "-i", cfg.AP_IFACE, "-w", f"{cfg.AP_IFACE}.pcap", "--immediate-mode", ns=cfg.WIFI_NS)
            stack.callback(tcpdump_ap.terminate)
            tcpdump_tun = net.start("tcpdump", "-i", cfg.TUN_IFACE, "-w", f"{cfg.TUN_IFACE}.pcap", "--immediate-mode", ns=cfg.SERVER_NS)
            stack.callback(tcpdump_tun.terminate)

            proc.post_config(cfg.vole_conf)
            proc.wait_ap_associated(vole_wan_bssid)
            proc.wait_ipv6_reachable()

            iperf3_server = net.start("iperf3", "-s", ns=cfg.SERVER_NS)
            stack.callback(iperf3_server.terminate)
            time.sleep(1)
            net.run("iperf3", "-c", cfg.TEST_IPV6, ns=cfg.WIFI_NS)
    except Exception as e:
        print(e, file=sys.stderr)
        sys.exit(1)
    finally:
        os.close(device_fd)
