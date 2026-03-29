import os
import shutil
import subprocess
import sys
import threading
import time
from contextlib import ExitStack
from importlib.metadata import version

import esptool

import testbed.config as cfg
import testbed.device as dev
import testbed.net as net
import testbed.proc as proc


def make_output_dir() -> str:
    import re

    existing = [m.group(1) for e in os.listdir() if (m := re.fullmatch(r"output-(\d+)", e))]
    n = max((int(x) for x in existing), default=0) + 1
    path = f"output-{n:04d}"
    os.mkdir(path)
    return path


def main() -> None:
    print("testbed", version("testbed"))

    if len(sys.argv) != 4:
        print("usage: python -m testbed path/to/tun-executable /dev/ttyPORT firmware.bin")
        sys.exit(1)

    tun_executable = sys.argv[1]
    device = sys.argv[2]
    firmware_path = sys.argv[3]

    subprocess.run(("uname", "-a"), check=True)
    print("jool ", end="", flush=True)
    subprocess.run(("jool", "--version"), check=True)
    subprocess.run(("nft", "--version"), check=True)

    try:
        subprocess.run((tun_executable, "--version"), check=True)
    except FileNotFoundError:
        print(f"{tun_executable} doesn't exist or not found in PATH")
        sys.exit(1)
    except PermissionError:
        print(f"{tun_executable} exists but not executable")
        sys.exit(1)

    if not os.path.isfile(firmware_path):
        print(f"{firmware_path} file doesn't exist")
        sys.exit(1)

    output_dir = make_output_dir()

    deadline = time.monotonic() + 3
    while not os.path.exists(device):
        if time.monotonic() >= deadline:
            print(f"{device} did not appear within 3 seconds")
            sys.exit(1)
        time.sleep(0.1)

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
    log_thread = threading.Thread(target=dev.read_device_log, args=(device_fd, os.path.join(output_dir, "device.log")), daemon=True)
    dev.reset_device(device_fd, on_release=log_thread.start)

    try:
        with ExitStack() as stack:
            stack.enter_context(net.setup_netns())
            net.setup_interfaces()
            stack.enter_context(proc.start_sta(output_dir))
            stack.enter_context(proc.start_tun(tun_executable, output_dir))

            stack.enter_context(net.setup_network())
            proc.wait_sta_associated()
            proc.wait_slaac()

            vole_wan_bssid = proc.get_status()["wan"]["hwaddr"]
            stack.enter_context(proc.start_ap(vole_wan_bssid, output_dir))

            tcpdump_ap = net.start(
                "tcpdump",
                "--immediate-mode",
                f"--interface={cfg.AP_IFACE}",
                "-w",
                os.path.join(output_dir, f"{cfg.AP_IFACE}.pcap"),
                ns=cfg.WIFI_NS,
                log=os.path.join(output_dir, "tcpdump-ap.log"),
            )
            stack.callback(tcpdump_ap.terminate)
            tcpdump_tun = net.start(
                "tcpdump",
                "--immediate-mode",
                f"--interface={cfg.TUN_IFACE}",
                "-w",
                os.path.join(output_dir, f"{cfg.TUN_IFACE}.pcap"),
                ns=cfg.SERVER_NS,
                log=os.path.join(output_dir, "tcpdump-tun.log"),
            )
            stack.callback(tcpdump_tun.terminate)

            proc.post_config(cfg.vole_conf)
            proc.wait_ap_associated(vole_wan_bssid)
            proc.wait_ipv6_reachable()

            tcpdump_ap.terminate()
            tcpdump_tun.terminate()

            iperf3_server = net.start("iperf3", "-s", ns=cfg.SERVER_NS)
            stack.callback(iperf3_server.terminate)
            time.sleep(1)
            iperf3_client = net.start("iperf3", "-c", cfg.TEST_IPV6, ns=cfg.WIFI_NS, log=os.path.join(output_dir, "iperf3.log"))
            stack.callback(iperf3_client.terminate)
            iperf3_client.wait(20)
            iperf3_server.terminate()

            netserver = net.start("netserver", "-D", ns=cfg.SERVER_NS, log=os.path.join(output_dir, "netserver.log"))
            stack.callback(netserver.terminate)
            time.sleep(1)

            flent_exec = shutil.which("flent") or os.path.join(os.path.dirname(sys.executable), "flent")
            net.run(flent_exec, "rrul", f"--data-dir={output_dir}", f"--host={cfg.TEST_IPV6}", "--length=20", ns=cfg.WIFI_NS)

    except Exception as e:
        print(e, file=sys.stderr)
        sys.exit(1)
    finally:
        os.close(device_fd)
