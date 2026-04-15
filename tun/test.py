import select
import signal
import subprocess
import sys
import time

import tomllib

executable_path = ""
verbose = False
namespaces = []
processes = {}


def log(message: str):
    if not verbose:
        return
    if sys.stdout.isatty():
        print("\033[32m" + message + "\033[0m")
    else:
        print("# " + message)


def create_ns(ns: str):
    subprocess.run(["ip", "netns", "add", ns])
    subprocess.run(["ip", "netns", "exec", ns, "ip", "link", "set", "dev", "lo", "up"])
    namespaces.append(ns)


def delete_all_ns():
    for ns in namespaces:
        subprocess.run(["ip", "netns", "del", ns])


def spawn(config: str) -> subprocess.Popen:
    process = subprocess.Popen(
        [executable_path, "-"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )
    c = tomllib.loads(config)
    role = c["role"]
    log(f"running {role} {c['endpoint']} pid {process.pid}")
    assert process.stdin
    process.stdin.write(config)
    process.stdin.close()
    processes[process] = role
    return process


def terminate(process: subprocess.Popen):
    log(f"terminating pid {process.pid}")
    assert process.poll() is None
    readable, _, _ = select.select([process.stderr], [], [], 0)
    assert not readable
    process.send_signal(signal.SIGINT)
    log("checking exit code is 0")
    assert process.wait(None) == 0


def terminated(process: subprocess.Popen, exit_code: int):
    log(f"checking {processes[process]} pid {process.pid} has been terminated")
    process.wait(1)
    assert process.poll() is not None
    assert process.stderr
    assert not process.stderr.read()
    log(f"checking exit code is {exit_code}")
    assert process.returncode == exit_code


def killall():
    for process, role in processes.items():
        log(f"killing {role} pid {process.pid}")
        process.terminate()
        process.wait()


def assert_line_generic(process: subprocess.Popen, tag: str, err: bool, timeout: int):
    log(f'looking for "{tag}" for {processes[process]} pid {process.pid}')
    assert process.stderr and process.stdout
    start_time = time.time()
    while True:
        elapsed = time.time() - start_time
        remaining = timeout - elapsed

        assert remaining > 0  # timeout

        line = process.stderr.readline() if err else process.stdout.readline()
        if verbose:
            print(line, end="")
        if tag in line:
            return


def assert_line(process: subprocess.Popen, tag: str, timeout=3):
    assert_line_generic(process, tag, False, timeout)


def assert_line_err(process: subprocess.Popen, tag: str, timeout=3):
    assert_line_generic(process, tag, True, timeout)


def run(cmd: str):
    args = cmd.split(" ")
    process = subprocess.run(
        args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )
    assert process.returncode == 0
    return process


conf_server = """
role = "server"
proto = "tls13-chacha20-poly1305-sha256"
endpoint = "127.0.0.1:12345"
tun = "dtls1"
address = "10.8.0.1/30"
psk = "0qhQoLAvfOukhP0NqGVOuQ=="
privdrop = "nogroup:nobody"
"""

conf_client = """
role = "client"
proto = "tls13-chacha20-poly1305-sha256"
endpoint = "127.0.0.1:12345"
tun = "dtls2"
address = "10.8.0.2/30"
psk = "0qhQoLAvfOukhP0NqGVOuQ=="
privdrop = "nogroup:nobody"
"""


def test_connect_disconnect():
    server = spawn(conf_server)
    assert_line(server, "listening")
    client = spawn(conf_client)
    assert_line(server, "established")
    assert_line(client, "established")
    terminate(client)
    assert_line(server, "disconnected")
    assert_line(server, "listening")
    terminate(server)


conf_server_aes = """
role = "server"
proto = "tls13-aes128-ccm-8-sha256"
endpoint = "127.0.0.1:12345"
tun = "dtls1"
address = "10.8.0.1/30"
psk = "0qhQoLAvfOukhP0NqGVOuQ=="
"""

conf_client_aes = """
role = "client"
proto = "tls13-aes128-ccm-8-sha256"
endpoint = "127.0.0.1:12345"
tun = "dtls2"
address = "10.8.0.2/30"
psk = "0qhQoLAvfOukhP0NqGVOuQ=="
"""


def test_connect_disconnect_aes():
    server = spawn(conf_server_aes)
    assert_line(server, "listening")
    client = spawn(conf_client_aes)
    assert_line(server, "established")
    assert_line(client, "established")
    terminate(client)
    assert_line(server, "disconnected")
    assert_line(server, "listening")
    terminate(server)


conf_client_3rdparty = """
role = "client"
proto = "tls13-chacha20-poly1305-sha256"
endpoint = "127.0.0.1:12345"
tun = "dtls2"
address = "10.8.0.2/30"
psk = "C+F/+6xsOn1nr5uW31/8OA=="
"""


def test_psk_mismatch():
    server = spawn(conf_server)
    assert_line(server, "listening")
    client = spawn(conf_client_3rdparty)
    assert_line_err(server, "binder does not verify")
    assert_line_err(client, "received alert fatal error")
    terminated(client, 0)
    assert_line(server, "listening")
    terminate(server)


def test_ping():
    create_ns("ns1")
    create_ns("ns2")

    server = spawn(conf_server)
    assert_line(server, "listening")
    client = spawn(conf_client)
    assert_line(server, "established")
    assert_line(client, "established")

    run("ip link set dtls1 netns ns1")
    run("ip netns exec ns1 ip addr add 10.8.0.1/30 dev dtls1")
    run("ip netns exec ns1 ip link set dtls1 up")

    run("ip link set dtls2 netns ns2")
    run("ip netns exec ns2 ip addr add 10.8.0.2/30 dev dtls2")
    run("ip netns exec ns2 ip link set dtls2 up")

    ping = run("ip netns exec ns1 ping -c 1 10.8.0.2")
    assert "64 bytes from 10.8.0.2" in ping.stdout

    ping = run("ip netns exec ns2 ping -c 1 10.8.0.1")
    assert "64 bytes from 10.8.0.1" in ping.stdout

    terminate(client)
    assert_line(server, "disconnected")
    assert_line(server, "listening")
    terminate(server)

    delete_all_ns()


def test_keys_update():
    server = spawn(conf_server)
    assert_line(server, "listening")
    client = spawn(conf_client)
    assert_line(server, "established")
    assert_line(client, "established")

    client.send_signal(signal.SIGHUP)
    assert_line(client, "keys update requested")
    assert_line(client, "keys updated")

    terminate(client)
    assert_line(server, "disconnected")
    assert_line(server, "listening")
    terminate(server)


conf_server_timeout = """
role = "server"
proto = "tls13-chacha20-poly1305-sha256"
endpoint = "127.0.0.1:12345"
tun = "dtls1"
address = "10.8.0.1/30"
psk = "0qhQoLAvfOukhP0NqGVOuQ=="
timeout = 3
"""


def test_server_timeout():
    server = spawn(conf_server_timeout)
    assert_line(server, "listening")
    client = spawn(conf_client)
    assert_line(server, "established")
    assert_line(client, "established")

    assert_line(server, "disconnected on timeout", 5)
    assert_line(server, "listening")
    assert_line(client, "disconnected")

    terminate(server)
    terminated(client, 1)


if len(sys.argv) < 2 or len(sys.argv) > 3:
    print("Usage: python3 test.py <tun-executable-path> [verbose]")
    sys.exit()

executable_path = sys.argv[1]

if len(sys.argv) == 3 and sys.argv[2] == "verbose":
    verbose = True

try:
    test_connect_disconnect()
    test_connect_disconnect_aes()
    test_psk_mismatch()
    test_ping()
    test_keys_update()
    test_server_timeout()
    print("PASSED")
except:
    killall()
    delete_all_ns()
    raise
