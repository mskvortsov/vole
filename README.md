# Vole, an embedded tunnel

Vole is a network router firmware based on Zephyr RTOS and wolfSSL library:
* connects to an upstream IPv4 WiFi network (`wan`),
* creates an IPv6 WiFi access point for client hosts (`lan`),
* creates a DTLS 1.3 or a WireGuard tunnel (`tun`) through the `wan` to a server,
* routes traffic through the tunnel,
* runs an HTTP/1 server (mDNS advertised) for monitoring and configuration.

The primary target is a low-cost esp32-c6 board; some other esp32 variants are also supported but less tested. There are no hard dependencies on esp32 platform, porting to other Zephyr-supported hardware shouldn't be hard.

On esp32-c6, expected tunneling throughput is 2-5 Megabits/s for both directions combined. Peak latency requires improvement.

Supported DTLS 1.3 cipher suites:
* TLS13-AES128-CCM-8-SHA256,
* TLS13-CHACHA20-POLY1305-SHA256,
* TLS13-SHA256-SHA256 (null cipher).

Key exchange scheme is X25519.

## Usage

The `default.toml` file contains a default WiFi access point configuration with a commented-out template for upstream connection and tunnel settings.

To allow editing the configuration and checking out system status, the firmware runs a simple web page. Tools like `curl` or `wget` may be used to do the same from a command line — there are two HTTP API endpoints available:
* `/api/status` (application/json, `GET`-only)
* `/api/config` (application/toml, `GET` and `POST`)

Getting info and statistics:
```
$ curl http://vole.local/api/status
{
 "sys": {
  "version": "v0.1.0-e9a2e9e0c1e7",
  "uptime": 1983,
  ...
```
Getting the current configuration:
```
$ curl http://vole.local/api/config
[lan]
ssid = "vole"
psk = "volevole"
...
```
Setting a configuration:
```
$ curl --request POST --data-binary @config.toml http://vole.local/api/config
{
 "status": 0,
 "report": "accepted and saved, reloading tun"
}
```

The code for the DTLS server (Linux-only) is in the `tun` directory. Scripts in `tun/scripts` are for setting up NAT on a server machine; `default-server.toml` contains a sample configuration.

## Flashing

Download a firmware binary for your platform from the Releases section, flash at zero offset using esptool (see `scripts/flash.sh` for an example).

## Building

*Note* Device tree overlays and Kconfig .conf files may need some adaptation to run the firmware on a particular board.

1. Check out "Install dependencies" section at Zephyr's [Getting Started Guide](https://docs.zephyrproject.org/latest/develop/getting_started/index.html#install-dependencies) and make sure your system has all the packages installed.

2. Clone the repository and setup a development environment (requires a couple gigs of disk space and may take some time to download; don't skip creating a new empty directory for the workspace):
```shell
mkdir vole-workspace && cd vole-workspace
git clone https://github.com/mskvortsov/vole
vole/scripts/setup-dev.sh
```

The resulting workspace directory should look like this:
```
vole-workspace
├── .clangd -> vole/.clangd-workspace
├── cryptogams
├── modules
├── .nvm
├── tomlc17
├── toolchains
├── .venv
├── vole
├── .west
├── wolfssl
├── .zed -> vole/.zed-workspace
└── zephyr
```

3. Run a script to build and flash in one shot:
```shell
vole/scripts/make.sh apsta esp32c6 /dev/ttyACM0
```

During development you may want to run `west` or `ninja -C build` manually to speed up iteration, or use whatever workflow you prefer.

4. If you use Zed editor and clangd for source code indexing, open the `vole-workspace/` directory in Zed — code completion and navigation across all sources including modules should work without additional configuration.

### Landing page dev run

If you want to make a change to the vole's configuration webpage, you may want to run a mocking HTTP server to test your changes without flashing a device:
```shell
cd vole/www
npm run dev
```

### Telemetry

For real-time performance monitoring, see the [Telemetry Monitoring](telemetry/README.md) guide.

## Server setup

1. Build locally and copy the executable and configuration scripts to a server host
```shell
vole/scripts/make-tun.sh
scp -r build-tun/tun vole/tun/scripts vole/default-server.toml server:~/vole/
```

Then, on the server host side:

2. Run the tunnel server
```shell
cd ~/vole
sudo setcap cap_net_admin+ep tun
./tun server.toml
```

3. Set up forwarding and NAT
```shell
cd ~/vole/scripts
# edit the settings in the script header first
sh setup.sh
```

Optionally, to mitigate bufferbloat in the down direction, you may want to add a queue discipline on the tunnel interface (see `tun/scripts/qdisc-cake.sh`).
