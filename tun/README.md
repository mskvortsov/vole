# TUN

A simple point-to-point L3 tunnel based on wolfSSL DTLS 1.3:
* PSK authorization,
* X25519 key sharing,
* ChaCha20-Poly1305 AEAD.

## Usage

1. Generate a psk
```
$ tun genpsk
AAAAAAAAAAAAAAAAAAAAAA==
```
2. Create configs (see `configs/` for reference)
3. Run `tun server.toml` and `tun client.toml` (requires `CAP_NET_ADMIN` capability)
4. Set up forwarding and address translation, check out `scripts` directory for samples

## Performance

A iperf3 run over a 100 Mb/s Ethernet network:
```
[ ID] Interval           Transfer     Bitrate         Retr
[  5]   0.00-10.00  sec   111 MBytes  93.3 Mbits/sec   47            sender
[  5]   0.00-10.01  sec   109 MBytes  91.6 Mbits/sec                  receiver
```

and over the tunnel:
```
[ ID] Interval           Transfer     Bitrate         Retr
[  5]   0.00-10.00  sec   106 MBytes  88.5 Mbits/sec   30            sender
[  5]   0.00-10.01  sec   105 MBytes  88.0 Mbits/sec                  receiver
```
