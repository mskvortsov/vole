#!/usr/bin/env python3

import signal
import socket
import struct
import sys

UDP_PORT = 58761
HOSTNAME = "vole"

HEADER_FORMAT = "<Bq"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

TAG_BASIC = 1
BODY_BASIC_FORMAT = "<6I"
BODY_BASIC_SIZE = struct.calcsize(BODY_BASIC_FORMAT)

TAG_SOJOURN = 2
SOJOURN_HIST_SIZE = 13
BODY_SOJOURN_FORMAT = f"<{SOJOURN_HIST_SIZE}H{SOJOURN_HIST_SIZE}H"
BODY_SOJOURN_SIZE = struct.calcsize(BODY_SOJOURN_FORMAT)

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("0.0.0.0", UDP_PORT))


def handle_sigterm(signum, frame):
    sock.close()
    sys.exit(0)


signal.signal(signal.SIGTERM, handle_sigterm)
signal.signal(signal.SIGINT, handle_sigterm)


while True:
    try:
        sys.stdout.flush()
        sys.stderr.flush()

        data, addr = sock.recvfrom(1024)

        if len(data) < HEADER_SIZE:
            print(f"invalid packet: {data.hex()}", file=sys.stderr)
            continue

        tag, timestamp_ms = struct.unpack(HEADER_FORMAT, data[:HEADER_SIZE])
        body = data[HEADER_SIZE:]

        timestamp_ns = timestamp_ms * 1_000_000

        if tag == TAG_BASIC:
            if len(body) != BODY_BASIC_SIZE:
                print(
                    f"basic body has invalid size {len(body)}: {body.hex()}",
                    file=sys.stderr,
                )
                continue

            fields = struct.unpack(BODY_BASIC_FORMAT, body)

            allocs_failed = fields[0]
            early_drops = fields[1]
            heap_used = fields[2]
            tx_backlog = fields[3]
            codel_drop_count = fields[4]
            codel_drop_len = fields[5]

            print(
                f"basic,host={HOSTNAME} "
                + f"allocs_failed={allocs_failed}i,"
                + f"early_drops={early_drops}i,"
                + f"heap_used={heap_used}i,"
                + f"tx_backlog={tx_backlog}i,"
                + f"codel_drop_count={codel_drop_count}i,"
                + f"codel_drop_len={codel_drop_len}i "
                + f"{timestamp_ns}\n"
            )

        elif tag == TAG_SOJOURN:
            if len(body) != BODY_SOJOURN_SIZE:
                print(
                    f"sojourn body has invalid size {len(body)}: {body.hex()}",
                    file=sys.stderr,
                )
                continue

            fields = struct.unpack(BODY_SOJOURN_FORMAT, body)

            sojourn_lan = fields[0:SOJOURN_HIST_SIZE]
            sojourn_wan = fields[SOJOURN_HIST_SIZE:]

            for i, v in enumerate(sojourn_lan):
                print(
                    f"sojourn_lan,host={HOSTNAME},bucket={(1 << i) / 10.0} value={v} {timestamp_ns}"
                )
            for i, v in enumerate(sojourn_wan):
                print(
                    f"sojourn_wan,host={HOSTNAME},bucket={(1 << i) / 10.0} value={v} {timestamp_ns}"
                )

        else:
            print(f"unknown tag {tag}", file=sys.stderr)
            continue

    except OSError:
        break

    except Exception as e:
        print(f"error: {e}", file=sys.stderr)
