#!/bin/sh
set -ux

# Prepare a host (once)
#   sudo ./testbed-prepare.sh
# Then run this script
#   ./testbed-run.sh ./tun /dev/ttyACM0 firmware.bin

sudo uhubctl --location 2 --action on >/dev/null
sudo .venv/bin/python3 -m testbed "$@"
sudo uhubctl --location 2 --action off >/dev/null
