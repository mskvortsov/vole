#!/bin/sh -ex

# python3 -m venv .venv
# source .venv
# pip install esptool

# .bin file name
binary=${1:-build/zephyr/zephyr.bin}

esptool                \
--baud 921600          \
--before default-reset \
--after hard-reset     \
write-flash            \
--compress             \
--flash-mode dio       \
--flash-freq 80m       \
--flash-size 4MB       \
0x0 $binary
