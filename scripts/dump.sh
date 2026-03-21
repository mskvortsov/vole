#!/bin/sh

riscv64-unknown-elf-objdump -d \
-j .iram0.text \
-j .loader.text \
-j .flash.text \
build/zephyr/zephyr.elf
