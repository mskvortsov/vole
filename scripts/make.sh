#!/bin/sh -e

usage() {
    echo "Usage: $0 [apsta|sta] [esp32c6|esp32c3|esp32s3] [/dev/ttyACMx]" >&2
    exit 1
}

flavor=${1:-apsta}
platform=${2:-esp32c6}
port=${3:-}

case "$platform" in
    esp32c6)
        export CROSS_COMPILE_TOOLCHAIN_PATH=$(pwd)/toolchains/riscv32-esp-elf
        export CROSS_COMPILE=$(pwd)/toolchains/riscv32-esp-elf/bin/riscv32-esp-elf-
        board="esp32c6_devkitc/esp32c6/hpcore"
        ;;
    esp32c5)
        export CROSS_COMPILE_TOOLCHAIN_PATH=$(pwd)/toolchains/riscv32-esp-elf
        export CROSS_COMPILE=$(pwd)/toolchains/riscv32-esp-elf/bin/riscv32-esp-elf-
        board="esp32c5_devkitc/esp32c5/hpcore"
        ;;
    esp32c3)
        export CROSS_COMPILE_TOOLCHAIN_PATH=$(pwd)/toolchains/riscv32-esp-elf
        export CROSS_COMPILE=$(pwd)/toolchains/riscv32-esp-elf/bin/riscv32-esp-elf-
        board="esp32c3_devkitm/esp32c3"
        ;;
    esp32s3)
        export CROSS_COMPILE=$(pwd)/toolchains/xtensa-esp-elf/bin/xtensa-esp32s3-elf-
        export CROSS_COMPILE_TOOLCHAIN_PATH=$(pwd)/toolchains/xtensa-esp-elf
        board="esp32s3_devkitc/esp32s3/procpu"
        ;;
    *)
        usage
        ;;
esac

export ZEPHYR_TOOLCHAIN_VARIANT=cross-compile

case "$flavor" in
    apsta) extra_conf="-DCONFIG_VOLE_LAN=y" ;;
    sta)   extra_conf="" ;;
    *)     usage ;;
esac

. .venv/bin/activate
. .nvm/nvm.sh

npm --prefix vole/www ci
npm --prefix vole/www run build

west build --pristine=always --board $board vole -- $extra_conf

if [ -n "$port" ]; then
    west flash --esp-device $port
    west espressif monitor --port $port
fi
