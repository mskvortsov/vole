#!/bin/sh -ex

usage() {
    echo "Usage: $0 [dev|ci]" >&2
    exit 1
}

mode=${1:-dev}
case "$mode" in
    dev) ;;
    ci)  ;;
    *)   usage ;;
esac

# https://docs.espressif.com/projects/esp-idf/en/stable/esp32s3/api-guides/tools/idf-tools.html
toolchain_tarballs="
    https://github.com/espressif/crosstool-NG/releases/download/esp-15.2.0_20251204/riscv32-esp-elf-15.2.0_20251204-x86_64-linux-gnu.tar.xz
    https://github.com/espressif/crosstool-NG/releases/download/esp-15.2.0_20251204/xtensa-esp-elf-15.2.0_20251204-x86_64-linux-gnu.tar.xz
"

export NVM_DIR=$(pwd)/.nvm
export PROFILE=/dev/null
mkdir -p "$NVM_DIR"
wget -qO- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.4/install.sh | bash
. $NVM_DIR/nvm.sh
nvm install --lts

python3 -m venv .venv
. .venv/bin/activate
pip install -U pip
pip install west

west init --local vole
west update --fetch-opt=--filter=blob:none
west packages pip --install
west blobs fetch hal_espressif

mkdir toolchains
for tarball in $toolchain_tarballs; do
    curl --silent --location $tarball | tar xvJf - -C toolchains
done

if [ "$mode" = "dev" ]; then
    git -C    zephyr apply $(pwd)/vole/patches/zephyr-*.patch
    git -C   wolfssl apply $(pwd)/vole/patches/wolfssl.patch
    ln --symbolic vole/.zed-workspace .zed
    ln --symbolic vole/.clangd-workspace .clangd
fi
