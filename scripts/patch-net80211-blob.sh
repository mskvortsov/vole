#!/bin/sh
set -eu

if [ "$#" -ne 3 ]; then
    echo "usage: $0 <esp32-flavor> <src-lib> <dst-dir>" >&2
    exit 2
fi

flavor=$1
src_lib=$2
dst_dir=$3

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/../.." && pwd)

ar=ar
case "$flavor" in
    esp32s*)
        objcopy="$repo_root/xtensa-esp-elf/bin/xtensa-${flavor}-elf-objcopy"
        readelf="$repo_root/xtensa-esp-elf/bin/xtensa-${flavor}-elf-readelf"
        ;;
    *)
        objcopy="$repo_root/toolchains/riscv32-esp-elf/bin/riscv32-esp-elf-objcopy"
        readelf="$repo_root/toolchains/riscv32-esp-elf/bin/riscv32-esp-elf-readelf"
        ;;
esac

patched_lib="$dst_dir/libnet80211.a"
obj="$dst_dir/ieee80211_output.o"

mkdir -p "$dst_dir"
cp "$src_lib" "$patched_lib"

(cd "$dst_dir" && "$ar" x "$patched_lib" ieee80211_output.o)

sec_idx=$("$readelf" -sW "$obj" | awk '/ieee80211_post_hmac_tx/{print $7; exit}')
if [ -z "$sec_idx" ]; then
    echo "failed to find ieee80211_post_hmac_tx section index in $obj" >&2
    exit 1
fi

sec_name=$("$readelf" -SW "$obj" | awk -v idx="[$sec_idx]" 'NR > 5 && $1 == idx {print $2; exit}')
if [ -z "$sec_name" ]; then
    echo "failed to resolve section name for index $sec_idx in $obj" >&2
    exit 1
fi

"$objcopy" \
    --weaken-symbol ieee80211_post_hmac_tx \
    "--add-symbol=__real_ieee80211_post_hmac_tx=${sec_name}:0,global,function" \
    "$obj"

(cd "$dst_dir" && "$ar" r "$patched_lib" ieee80211_output.o)
