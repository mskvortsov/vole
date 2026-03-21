#!/bin/sh -e

PATCHES="vole/patches/zephyr-*.patch"
ZEPHYR_DIR="zephyr"

for patch in $PATCHES; do
    files=$(grep "^+++ b/" "$patch" | sed 's|^+++ b/||')
    if [ -z "$files" ]; then
        echo "warning: no files found in $patch, skipping" >&2
        continue
    fi

    new=$(git -C "$ZEPHYR_DIR" diff -- $files)
    if [ -z "$new" ]; then
        echo "warning: no working tree changes for $(basename "$patch"), skipping" >&2
        continue
    fi

    echo "$new" > "$patch"
    echo "updated $(basename "$patch")"
done
