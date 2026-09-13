#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
OUT=${1:-"$ROOT/kernel/rootfs"}
TMP="$ROOT/target/dynlink-test"
mkdir -p "$TMP" "$OUT/System/Lib" "$OUT/System/Test"
CLANG=${CLANG:-clang}
LLD=${LLD:-rust-lld}
"$CLANG" --target=aarch64-none-elf -fPIC -c "$ROOT/tools/dynlink-test/libzero.S" -o "$TMP/libzero.o"
"$CLANG" --target=aarch64-none-elf -fPIC -c "$ROOT/tools/dynlink-test/dynapp.S" -o "$TMP/dynapp.o"
"$LLD" -flavor gnu -shared -soname libzero.so -o "$OUT/System/Lib/libzero.so" "$TMP/libzero.o"
"$LLD" -flavor gnu -pie -e _start -o "$OUT/System/Test/zero-dynapp" "$TMP/dynapp.o" -L"$OUT/System/Lib" -lzero
printf 'dynlink-test: built %s and %s\n' "$OUT/System/Lib/libzero.so" "$OUT/System/Test/zero-dynapp"
