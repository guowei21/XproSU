#!/bin/sh
# Build the vendored 6.1 core with the Android NDK.
#
#   ./build.sh [OUT] [PROFILE]
#
# PROFILE is a profiles.h selector suffix: pd2571 (default) or qemu_iqoo12,
# and is passed as -DIC_PROFILE_<PROFILE upper-cased>.
#
# API 29 is required: NDK r27 with API 24 emits a TLS segment aligned to 8,
# which the arm64 bionic linker refuses at exec time ("executable's TLS
# segment is underaligned ... needs to be at least 64").
set -eu
ROOT=$(cd "$(dirname "$0")" && pwd)
OUT=${1:-$ROOT/t98260}
PROFILE=$(echo "${2:-pd2571}" | tr '[:lower:]' '[:upper:]')
CC=${CC:-${ANDROID_NDK_HOME:-/d/Android/Sdk/ndk/27.2.12479018}/toolchains/llvm/prebuilt/windows-x86_64/bin/aarch64-linux-android29-clang}
"$CC" -O2 -static -pthread -Wall -Wextra -DIC_PROFILE_"$PROFILE" \
    -DIC_SYMS_HAVE_ZLIB "$ROOT/timer98260.c" "$ROOT/ic_syms.c" -lz -o "$OUT"
echo "built $OUT (profile $PROFILE)"
