#!/bin/sh
# 用 Android NDK 编译 core（与上游 core/build.sh 等价，路径改成 Linux 主机）。
#
#   ./scripts/build-core.sh [OUT] [PROFILE]
#
# PROFILE: pd2571（默认）| qemu_iqoo12
# 需要 NDK r27+；API 29 是硬要求（API 24 的 TLS 段 8 字节对齐会被 bionic 拒绝）。
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
OUT=${1:-$ROOT/app/src/main/assets/ic-timer}
PROFILE=$(echo "${2:-pd2571}" | tr '[:lower:]' '[:upper:]')

NDK=${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-/opt/android-sdk/ndk}}
if [ ! -d "$NDK" ]; then
    echo "找不到 NDK：设置 ANDROID_NDK_HOME 或用 minis-android-sdk-setup 安装" >&2
    exit 1
fi
# 兼容 sdk/ndk/<rev> 目录
if [ -d "$NDK" ] && [ ! -d "$NDK/toolchains" ]; then
    NDK=$(ls -d "$NDK"/* 2>/dev/null | sort -V | tail -1)
fi

HOST=$(uname -m)
case "$HOST" in
    aarch64|arm64) PREBUILT=linux-aarch64 ;;
    x86_64|amd64)  PREBUILT=linux-x86_64 ;;
    *) echo "不支持的主机架构: $HOST" >&2; exit 1 ;;
esac

CC=${CC:-$NDK/toolchains/llvm/prebuilt/$PREBUILT/bin/aarch64-linux-android29-clang}
[ -x "$CC" ] || { echo "clang 不存在: $CC" >&2; exit 1; }

mkdir -p "$(dirname "$OUT")"
"$CC" -O2 -static -pthread -Wall -Wextra -DIC_PROFILE_"$PROFILE" \
    -DIC_SYMS_HAVE_ZLIB \
    "$ROOT/core/timer98260.c" "$ROOT/core/ic_syms.c" -lz -o "$OUT"

echo "built $OUT (profile $PROFILE, $(stat -c%s "$OUT" 2>/dev/null || stat -f%z "$OUT") bytes)"
