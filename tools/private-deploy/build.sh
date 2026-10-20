#!/bin/sh
# ============================================================================
# GhostLock R15 — 本地 aarch64 clang + NDK sysroot 两段式编译 libghostlock.so
#
#   用法:  sh tools/build.sh [输出文件]        默认 /tmp/ghostlock_build/ghostlock
#   覆盖:  NDK=<NDK toolchain 目录>  API=<NDK API 级别,默认 35>
#          WORK=<中间文件目录>       TMPDIR=<临时目录>
#
#   本脚本已改为可移植版本:ROOT 自动取脚本上级目录,NDK 可用环境变量覆盖。
#   原版(路径写死为本机 <workspace>/ghostlock)保留为 tools/upstream/build.sh.orig。
#   本机默认 NDK = /opt/android-ndk-cache/android-ndk-r29 (含 linux-aarch64),
#   并使用 NDK 自带 clang/ld.lld；实测本树(3 条内建)产出 5293b118…(94688B) 可复现。
# ============================================================================
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)
NDK=${NDK:-/opt/android-ndk-cache/android-ndk-r29/toolchains/llvm/prebuilt/linux-aarch64}
SYS=$NDK/sysroot
API=${API:-35}
WORK=${WORK:-/tmp/ghostlock_build}
OUT=${1:-$WORK/ghostlock}
BUILTINS=$(ls "$NDK"/lib/clang/*/lib/linux/libclang_rt.builtins-aarch64-android.a 2>/dev/null | head -1)

if [ ! -d "$SYS" ]; then
  echo "!! 找不到 NDK sysroot: $SYS"
  echo "   请下载 NDK 或指定: NDK=/path/to/android-ndk/toolchains/llvm/prebuilt/linux-x86_64 sh tools/build.sh"
  exit 1
fi
if [ -z "$BUILTINS" ]; then
  echo "!! 找不到 libclang_rt.builtins-aarch64-android.a(NDK 不完整)"
  exit 1
fi

mkdir -p "$(dirname "$OUT")" "$WORK"
cd "$ROOT"
# 优先使用 NDK 自带 clang/ld.lld（已验证：产出可复现）
PATH="$NDK/bin:$PATH"
export PATH

CFLAGS="-O2 -flto -Wall -Wno-unused-parameter -Wno-sign-compare -Wno-unused-function -Wno-trigraphs"
CFLAGS="$CFLAGS -Isrc/core -Isrc/kernels -DTARGET_CONFIG_H=\"target.h\" -fPIE -pthread"

OBJS=""
for f in src/core/main.c src/core/offsets_json.c src/core/util.c src/core/fops.c; do
  o=$WORK/$(basename "$f" .c).o
  TMPDIR=${TMPDIR:-/tmp} clang -c --target=aarch64-linux-android$API --sysroot=$SYS \
    $CFLAGS "$f" -o "$o"
  OBJS="$OBJS $o"
done

NDK="$NDK" API="$API" NDK_BUILTINS="$BUILTINS" sh "$HERE/lld_link.sh" "$OUT" $OBJS
ls -la "$OUT"
sha256sum "$OUT"
echo "期望指纹(本私有化树, NDK r29 clang 21): 5293b118cb5726c4323667bee8ab18ce5d926b2869864973257e20a44f27156e  (94688B)"
echo "上游原始树参考指纹(历史):                  d9ff9c43c6073c47ff10c67b063074813cfb2035348f79ddca3546c9d01051b5  (105456B)"
