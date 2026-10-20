#!/bin/sh
# ────────────────────────────────────────────────────────────────────────────
# GhostLock R15 一键构建(Alpine aarch64 + Android NDK r29 sysroot)
#
#   用法:  sh tools/build_r15.sh [输出文件]        (默认 /tmp/ghostlock_build/r15)
#   环境:  NDK=<ndk toolchain 路径>                (可覆盖默认路径)
#
#   期望(本私有化树, NDK r29 clang 21): 94688 字节
#          sha256 5293b118cb5726c4323667bee8ab18ce5d926b2869864973257e20a44f27156e
#   (上游原始树的参考指纹为 d9ff9c43…/105456B；改过 src/ 或换工具链后指纹必然变化)
# ────────────────────────────────────────────────────────────────────────────
set -e

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)
OUT=${1:-/tmp/ghostlock_build/r15}
NDK=${NDK:-/opt/android-ndk-cache/android-ndk-r29/toolchains/llvm/prebuilt/linux-aarch64}
SYS=$NDK/sysroot
API=35
LIB35=$SYS/usr/lib/aarch64-linux-android/$API
BUILTINS=$(ls "$NDK"/lib/clang/*/lib/linux/libclang_rt.builtins-aarch64-android.a 2>/dev/null | head -1)

[ -d "$SYS" ]      || { echo "!! 找不到 NDK sysroot: $SYS  (用 NDK=<路径> 覆盖)"; exit 1; }
[ -n "$BUILTINS" ] || { echo "!! 找不到 libclang_rt.builtins-aarch64-android.a"; exit 1; }

mkdir -p "$(dirname "$OUT")" /tmp/ghostlock_build
cd "$ROOT"
PATH="$NDK/bin:$PATH"
export PATH

CFLAGS="-O2 -flto -Wall -Wno-unused-parameter -Wno-sign-compare -Wno-unused-function -Wno-trigraphs"
CFLAGS="$CFLAGS -Isrc/core -Isrc/kernels -DTARGET_CONFIG_H=\"target.h\" -fPIE -pthread"

OBJS=""
for f in src/core/main.c src/core/offsets_json.c src/core/util.c src/core/fops.c; do
  o=/tmp/ghostlock_build/$(basename "$f" .c).o
  echo "  CC  $f"
  TMPDIR=/tmp clang -c --target=aarch64-linux-android$API --sysroot=$SYS \
      $CFLAGS "$f" -o "$o"
  OBJS="$OBJS $o"
done

# 与原 tools/lld_link.sh 完全相同的链接命令(参数、顺序、builtins 出现次数均保持一致)
echo "  LD  $OUT"
ld.lld --sysroot=$SYS -EL --fix-cortex-a53-843419 -z now -z relro \
  -z max-page-size=16384 --hash-style=gnu --build-id --eh-frame-hdr \
  -m aarch64linux -pie -dynamic-linker /system/bin/linker64 \
  -o "$OUT" \
  $LIB35/crtbegin_dynamic.o \
  -L$LIB35 -L$SYS/usr/lib/aarch64-linux-android -L$SYS/usr/lib \
  --as-needed $OBJS \
  "$BUILTINS" -ldl -lc \
  "$BUILTINS" -ldl \
  $LIB35/crtend_android.o

echo "  ── 构建结果 ──"
ls -l "$OUT"
sha256sum "$OUT"
echo "  期望(本私有化树): 5293b118cb5726c4323667bee8ab18ce5d926b2869864973257e20a44f27156e"
