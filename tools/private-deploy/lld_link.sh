#!/bin/sh
# 复刻 NDK clang 驱动的链接命令，剔除 Alpine host 注入项
# 用法: [NDK=<toolchain 路径>] [API=35] lld_link.sh <out> <objs...>
# 与原版唯一区别：NDK / API 可用环境变量覆盖，BUILTINS 自动探测 clang 版本目录。
set -e
NDK=${NDK:-/opt/android-ndk-cache/android-ndk-r29/toolchains/llvm/prebuilt/linux-aarch64}
API=${API:-35}
SYS=$NDK/sysroot
LIB=$SYS/usr/lib/aarch64-linux-android/$API
BUILTINS=${NDK_BUILTINS:-$(ls "$NDK"/lib/clang/*/lib/linux/libclang_rt.builtins-aarch64-android.a 2>/dev/null | head -1)}
OUT=$1; shift

[ -d "$LIB" ] || { echo "!! 缺少 NDK 平台库目录: $LIB" >&2; exit 1; }
[ -n "$BUILTINS" ] || { echo "!! 未找到 libclang_rt.builtins-aarch64-android.a(NDK 不完整?)" >&2; exit 1; }

ld.lld --sysroot=$SYS -EL --fix-cortex-a53-843419 -z now -z relro \
  -z max-page-size=16384 --hash-style=gnu --build-id --eh-frame-hdr \
  -m aarch64linux -pie -dynamic-linker /system/bin/linker64 \
  -o "$OUT" \
  $LIB/crtbegin_dynamic.o \
  -L$LIB -L$SYS/usr/lib/aarch64-linux-android -L$SYS/usr/lib \
  --as-needed "$@" \
  "$BUILTINS" -ldl -lc \
  "$BUILTINS" -ldl \
  $LIB/crtend_android.o
