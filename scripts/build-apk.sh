#!/bin/sh
# 一条命令出 debug APK。x86_64 主机装了 Google build-tools 时可去掉 aapt2 覆盖。
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
GRADLE=${GRADLE:-/opt/gradle/gradle-8.9/bin/gradle}
SDK=${ANDROID_HOME:-/opt/android-sdk}
AAPT2=${AAPT2:-$SDK/build-tools/35.0.2/aapt2}

[ -x "$GRADLE" ] || { echo "找不到 Gradle：$GRADLE（可用 GRADLE=... 覆盖）" >&2; exit 1; }
[ -x "$AAPT2" ] || { echo "找不到 aapt2：$AAPT2（可用 AAPT2=... 覆盖）" >&2; exit 1; }
[ -f "$ROOT/local.properties" ] || echo "sdk.dir=$SDK" > "$ROOT/local.properties"

exec "$GRADLE" -p "$ROOT" assembleDebug \
    -Pandroid.aapt2FromMavenOverride="$AAPT2" "$@"
