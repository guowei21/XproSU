#!/bin/sh
# 已废弃：APK 打包统一走 GitHub Actions（.github/workflows/build-release.yml）。
#
# 原因：本地 Gradle/JDK 会在系统盘留下几 GB 缓存，而 CI 的产物已经带 release
# 签名、SHA-256 与 Release 条目，直接用那份即可。
#
# 需要一版可安装的 APK 时：
#   git push origin cve-2026-98260
# 然后从 Actions 的 Release 资产下载 XproSU-<version>-<code>-<run>-release.apk。
echo "build-apk.sh 已废弃：APK 只在 CI 构建，请推送 cve-2026-98260 后从 Release 下载。" >&2
exit 1
