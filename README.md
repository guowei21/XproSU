# XproSu

基于上游 `kzktor/ic-timer-lpe`（分支 `refactor-98260`，0.12.31）补齐的 Android 工程。
exploit core 与运行脚本保留上游实现，应用壳重写为 Kotlin + Jetpack Compose。

## 当前版本

| 项 | 值 |
|---|---|
| versionName / versionCode | 0.16.2 / 18 |
| 包名 | `com.xprosu`（debug：`com.xprosu.dev`） |
| 应用名 | XproSu |
| minSdk / targetSdk / compileSdk | 33 / 35 / 35 |
| 构建 | Gradle 8.9 · AGP 8.7.3 · Kotlin 2.0.21 · Compose BOM 2024.10.01 |
| 原生载荷 | `app/src/main/assets/ic-timer`，NDK r27+ / API 29，profile `qemu_iqoo12` |
| 载荷校验 | 本机 NDK 27.3 产物 2,445,136 B，SHA-256 `99f9eb7f5441b2ceb80a9e69fb03eb2f1eaf4f94791d1a585f8ae6066fa14ade` |
| 真机验证 | vivo V2324A / `PD2324C_A_16.2.13.1.W10`，表 `ic_pd2324j_links` |

## 功能

- Shizuku shell 用户服务（uid 2000 / `u:r:shell:s0`），应用不直接碰 `/data/local/tmp`
- 12 阶段进度：按 core 日志锚点解析，不需要改 native
- KSU 管理器自动检测：已知包名优先，未命中按关键字扫描并用 `resolve-activity` 验证
- 交接时通过 `IC_KSU_PKG` 把管理器包名传给 core，用 `monkey` 冷启动（兼容随机 Activity 别名）
- 日志为首页二级抽屉，诊断并入同一面板；不再向 `/sdcard/Download` 写副本
- 运行结束自动清理 `/data/local/tmp` 的临时文件；**不删除 `/data/adb/ksu` 内任何内容**
- ksud 暂存放在 `/data/local/tmp/ksud-h*`，由自动清理回收

## 目录

```
app/                        Android 壳
  src/main/aidl/com/xprosu/ IIcService.aidl（8 个方法，签名与上游一致）
  src/main/assets/          run_core.sh / ksu_handoff.sh / safemode.sh
                            cleanup_tmp.sh / manual.md / ic-timer
  src/main/java/com/xprosu/ MainActivity.kt / MainViewModel.kt / IcService.java
                            core/Stages.kt（12 阶段锚点）
                            ui/{AppRoot,HomeScreen,LogScreen,Theme}.kt
core/                       exploit 源码（MIT，molanp）
scripts/build-core.sh       NDK 编 core → assets/ic-timer
scripts/build-apk.sh        一条命令出 debug APK
```

## 构建

```sh
# 1) core（NDK r27+，目标 API 29；API 24 的 TLS 对齐会被 bionic 拒绝）
#    默认 profile 是 qemu_iqoo12：X100 / PD2324J（V2324A）的 cred 以
#    4 字节 usage 开头，uid 在 +0x4；pd2571 是 8 字节 usage，uid 在 +0x8。
#    qemu_iqoo12 只是 profile 名，不要求跑 QEMU。
export ANDROID_NDK_HOME=/opt/android-sdk/ndk/27.3.13750724
./scripts/build-core.sh

# 2) APK
./scripts/build-apk.sh                 # debug
./gradlew assembleRelease \
  -Pandroid.aapt2FromMavenOverride=/opt/android-sdk/build-tools/35.0.1/aapt2
```

用错 profile 时 core 仍会继续跑（从 timer 调用点反推 slide），但编译期
cred 偏移跟着错，日志会出现 `[site] ... differs from profile` 和反复
`[!] fake uid write missed (uid=-126)`，最终 `plant1 burst missed`。
APK 构建阶段也会检查载荷内嵌的 profile 名，发现 `pd2571` 直接报错。

aarch64 主机必须用 `android.aapt2FromMavenOverride` 指向 arm64 的 aapt2；
x86_64 主机装好 Google build-tools 后可省略。

release 默认回退 debug 签名；要正式签名，把 `keystore.properties.example`
复制成 `keystore.properties` 并填 keystore（已 gitignore）。

## GitHub Actions

推送 `cve-2026-98260` 或手动触发 `.github/workflows/build-release.yml` 会：

1. 安装 JDK 17、Gradle 8.9、Android SDK 35 / build-tools 35.0.1 /
   NDK 27.3.13750724；
2. 用 `qemu_iqoo12` 编译 `ic-timer` 并校验内嵌 profile；
3. 构建 release APK，成功后自动创建 Release（tag
   `v<versionName>-<run_number>`），附 APK 与 SHA-256。

正式签名在仓库 Secrets 配置 `SIGNING_KEY_BASE64`（keystore 的 base64）、
`KEYSTORE_PASSWORD`、`KEY_ALIAS`、`KEY_PASSWORD`；未配置时回退 debug 签名，
Release 说明会标注。`GITHUB_TOKEN` 需要 `contents: write`，工作流已声明。

## 运行前提

- 每次完整运行前重启手机（上一轮的 slab 状态会污染 fake-cred 命中率）
- Shizuku 用无线调试 / ADB 启动，不要用 root 启动
- 接管 KSU 前先装好对应管理器 APK，模块由 late-load 加载
- 只支持 KernelSU 系（KernelSU / KSU-Next / SukiSU / BakaSU / ReSukiSU /
  SakiSU / FinaSU / 7kimisu / vivoKSU）；Magisk、APatch 不走这条链路

## 与上游的差异

- `core/` 与 4 个运行脚本来自上游，脚本未改逻辑
- `core/timer98260.c` 唯一改动：KSU 收尾启动管理器时读 `IC_KSU_PKG`，
  有值用 `monkey -p <pkg>`，无值保持原来的 `am start -n <KSU_PKG>/.ui.MainActivity`
- 构建默认 profile 改为 `qemu_iqoo12`（`core/build.sh` 与 `scripts/build-core.sh`）；
  上游 X100 系列的预编译载荷同样使用该 profile，`pd2571` 仅用于 8 字节
  cred usage 的机型
- 其余全部是应用壳、构建工程与文档

## 已知限制

- release 默认使用 debug 签名
- 多用户 / 工作资料下的管理器按 user 0 处理
- 运行后残留的 root `ic-timer` 进程按上游手册不能 `kill -9`，只能重启

## 许可

core 为 MIT（Copyright (c) 2026 molanp，见 `core/LICENSE.molanp`）。
上游仓库根目录未附 APK 侧代码的许可证，对外分发前先与作者确认。
