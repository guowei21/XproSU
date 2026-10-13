# GhostLock 产品工程（收费分发基线）

> **定位**：GhostLock 1.1（`versionCode 93`）的**完整、可编译源码工程**，
> 作为「加密 + 卡密鉴权」商业化改造的基线。
>
> **上游基线**：`YuKongA/ghostlock-app` 提交 `50d2b72`（2026-09-12，`pselect: fix compact route on 6.1 (#127)`）。
> 定位依据、比对方法与还原验证见 [`RECONSTRUCTION.md`](RECONSTRUCTION.md)。
>
> **商业化方案**：[`ENCRYPTION-PLAN.md`](ENCRYPTION-PLAN.md)。
> **卡密授权接入**：[`docs/uverif-integration.md`](docs/uverif-integration.md)。

---

## 1. 目录结构

| 路径 | 内容 |
|---|---|
| `app/` | Android 应用（Kotlin + Compose + Miuix，14 个 Kotlin 源文件） |
| `app/src/main/assets/offsets.glt` | 偏移表二进制容器（940 B，3 条表）——**唯一随包分发的偏移数据** |
| `src/` | native 引擎源码（16 文件）；偏移已移出源码，`src/kernels/offsets.h` 仅剩 struct 定义 |
| `Makefile` / `build.gradle.kts` | C 引擎构建（gradle 的 `buildGhostlockNative` → `prepareGhostlockJniLibs`） |
| `app/build.gradle.kts` | app 构建（含 U验证 6 项 `buildConfigField` 注入、签名、ABI 裁剪） |
| `buildSrc/` | 空壳（生成 `SupportedKernels.kt` 的任务已废弃，该文件改为手写） |
| `docs/offsets-binary-format.md` | 偏移表二进制容器（`.glt`）格式与实测证据 |
| `docs/uverif-integration.md` | U验证 协议、后台配置要求、凭据填写与实测证据 |
| `docs/upstream-README.md`<br>`docs/upstream-README_ZH.md` | 上游 README 原文（42 条内核 + Rust 提取器说明，**对本工程已不适用**） |
| `RECONSTRUCTION.md` | 源码还原说明 |
| `ENCRYPTION-PLAN.md` | 加密与卡密鉴权方案 |
| `dist/` | 交付 APK 归档 |

**不在这里的东西**：PC 侧的偏移提取脚本与明文 `offsets/*.json` 留在私有化主工程
（`ghostlock-57-124-145-project/`）。明文表按 `ENCRYPTION-PLAN.md` §1 泄漏点 8 属
「分发即致命」，**不得进入交付物**。

---

## 2. 支持的内核（3 条内建表）

| release（`uname -r`） | 设备 |
|---|---|
| `6.1.57-android14-11-maybe-dirty` | vivo PD2324（早期固件） |
| `6.1.124-android14-11-maybe-dirty` | vivo PD2324 / V2324A（MT6989，当前固件） |
| `6.1.145-android14-11-maybe-dirty` | vivo iQOO V2339FA（Dimensity 9300+） |

app **不再内置任何偏移数据**：`assets/` 里没有载荷，全部由授权服务端按设备下发。

---

## 3. 授权（阶段②：卡密同时管「门」和「锁」）

```
登录窗口（独立 Activity，App 入口）
  └─ 卡密 + 本机指纹 + 本机公钥 ──► 自建授权服务
                                     ├─ 调 U验证 校验卡密（服务端到服务端）
                                     ├─ Kd  = HKDF-SHA256(master, salt=SHA-256(卡密), info=设备指纹)
                                     ├─ blob = GLT2：ChaCha20-Poly1305(Kd, AAD=64B 头含卡密摘要)
                                     └─ wrapped = ECIES(本机公钥, Kd)
  ◄─ blob + wrapped
  └─ TEE 内解出 Kd → 落盘（Kd 经 Keystore 加密）→ 进主界面
```

- **登录是独立窗口**：`LoginActivity` 是 LAUNCHER，主界面在授权之前**根本不会被创建**；
  主界面未授权时会自己退回登录窗口。
- **卡密同时参与偏移解密**：容器头里的 `card_tag = SHA-256(卡密)[:16]` 被 AEAD 认证，
  引擎解密前会拿用户输入卡密的摘要与它比对。登录分支被 patch 掉也拿不出这个值，
  容器照样解不开——「门」不再是唯一防线。
- **两把钥匙缺一不可**：`Kd` 通过 HKDF 的 salt 与卡密绑定；换成另一张卡的 `Kd`
  在认证阶段失败，伪造绑定值在比对阶段失败（实测 5 组负向用例全部拒绝）。
- **一机一码**：本机指纹取 Widevine `MediaDrm.PROPERTY_DEVICE_UNIQUE_ID`（硬件级，
  恢复出厂不变），退化用 ANDROID_ID + Build 字段；容器头的 `device_fp` 被 AEAD 认证，
  引擎再明文比对一次，拷贝到别的设备直接拒绝。
- **Release fail-closed**：未配置授权服务地址时激活明确报错，不静默放行；
  只有 `BuildConfig.DEBUG && 未配置服务` 才放行，便于本地调试。
- **离线容忍**：只有服务端**明确拒绝**才收回授权与载荷，网络不通保持现状（稳定性优先）。
- **日志分级**：Debug 显示明文运行日志；Release 只显示百分比 + 阶段名，
  R8 + 资源收缩会把日志字符串一并从 APK 删除。

完整协议见 [`docs/stage2-protocol.md`](docs/stage2-protocol.md)；
U验证 的 5 项凭据与后台配置见 [`docs/uverif-integration.md`](docs/uverif-integration.md)；
**构建与部署步骤见 [`docs/build-and-deploy.md`](docs/build-and-deploy.md)**；
**加固清单与 A/B 要求见 [`docs/hardening.md`](docs/hardening.md)**。
- **Release fail-closed**：未配置授权服务地址时激活明确报错，不静默放行；
  只有 `BuildConfig.DEBUG && 未配置服务` 才放行，便于本地调试。
- **离线容忍**：只有服务端**明确拒绝**才收回授权与载荷，网络不通保持现状（稳定性优先）。
- **日志分级**：Debug 显示明文运行日志；Release 只显示百分比 + 阶段名，
  R8 + 资源收缩会把日志字符串一并从 APK 删除。

完整协议见 [`docs/stage2-protocol.md`](docs/stage2-protocol.md)；
U验证 的 5 项凭据与后台配置见 [`docs/uverif-integration.md`](docs/uverif-integration.md)；
**构建与部署步骤见 [`docs/build-and-deploy.md`](docs/build-and-deploy.md)**。

---

## 4. 构建

前置：JDK 21、Android SDK（本机无 `make`，故跳过 native 编译）。

```properties
# local.properties（不入库）
sdk.dir=<Android SDK>
UVERIF_BASE_URL=<自建 U验证 地址>
UVERIF_APP_ID=<应用 ID>
UVERIF_APP_INDEX=<版本索引>
UVERIF_APP_VER=<版本号>
UVERIF_APP_KEY=<应用密钥>
```properties
# local.properties（不入库）
sdk.dir=<Android SDK>
LICENSE_BASE_URL=<自建授权服务对外地址>
```

> U验证 的 5 项凭据**不在 App 里**，写在服务端 `config.json`。
> 完整步骤（服务端部署、引擎构建、Release 签名、联调清单、排错）见
> [`docs/build-and-deploy.md`](docs/build-and-deploy.md)。

```powershell
$env:JAVA_HOME    = '<JDK>'
$env:ANDROID_HOME = '<Android SDK>'

.\gradlew.bat assembleDebug   -x :buildGhostlockNative --no-daemon
.\gradlew.bat assembleRelease -x :buildGhostlockNative --no-daemon
```

产物：

```
app/build/outputs/apk/debug/GhostLock-v1.1(93)-arm64-v8a-debug.apk
app/build/outputs/apk/release/GhostLock-v1.1(93)-arm64-v8a-release.apk
```

`-x :buildGhostlockNative` 跳过 `make`；`.so` 已预置在
`app/src/main/jniLibs/arm64-v8a/libghostlock.so`，`prepareGhostlockJniLibs` 只做拷贝。
若本机有 `make` + NDK，去掉 `-x` 即可从 `src/` 全量重编。

**不需要 Rust / cargo** —— OTA 与 boot.img 解析功能已整体移除（见 §5）。

### 4.1 实测构建结果

| 项 | 值 |
|---|---|
| 包名 / 版本 | `com.ghostlock.pro` / `versionCode 93` / `versionName 1.1` |
| 入口 Activity | `com.ghostlock.pro.ui.MainActivity` |
| ABI | `arm64-v8a` |
| Debug APK | 63,319,543 B |
| Release APK | 2,564,725 B（R8 + 资源收缩，13 个 zip 条目） |
| `lib/arm64-v8a/libghostlock.so` | 74,840 B，SHA-256 `ca80f11712869425ed37c091765e4ebc380a705864d8f6ac6ff1ebb15a64e9b0` |
| `assets/offsets.glt` | 940 B（3 条表） |
| `libextract.so` | **不存在** ✅ |
| 明文偏移扫描（Release） | `task_seccomp` / `off_init_cred` / 偏移数值 = **0 命中** |
| Release 日志字符串 | `console_title` / `action_clear` 已从资源表消失（Debug-only 路径被判死代码） |

> **引擎指纹说明**：本目录 Makefile 编出的 `.so` 与私有化主工程 `dist/` 里的
> `libghostlock-r15-s1-arm64.so` **不是同一个哈希** —— 差别只在链接方式
> （Makefile 用 clang 驱动 vs `tools/lld_link.sh` 的手写 lld 命令）。
> 已实测两者**功能等价**：152 个函数中 149 个指令序列完全相同，其余 3 个是 PLT 桩
> （只有 GOT 地址不同），`.rodata` / `.data` 字节完全相同。

---

## 5. 与上游 `50d2b72` 的差异

1. `app/build.gradle.kts` —— `versionCode` 固定为 `93`
   （原逻辑走 `git rev-list --count HEAD`，在无 `.git` 目录会回退成 `1` → 无法覆盖安装）
2. `app/.../data/AndroidGhostlockRepository.kt` —— 固定 `GHOSTLOCK_ROUTE=mcast`（TCP 路线默认开启）
3. `src/` —— 替换为本项目引擎（偏移表移入 `.glt` 容器；上游 56 文件 / 42 条表留档在
   `_backups/ghostlock-product-20261010-171829/src.upstream-backup/`，**不参与构建**）
4. **OTA / boot.img 解析功能整体移除**（gradle 任务 + 6 个 Kotlin 文件）
5. **商业化改造**：包名 `com.ghostlock.app` → `com.ghostlock.pro`；删除偏移导入/导出入口；
   UI 重构为 HyperOS/Miuix 卡片式；接入 U验证 卡密鉴权；Debug/Release 日志分级

逐项依据与比对方法见 [`RECONSTRUCTION.md`](RECONSTRUCTION.md) §2。

---

## 6. 红线

1. **签名密钥必须在卖出第一个卡密前固定** —— 换签名可能改 DRM ID，全部已绑定卡密一次性失效，
   而「一机一码不允许解绑」下不可恢复（`ENCRYPTION-PLAN.md` §8.1）。
2. **明文偏移表绝不落盘、绝不进交付物** —— 一旦图省事写回文件，加密工作全部归零
   （`ENCRYPTION-PLAN.md` §6.1）。
3. **不要动已真机验证的引擎路径**，任何改动都要 A/B 对照 —— 本引擎时序敏感（futex 竞速），
   加固或重排可能让它从「稳定成功」退化成「偶尔成功」。
4. `src/kernels/offsets.h` 里 `task_cred` **必须显式给值** —— 缺键会回落到 6.6 的 `0x900`，
   而该值恰等于 6.1 的 `task_seccomp`，会把 root cred 写进 seccomp 字段。
5. 同一开机周期**不得二跑** —— race 失败会留下悬空 PI 节点。

---

## 7. 上游参考

| 项 | 值 |
|---|---|
| 仓库 | `https://github.com/YuKongA/ghostlock-app` |
| 基线提交 | `50d2b72`（2026-09-12） |
| 为什么不用上游 `main` | `main` 已重构成 C++ 世代（`src/core/race/`、`route/`、`session/`），app 层只设 2 个环境变量、配置走 JSON profile —— **与本引擎接口不兼容** |
| 本工程与引擎的契约 | `exec` 调用 + 6 个 `GHOSTLOCK_*` 环境变量 + `GHOSTLOCK_HOME/offsets.glt` |
