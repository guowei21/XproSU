# 源码还原说明 — GhostLock 1.1 (versionCode 93)

> 本目录是从**设备上原装 APK**反推还原出来的完整、可编译源码。
> 定位依据、比对方法、验证结果全部记录在下面。

---

## 1. 版本定位（三重交叉验证）

| 证据 | 结果 |
|---|---|
| APK `versionName` | `1.1` |
| APK `versionCode` | `93` ← 上游 build.gradle 用 `git rev-list --count HEAD` 生成 |
| 全历史扫描 `rev-list --count == 93` | **566 个提交里唯一命中 `50d2b72`** |
| 引擎基线（46 个 C 世代提交中差异最小） | `50d2b72` |

**上游对应提交**：`50d2b72`（2026-09-12，`pselect: fix compact route on 6.1 (#127)`）
仓库：`https://github.com/YuKongA/ghostlock-app`

---

## 2. 与上游 `50d2b72` 的**全部**差异

比对方式见 §3，结果如下 —— 一共只有 3 处代码/资源改动：

### ① `app/build.gradle.kts` — 固定 versionCode

```diff
-val gitVersionCode = runCatching {
-    providers.exec { commandLine("git", "rev-list", "--count", "HEAD") }
-        .standardOutput.asText.get().trim().toInt()
-}.getOrElse { logger.warn("git rev-list failed; versionCode falls back to 1"); 1 }
+// 原构建用 `git rev-list --count HEAD`（= 93）。从无 .git 的源码目录构建时会回退成 1，
+// 导致无法覆盖安装设备上已装的 versionCode 93。故固定为 93；升级时手工递增。
+val gitVersionCode = 93
```

**为什么必须改**：原逻辑在无 `.git` 的目录里会回退成 `1` → `INSTALL_FAILED_VERSION_DOWNGRADE`。
（这是实测出来的 —— 首次构建就是因此失败。）

### ② `app/src/main/kotlin/com/ghostlock/app/data/AndroidGhostlockRepository.kt` — +2 行

```diff
                     if (!tcpRouteEnabled) environment()["GHOSTLOCK_TCP_ROUTE"] = "0"
+
+                    if (tcpRouteEnabled) environment()["GHOSTLOCK_ROUTE"] = "mcast"
                 }
```

**作用**：原装 app 把「利用路径」开关（UI 显示 *TCP 零拷贝 / pselect*）的 ON 档接到了 **mcast** 路由上 ——
上游这一档走的是默认 tcp。没有这 2 行，引擎会退回 tcp 路由。

**精确还原依据**（反编译 smali）：

```
.line 263   → GHOSTLOCK_TCP_ROUTE = "0"      （与上游一致，未移位）
             （第 264 行无代码 → 空行）
.line 265   → GHOSTLOCK_ROUTE = "mcast"      （新增）
.line 266   → 上游的 264（}），整体后移 2 行
```

### ③ `src/` — 替换为本项目的 native 引擎

| | 上游 | 本目录 |
|---|---|---|
| `src/` 文件数 | 56 | **17** |
| `src/kernels/` 内建表 | 42 条 | **3 条**（6.1.57 / 6.1.124 / 6.1.145-maybe-dirty） |

上游原始 `src/` 完整留档在 **`src.upstream-backup/`**。

> **注意**：`src/kernels/*/offsets.h` 是 **app 构建期读取**的 —— `app/build.gradle.kts` 的
> `generateSupportedKernels` 任务从它生成 Kotlin 的 `SupportedKernels.kt`。
> 换成我们的 3 条后，生成的 `SupportedKernels.kt` 从 **1205 行缩到 110 行**（已实测）。

### ④ 移除 OTA / boot.img 解析功能（Rust 提取器）

| 移除内容 | 位置 |
|---|---|
| `buildGhostlockExtract` / `prepareGhostlockExtractJniLibs` / `extractNdkTools()` / `useOndk()` | `build.gradle.kts` |
| `prepareGhostlockExtractJniLibs` 的 `preBuild` 依赖 | `app/build.gradle.kts` |
| `parseSource()`、`ExtractBinaryName` | `data/AndroidGhostlockRepository.kt` |
| `parseSource` 接口方法 | `domain/repository/GhostlockRepository.kt` |
| `ParseSourceUseCase` | `domain/usecase/GhostlockUseCases.kt` |
| `onParseOta` / `onParseImage` 动作 + 两个按钮 | `ui/GhostlockUi.kt` |
| `onParseOta` / `onParseImage` 覆写 | `ui/MainActivity.kt` |
| `parseOffsets()` / `promptParseUrl()` / `stageBoot()` / `stageXbl()` / `parseUrl()` / `runParse()` / `parseFailureToast()` / `parseFailureResult()` / `PendingConfirmation.Parse` / `pendingParseWithXbl` / `pendingBootPath` / `DocumentRequest.BootImage` / `DocumentRequest.XblImage` | `ui/GhostlockViewModel.kt` |

**理由**：本项目的偏移提取在 **PC 侧用 Python 脚本**完成（`scripts/parse_boot.py` / `ksg.py` / `gen_v2.py`），
不需要手机上那个 Rust 提取器。移除后 APK 内不再有 `libextract.so`，界面上也不再出现那两个入口。

`tools/extract_rs/` 源码**保留未删** —— 将来若要恢复，只需还原上述改动。

---

## 3. 比对方法（可复现）

### 3.1 反编译

```bash
java -jar apktool.jar d -f -o <out> <apk>       # smali + 资源 + Manifest
```

### 3.2 编译上游源码做对照

```bash
# 在 50d2b72 的源码目录
./gradlew assembleDebug -x buildGhostlockNative -x buildGhostlockExtract
```

> 两个 `-x` 是必须的：`buildGhostlockNative` 要 `make`（C 引擎），
> `buildGhostlockExtract` 要 `cargo`（Rust 提取器）。比对 dex 时不需要它们。

### 3.3 行号指纹比对（决定性）

smali 里的 `.line` 指令保留原始源码行号。逐 `.source` 取最大行号做指纹：

| 源文件 | 原装 APK | 上游直接构建 | 还原后构建 |
|---|---|---|---|
| AndroidGhostlockRepository.kt | 801 | 799 | **801** ✅ |
| GhostlockUi.kt | 1367 | 1367 | 1367 ✅ |
| GhostlockViewModel.kt | 610 | 610 | 610 ✅ |
| MainActivity.kt | 153 | 153 | 153 ✅ |
| SupportedKernels.kt | 1205 | 1205 | 1205 ✅ |
| 其余 11 个文件 | — | 全部一致 | 全部一致 ✅ |

**还原后：16 个源文件，0 个不一致。**

> **一个坑**：`.line` 最大值**不等于文件行数**（Compose 生成代码会推高它，
> 如 `GhostlockUi.kt` 实际 800 行但最大行号 1367）。最初我用文件行数比对，
> 得到"APK 比上游多 567 行"的错误结论；改用"同源构建对照"才定位正确。

### 3.4 其他已核验项（均一致）

- **类清单**：`com/ghostlock/app/**` 全部类名与上游一致
- **composable 清单**：16 个全部一致
- **方法名 / 字段名**：差异只有 R8 合成产物（`$r8$lambda$…`、`L$0`、`BuildConfig.*`、资源 ID）
- **资源**：`values*/strings.xml`、`colors.xml`、`bools.xml` 值与上游逐项一致
  （APK 里多出的条目全是 AndroidX 库自带）
- **Manifest**：差异全是构建生成项（AndroidX startup、`DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION` 等）

---

## 4. 如何构建

### 4.1 前置

```properties
# 新建 local.properties（不入库）
sdk.dir=D\:\\XM\\GJ\\android-sdk
```

环境变量：
```
JAVA_HOME        = <JDK 17+>
ANDROID_HOME     = <Android SDK>
ANDROID_NDK_HOME = <NDK>          # 供 Makefile 找 aarch64 clang
PATH            += <NDK>/prebuilt/windows-x86_64/bin   # 供 `make`
```

### 4.2 构建

```bash
./gradlew assembleDebug        # 完整（含 C 引擎）
```

构建**不需要 Rust / cargo** —— OTA 与 boot.img 解析功能已整体移除（见 §2 ④），
`buildGhostlockExtract` 任务已删除。`make` 由 NDK 提供，把
`<NDK>/prebuilt/windows-x86_64/bin` 加进 PATH 即可。

### 4.3 产物

```
app/build/outputs/apk/debug/GhostLock-v1.1(93)-arm64-v8a-debug.apk
```

---

## 5. 已验证的构建结果

```
versionCode=93  versionName=1.1                      ✅
lib/arm64-v8a/libghostlock.so   99,280 B             ✅（本项目引擎）
    'mcast route'  x6        ← mcast 路由
    'REJECTED'     x8        ← offsets.json 六条校验（S1）
    '6.1.145-android14-11-maybe-dirty' x1
    '6.1.115'      x0        ← 上游 42 条表已清干净
生成的 SupportedKernels.kt: 110 行（3 条）           ✅
```

> **引擎指纹说明**：APK 内 `.so`（`d714d485…`）与本项目 `dist/` 里的
> `libghostlock-r15-s1-arm64.so`（`40ce49ac…`）不同 —— 因为 Makefile 用的链接方式
> （`-fPIE -pie`）与 `tools/lld_link.sh` 的自定义 lld 命令不同，NDK 版本也不同。
> 若要产出与 `dist/` 完全一致的引擎，仍用 `tools/build.sh` 构建后替换
> `app/src/main/jniLibs/arm64-v8a/libghostlock.so`。

---

## 6. 目录结构

```
├── app/                      Android 应用（Kotlin + Compose）
│   └── src/main/kotlin/com/ghostlock/app/
│       ├── data/AndroidGhostlockRepository.kt   ← 引擎调用 + 那 2 行改动
│       ├── domain/model/GhostlockModels.kt
│       ├── domain/repository/GhostlockRepository.kt
│       ├── domain/usecase/*.kt
│       └── ui/{GhostlockUi,GhostlockViewModel,MainActivity}.kt
├── src/                      本项目 native 引擎（17 文件，3 条内建表）
├── src.upstream-backup/      上游原始 src/ 留档（56 文件，42 条表）
├── tools/extract_rs/         Rust 偏移提取器（保留，不参与构建）
├── docs/                     上游 README 原文（42 条表 + Rust 说明，已不适用本工程）
├── Makefile                  C 引擎构建（gradle 的 buildGhostlockNative 调用）
├── build.gradle.kts          根构建（含 native 任务定义）
├── app/build.gradle.kts      app 构建（含 generateSupportedKernels）
├── README.md                 本工程说明（目录 / 构建 / 差异 / 红线）
├── RECONSTRUCTION.md         源码还原说明（本文）
└── ENCRYPTION-PLAN.md        加密与卡密鉴权方案
```
