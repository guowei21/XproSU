# 规划：APK 提权 + WebUI 管理（`apk-root-webui`）

> 基线：`7fc9258`（`upstream-base`，我们动手前的 XproSU 代码）
> 本分支：`apk-root-webui`
> 定位：**非商业版**。不做卡密、不做服务端、不做付费链路；
> 只做两件事 —— 本地提权加固、偏移加密随包（本地解密，不需要任何授权）。
> 对照：`main`（`c37d8ba`，同一目标；本分支在偏移条目上加 `build` 双键，并去掉过渡代码）

---

## 1. 目标与边界

**一句话**：一个 APK 只做两件事 —— 把 uid 变成 0，然后把 ksud 的管理页面打开；
超级用户、模块、文件、终端全部由 DikSU 的 WebUI 提供，App 里没有一行管理逻辑。

**目标**

1. 单 APK，装完就能提权，不依赖设备上预先安装任何管理器。
2. 提权成功后，App 内一键进入管理页面（WebView），URL 与令牌只落在本 App 私有目录。
3. **偏移加密随包**：`assets/offsets.enc` 装 57/124/145（可扩展），运行时用本地密钥
   解密到 `files/offsets.json`，引擎按 `release + build` 双键选条目；
   **不需要授权、不需要服务端、不需要联网**。
4. Release 构建可直接分发：日志常显、失败有明确出口。

**非目标（本期不做）**

- 不做任何商业化：没有卡密、激活、心跳、授权服务器、日志上传。
- 不做持久 root（刷 boot / 集成 lkm 到 boot.img）——`late-load` 是内存态，重启即失效。
- 不合并 DikSU 的 Kotlin 管理器代码（避免 GPL 传染与 2–4 周 UI 合并）。
- 不做偏移表内建（改为加密容器 + 本地解密，见 §4.2）。
- 不做自动更新。

---

## 2. 为什么必须替换引擎（不是偏好，是基线缺陷）

`7fc9258` 的 `src/` 有两处会让提权失败/无法离线：

| 缺陷 | 证据 | 后果 |
|---|---|---|
| 路由看门狗 + 2 秒锁超时 | `src/core/main.c:278-341,431`：`ROUTE_SETUP_TIMEOUT_SEC 3`、`ROUTE_HARD_TIMEOUT_SEC 6`、`lock_to.tv_sec += 2` | 慢机上正常路线被提前打断；103 的 tcp/mcast 双失败就是这个 |
| 偏移只认 GLT2 + 服务端 `Kd` | `main.c:194` `load_offsets_aead(...)`，`offsets_bin.c` 的 AEAD 分支 | 没有服务端就没有偏移，离线不可用 |

**决定**：`src/` 整树替换为原版 ghostlock（`original-core` 分支上那份，17 个文件），
`Makefile` 只编 `main.c / offsets_json.c / util.c / fops.c`。这是真机验证过的执行路径，
一行时序都不改。偏移走引擎自带的 `offsets.json` 导入路径——本方案把收费版的
"服务端下发 Kd + GLT2" 换成 "随包 AES-GCM 容器 + 本地密钥"，只解密方式变了，
读取路径仍是引擎原本那条。

---

## 3. 目标架构

```
┌──────────────────────────── APK (com.ghostlock.pro) ────────────────────────────┐
│                                                                                 │
│  Compose UI                                                                    │
│   ├─ 首页：机型/内核/SELinux 状态 · 一键提权 · 进度与日志 · 「管理」入口          │
│   └─ 维护：W1 路由(tcp/mcast) · 核心对 · 兼容模式 · 日志导出                     │
│                                                                                 │
│  RootController (Kotlin)                                                       │
│   ├─ 解密 assets/offsets.enc  →  files/offsets.json（0600）                     │
│   ├─ 复制 jniLibs/libksud.so   →  files/ksud                                   │
│   └─ exec libghostlock.so（环境变量见 §4）                                      │
│                                                                                 │
│  WebUiActivity (WebView)  ←  files/webui.url（0600，属主=App）                  │
└───────────────┬──────────────────────────────────────────────┬──────────────────┘
                │ exec                                          │ http://127.0.0.1
                ▼                                               ▼
┌──────────────────────────────┐                 ┌────────────────────────────────┐
│ libghostlock.so（C，104 KB）  │                 │ ksud webui（DikSU 的内建服务）  │
│  W1 SELinux → vr.ko → W2     │                 │  超级用户 / 模块 / 文件 / 终端   │
│  → W3 seccomp → root         │                 │  keyMint / 隐藏应用 …           │
│  └ ksud late-load            │                 │  token 文件 0600 root          │
│  └ ksud webui --daemon       │                 └────────────────────────────────┘
└──────────────────────────────┘
```

职责边界：

| 角色 | 只负责 | 不负责 |
|---|---|---|
| App | 提权、解密偏移、拉起 ksud、打开页面 | 授权列表、模块安装、文件操作 |
| 引擎 | futex 竞速、SELinux/cred/seccomp、调用 ksud | UI、持久化 |
| ksud | 加载 `kernelsu.ko`、提供 WebUI 与全部管理 API | 提权 |

---

## 4. 提权链路（细化）

### 4.1 环境变量契约（App → 引擎）

| 变量 | 值 | 作用 |
|---|---|---|
| `GHOSTLOCK_HOME` | `filesDir` | 引擎读 `offsets.json`、写 `webui.url`、日志 |
| `TMPDIR` / `HOME` | 同上 | 临时文件 |
| `GHOSTLOCK_KSU_LOG` | `filesDir/.ghostlock_ksu.log.<ts>` | 根脚本日志（App 侧 tail） |
| `GHOSTLOCK_CORE` / `GHOSTLOCK_CONSUMER_CORE` | 用户选的核心对 | futex 竞速绑核 |
| `GHOSTLOCK_ROUTE` | `mcast`（默认）/ `tcp` | W1 路线 |
| `GHOSTLOCK_DISABLE_MODULES` | `1`（兼容模式） | late-load 前置禁用模块 |

### 4.2 偏移（加密容器 + 本地解密）

```
assets/offsets.enc      AES-256-GCM(json, aad="XSO1")
   key = SHA-256("XproSU/local-offsets/v1")      ← 本地固定标签，没有服务端
        │ LocalOffsets.decrypt()（设备本地，运行前）
        ▼
files/offsets.json      数组，每项 { release, build, symbols, struct_fields }
        │ 引擎 load_offsets_json()：release + build 双键命中
        ▼
active_offsets
```

- **容器可以装多台设备**：57/124/145 各一条，新增机型只加一条 JSON、重新打包，
  不需要改 C 代码、不需要发新引擎。
- **双键匹配**：`release`（`uname -r`）与 `build`（`uname -v`，带构建时间）
  同时相等才接受；不等 → `E04 unsupported kernel build`，打印两侧原文后中止。
  这是为了防止同版本串、不同厂商 vmlinux 的误配。
- 解密结果落在 `files/offsets.json`（0600），引擎启动时读一次；下一次运行覆盖。
  运行时可选在 `finally` 里删掉，减少明文驻留。
- **不回退到内建表**：原版 `select_offsets()` 在导入失败后会遍历 `known_offsets[]`。本分支
  把这条回退关掉——导入失败直接 `E02` 退出。内建表按弱键（只有 release）命中，
  正是要避免的误配路径；容器里才有 `build` 双键。
- 密钥在 APK 里 ⇒ 这是**混淆级**保护：挡得住 `unzip` 直接看表，挡不住反编译。
  与商业版的唯一差别是——商业版的 `Kd` 在服务端，这里的密钥在本地，所以不需要授权。
- 改表流程：改 JSON → `python tools/pack_offsets_local.py` → 重编 APK。

### 4.3 根脚本尾段（新增，其余保持原版）

```sh
# 模块已加载 → 起 WebUI，把带令牌的 URL 交给 App
if [ -x "$KSUD" ] && grep -q kernelsu /proc/modules 2>/dev/null; then
  "$KSUD" webui --daemon --idle-timeout 0 >>"$LOG" 2>&1
  WPORT=$(cat /data/adb/ksu/webui.port 2>/dev/null)
  WTOK=$(cat /data/adb/ksu/webui.token 2>/dev/null)
  if [ -n "$WPORT" ] && [ -n "$WTOK" ]; then
    printf 'http://127.0.0.1:%s/?t=%s' "$WPORT" "$WTOK" > "$HOME_DIR/webui.url"
    chown "$(stat -c %u "$HOME_DIR")" "$HOME_DIR/webui.url" 2>/dev/null
    chmod 600 "$HOME_DIR/webui.url" 2>/dev/null
  fi
fi
```

`late-load` 调用保持不变：`"$KSUD" late-load --kmi "$KMI" --allow-shell`，
**不传** `--package-name`（DikSU 把管理器包名烤在 `libksud.so` 里）。

### 4.4 文件生命周期

| 文件 | 位置 | 权限 | 何时写 | 何时删 |
|---|---|---|---|---|
| `offsets.json` | `filesDir` | 0600 | 每次运行前（解密 `offsets.enc`） | 运行结束可选删除；下次覆盖 |
| `ksud` | `filesDir` | 0700 | 每次运行前 | 不删（版本随包） |
| `webui.url` | `filesDir` | 0600 | 提权成功且 WebUI 起来 | 下次运行覆盖；重启后失效 |
| `webui.token` / `webui.port` | `/data/adb/ksu` | 0600 root | ksud | ksud 管理 |
| 运行日志 | `filesDir/device.log` | 0600 | 每行 fsync | 512 KB 滚动 |

---

## 5. WebUI 链路（细化）

### 5.1 启动与地址

- `ksud webui --daemon --idle-timeout 0`：绑定随机端口（持久化到 `/data/adb/ksu/webui.port`），
  绑定完成后再 daemonize，所以脚本返回即可读端口。
- 令牌：`/data/adb/ksu/webui.token`，`load_or_create_token()` 首次生成、之后复用。
- 入口 URL：`http://127.0.0.1:<port>/?t=<token>`（`t` 是 ksud 认的查询参数，落到 cookie）。

### 5.2 WebView 配置

| 项 | 值 | 原因 |
|---|---|---|
| `javaScriptEnabled` | true | 页面是纯前端渲染 |
| `domStorageEnabled` | true | 主题/面板状态存 localStorage |
| `allowFileAccess` / `allowContentAccess` | false | 页面不需要本地文件 |
| 外链 | 交给系统浏览器 | 文档/源码链接不丢管理上下文 |
| `shouldInterceptRequest` | 吞掉 `/api/close` | 页面 `pagehide` 会 beacon 它，ksud 收到就轮换令牌 → 存下的地址失效 |
| `onReceivedHttpError` | 403 时提示"再点一次获取 Root" | 令牌确已轮换时给出口，不白屏 |
| 返回键 | 先 `goBack()`，栈底再 finish | 页面内部有多级路由 |

### 5.3 生命周期

```
点提权 → 引擎跑完 → 脚本起 webui（daemon）→ 写 webui.url → App 可随时打开页面
关闭页面 → /api/close 被拦截 → 服务与令牌继续有效
重启手机 → 模块不在（内存态）→ 页面 502/连接失败 → 需要重新提权
再次提权 → 端口/令牌复用或重建 → 覆盖 webui.url
```

---

## 6. 文件级改动清单

### 6.1 引擎

| 路径 | 动作 | 说明 |
|---|---|---|
| `src/`（整树） | **替换** | 换成原版 ghostlock（`original-core` 分支）：`main.c`、`fops.c`、`util.c`、`offsets_json.c`、`offset.h`、`common.h`、`target.h`、`runtime_struct_offsets.h`、`kernelsnitch/*`、`kernels/offsets.h`（含 `known_offsets[]`）、`kernels/<release>/offsets.h` |
| `src/core/offsets_bin.c` `chacha20.*` `poly1305.*` `selftest.*` | **删除** | GLT2 链路整体移除，App 不再有 `Kd` |
| `Makefile` | 修改 | `SRCS` 只留 `main.c offsets_json.c util.c fops.c` |
| `src/core/offsets_json.c` | 修改 | 条目新增 `"build"` 字段；匹配改为 `release + build` 双键，不匹配返回非零（引擎报 `E04`） |
| `src/core/main.c` `select_offsets()` | 修改 | 日志加 `build: %s`；去掉 `known_offsets[]` 回退——导入失败直接 `E02`，不按弱键兜底 |
| `src/kernels/offsets.h` | 修改 | `known_offsets[]` 清空（只留 `{ .uname_r = NULL }` 终止项） |
| `src/core/main.c` | 两处增量 | ① 根脚本 ksud 查找改通用（`/data/adb/ksud` + `find -name libksud.so`）；② 尾段加 WebUI 启动与 `webui.url` |

### 6.2 App

| 路径 | 动作 | 说明 |
|---|---|---|
| `license/LicenseRepository.kt` `LicenseClient.kt` `LicenseStore.kt` `CardKey.kt` `DeviceKey.kt` `GlBlob.kt` `DeviceFingerprint.kt` | **删除** | 授权层整体移除 |
| `license/DeviceLogStore.kt` | 移动 | → `data/DeviceLogStore.kt`，只负责本机落盘 |
| `data/LocalOffsets.kt` | 新增 | AES-256-GCM 解密 `offsets.enc`（密钥由固定标签派生，无服务端） |
| `data/AndroidGhostlockRepository.kt` | 重写约 40% | 去掉 `Kd`/GLT2/env 密钥；加 `ensureLocalOffsets()`（解密 + 落 0600 文件）、`prepareKsud()`（随包优先） |
| `ui/GhostlockViewModel.kt` | 重写约 40% | 去掉激活/心跳/上传；日志常显；新增 `exportDiagnosticLogs()` |
| `ui/GhostlockUi.kt` | 删改 | 删授权卡与激活对话框；`RunButton` 去掉 `isLicensed`；维护区加「打开管理页面」 |
| `ui/WebUiActivity.kt` | 新增 | WebView 壳（§5.2） |
| `GhostlockApplication.kt` `MainActivity.kt` | 简化 | 不再注入 `LicenseRepository` |
| `assets/offsets.enc` | 新增 | AES-GCM 容器：57/124/145，每项带 `release` + `build` |
| `jniLibs/arm64-v8a/libksud.so` | 新增 | DikSU v3.3.0-57，6.38 MB，含 `android14-6.1_kernelsu.ko` 与 WebUI 前端 |
| `res/values(-zh)/strings.xml` | 删改 | 删 license/activate 文案；加 webui 四条 |
| `res/xml/network_security_config.xml` | 新增 | 只对 `127.0.0.1`/`localhost` 放行明文 |
| `AndroidManifest.xml` | 修改 | `INTERNET`（仅回环）+ `QUERY_ALL_PACKAGES` + `WebUiActivity` |
| `app/build.gradle.kts` | 修改 | 删 `LICENSE_BASE_URL`/`APP_VER`/明文放行任务；`versionCode` 起始 **200** |

### 6.3 工程

| 路径 | 动作 | 说明 |
|---|---|---|
| `tools/pack_offsets_local.py` | 新增 | 把偏移 JSON 密封成 `offsets.enc`（本地密钥，无服务端） |
| `README.md` | 重写 | 目标、流程图、构建、契约、红线 |
| `docs/private-deploy/` `server/gl-license/` | 保留 | 历史资料，App 不再引用；README 标注"非商业版不含授权链路" |

---

## 7. 安全设计

1. **令牌只在本 App 私有目录**：`/data/adb/ksu/webui.token` 是 0600 root，
   `webui.url` 被 `chown` 给 App uid、`chmod 600`；其他 App 读不到。
2. **只绑回环**：ksud 绑 `127.0.0.1`；`INTERNET` 权限只为 WebView，network security config
   只对 `127.0.0.1`/`localhost` 放行明文，其余默认拒绝。
3. **不打印令牌**：脚本与 App 日志都不输出 URL 全文（只输出端口）。
4. **ksud 只在 root 下运行**：脚本先校验 `id -u == 0`，否则 `exit 1`。
5. **GPL 边界**：`libksud.so` 是独立可执行程序（exec，不链接），README 注明出处与 GPL-3.0；
   App 代码保持 Apache-2.0。
6. **偏移以密文分发、双键匹配**：APK 里只有 `offsets.enc`（AES-GCM），解出来的
   `files/offsets.json` 是 0600、只在本 App 私有目录；命中要求 `release` 与 `build`
   同时相等，否则 `E04` 拒绝；日志只打印命中的 release/build，不打印绝对地址。
7. **本地加固（非商业版的全部内容）**：Release 开 R8 + 资源收缩、`vcsInfo` 关闭、
   无明文日志字符串；`allowBackup=false`；没有多余的 exported 组件；
   偏移不出现在 dex（本来就在 .so）；签名固定后不换（换签名 = 用户必须卸载重装）。

---

## 8. 构建与发布

```powershell
# 引擎
make ghostlock API=35

# APK
.\gradlew.bat assembleRelease --no-daemon
# 产物：XproSU-v1.1(200)-arm64-v8a-release.apk
```

- 版本号：本分支从 **200** 起手工递增（与 `main` 的 110 区分，避免覆盖安装歧义）。
- CI：`.github/workflows/build.yml`；本分支手动 `gh workflow run build.yml --ref apk-root-webui`。
- 产物自检（每次构建后）：
  - `unzip -l` 有 `lib/arm64-v8a/libghostlock.so`、`lib/arm64-v8a/libksud.so`、`assets/offsets.enc`
  - `.so` 含 `offsets imported from offsets.json`、`mcast route`、`webui --daemon`；不含 `GLT2`
  - `python tools/verify_offsets_local.py app/src/main/assets/offsets.enc` 能解回三条 release，
    且每条的 `symbols`/`struct_fields` 数量不变
  - dex 不含 `api/activate`、`License`
  - `apksigner verify --print-certs` 与上一版同证书

---

## 9. 真机验收

### 9.1 成功标准（V2324A / 6.1.145）

```
kernel: 6.1.145-android14-11-maybe-dirty
build: #1 SMP PREEMPT …                                 ← 双键的第二半
offsets imported from offsets.json: 6.1.145-…           ← 本地解密 + 命中
ksud source: bundled (6379944 bytes)
W1: SELinux attempt 1/15 … mcast route won
[+] KernelSU module loaded
[*] webui listening on 127.0.0.1:<port>
```

点「打开管理页面」→ 页面出现超级用户/模块/文件/终端；授予一个 App root 后
该 App 能拿到 `su`；装一个模块并重启服务后仍生效（本次开机内）。

### 9.2 失败矩阵

| 现象 | 定位 | 处理 |
|---|---|---|
| 无 `offsets imported` | 解密失败或没有匹配条目 | 看 `LocalOffsets` 的报错；确认 `offsets.enc` 里的 release/build 与日志两侧一致 |
| `E04 unsupported kernel build` | release 对上了，但 `build` 不同（换了固件或换了机型） | 把日志里的 `release=` / `build=` 原文发回来，加一条 JSON 后重新打包；**不要**去掉 build 字段 |
| `no offsets for kernel` | 容器里没有该 release | 同上；先确认 `uname -r` 与 JSON 里的字符串逐字一致 |
| `ksud missing; cannot late-load` | 随包 lib 没解出 | 检查 `useLegacyPackaging`、`nativeLibraryDir` |
| `Failed to get android14-6.1_kernelsu.ko` | ksud 没带该 KMI | 换 DikSU 版本或自编 ksud |
| 页面 403 | 令牌被轮换 | 重新提权（本期已拦截 `/api/close`） |
| 页面连接被拒 | webui 没起来/重启过 | 看脚本日志 `webui did not report port/token` |

---

## 10. 风险与对策

| 风险 | 影响 | 对策 |
|---|---|---|
| ksud 版本锁死（v3.3.0-57） | 换内核/换 KMI 要换包 | 版本与 sha256 写进 README；升级时重跑 §8 自检 |
| 固件 OTA 改了 `uname -v` | 老条目会被双键拒绝（E04） | 预期行为：拒绝 > 误写。取新 build 串加条目、重新打包 |
| 内存 root，重启失效 | 用户预期落差 | 首次引导明确说明；管理页失效时提示"重新提权" |
| WebView 兼容性 | 页面白屏 | 页面是标准前端；保留"用浏览器打开"兜底按钮 |
| 体积 9 MB | 分发成本 | 接受；ksud 无法裁剪（含 ko 与 WebUI） |
| GPL 争议 | 合规 | exec 边界 + 源码出处 + 不改 ksud |
| 上游 app 骨架带旧文案 | 体验不一致 | P4 统一文案（中英） |

---

## 11. 排期

| 阶段 | 内容 | 产出 | 估时 |
|---|---|---|---|
| P0 | 分支与基线：`src/` 换原版、Makefile 收敛 | `make ghostlock` 通过 | 0.5 d |
| P1 | 授权剥离：删 7 个 license 文件、ViewModel/UI/构建字段 | 编译通过、无 `License` 引用 | 0.5 d |
| P2 | 提权落地：`LocalOffsets` + `offsets.enc` + `prepareKsud` + 双键匹配 | 本地 Kotlin 编译 + 解密自检 | 1.5 d |
| P3 | WebUI：脚本尾段、`WebUiActivity`、manifest/网络配置 | 构建产物含 `webui --daemon` | 1 d |
| P4 | UI 与文案：管理入口、首次引导、失败提示 | 中英文案齐全 | 1 d |
| P5 | 真机回归：§9 全表 | 验收记录 | 1–2 d |

合计 **5–6 人日**。

---

## 12. 复用来源（避免重造）

本分支的实现已在 `main` 上验证过编译与产物扫描，按文件搬：

| 块 | 来源 |
|---|---|
| 原版引擎整树 | `original-core:src` |
| `LocalOffsets` + `offsets.enc` + 打包脚本 | `main:app/.../data/LocalOffsets.kt`、`tools/pack_offsets_local.py` |
| `prepareKsud`（随包优先 + 通用扫描） | `main:app/.../data/AndroidGhostlockRepository.kt` |
| WebUI 脚本尾段 | `main:src/core/main.c`（`webui --daemon` 段） |
| `WebUiActivity` + 网络配置 + 文案 | `main:app/.../ui/WebUiActivity.kt` 等 |

> 与 `main` 的差别：本分支在 `offsets_json.c` 里加了 `build` 双键（`main` 只按 release），
> 并删掉 `main` 上残留的过渡代码（`OFFLINE_MODE`、`Glt1Magic` 之类）；版本号从 200 起算。
