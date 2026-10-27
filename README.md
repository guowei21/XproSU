# XproSU 1.1（无授权 · 本地偏移版）

> **定位**：XproSU 1.1 的完整源码工程，**不含任何授权/联网校验**：没有激活页、没有卡密、
> 没有心跳、没有服务端。偏移表随 APK 分发，在设备上本地解密后交给引擎。
>
> **引擎**：原版 ghostlock（CVE-2026-43499 futex PI UAF 提权），`src/` 逐文件保留，
> 只把偏移的来源换成随包加密资产。
>
> **上游基线**：`YuKongA/ghostlock-app` 提交 `50d2b72`（2026-09-12，
> `pselect: fix compact route on 6.1 (#127)`）。源码还原依据见
> [`RECONSTRUCTION.md`](RECONSTRUCTION.md)。

---

## 1. 目录结构

| 路径 | 内容 |
|---|---|
| `app/` | Android 应用（Kotlin + Compose + Miuix） |
| `app/src/main/assets/offsets.enc` | **随包偏移表**：AES-256-GCM 密封的 `offsets.json` |
| `src/` | 原版 ghostlock 引擎（`main.c` / `fops.c` / `util.c` / `offsets_json.c` + 内建表） |
| `src/kernels/offsets.h` | `known_offsets[]`：57 / 124 / 145 三条内建条目（导入失败时的兜底） |
| `Makefile` | C 引擎构建（gradle 走 `buildGhostlockNative` → `prepareGhostlockJniLibs`） |
| `tools/pack_offsets_local.py` | 把偏移 JSON 密封成 `assets/offsets.enc`（打包期工具） |
| `docs/private-deploy/` | 私有化适配资料：逐符号偏移提取、可复现构建、重打包签名、真机核验 |
| `server/gl-license/` | **历史遗留**：旧卡密授权服务（Python 标准库）。本版 App 不再调用它 |
| `RECONSTRUCTION.md` / `ENCRYPTION-PLAN.md` | 源码还原说明 / 旧的加密方案记录（历史文档） |

---

## 2. 支持的内核（3 条内建表）

| release（`uname -r`） | 设备 |
|---|---|
| `6.1.57-android14-11-maybe-dirty` | vivo PD2324（早期固件） |
| `6.1.124-android14-11-maybe-dirty` | vivo PD2324 / V2324A（MT6989） |
| `6.1.145-android14-11-maybe-dirty` | vivo V2324A / iQOO 同代（Dimensity 9300） |

引擎先按 `uname -r` 找导入表，找不到再退回 `known_offsets[]`；两条都没有就报
`no offsets for kernel` 退出，不会拿错表硬跑。

---

## 3. 偏移数据怎么走（本地解密）

```
assets/offsets.enc            AES-256-GCM(json, aad="XSO1")
        │                     密钥 = SHA-256("XproSU/local-offsets/v1")
        ▼  LocalOffsets.decrypt()             （运行时，设备本地）
$filesDir/offsets.json        引擎的导入格式（数组，每项一个 release）
        ▼  load_offsets_json()
active_offsets               命中 release 的条目；缺失字段沿用内建表
        ▼
W1 → vr.ko → W2 → W3 → root
```

- **没有服务端**：密钥推导在 App 里，所以这是**混淆**而不是保密 —— 拿到 APK 的人
  可以复现这张表。要「APK 里拿不到表」就必须有服务端持有密钥，而这正是本版去掉的东西。
- **每次运行前重写**：解出来的表只有 5 KB，重写成本远低于「缓存被截断后静默退回
  内建表」的风险。
- **内建表仍在**：`known_offsets[]` 是兜底，也是 103 之前真机跑通的那一份。

重新生成资产（改过偏移 JSON 之后）：

```powershell
python tools\pack_offsets_local.py app\src\main\assets\offsets.enc `
    docs\private-deploy\offsets\offsets-57+124+145-combined.json
```

---

## 4. App 行为

- **无授权**：启动不弹激活框，不发 `/api/session`、不发心跳、前台不做在线核对；
  运行按钮只取决于内核是否在支持列表里。
- **日志常显**：Release 也显示完整运行日志与终端卡片；「维护 → 运行日志 →
  复制到剪贴板」可以把落盘的那份取出来（每行 fsync，卡死重启后仍在）。
- **只走回环**：`INTERNET` 权限仅为 WebView 打开 `127.0.0.1` 上的管理页面；App 自身
  不发任何外部请求（network security config 只对回环地址放行明文）。
- **W1 路由可切换**：默认 `mcast`（真机验证过的路线），打开「TCP 路由」走 socket。
  两条路都会在日志里打印 `route=…` 和 `xxx route start`。
- **无超时/看门狗**：引擎的 futex 竞速没有人为截止时间 —— 加超时会把本来能完成的
  路线提前打断（103 的失败原因）。

### 4.1 分工：APK 只负责提权，管理交给 ksud 的 WebUI

```
APK                                    设备                              浏览器 / WebView
 ├─ assets/offsets.enc ──本地解密──▶ files/offsets.json
 ├─ jniLibs/libksud.so ──复制──▶ files/ksud
 └─ exec libghostlock.so ─────────▶ W1 → vr.ko → W2 → W3 → root
                                     └─ ksud late-load（加载 kernelsu.ko）
                                     └─ ksud webui --daemon --idle-timeout 0
                                           └─ 127.0.0.1:<port> + token ──▶ 管理页面
```

提权只到「拿到 uid 0」为止；超级用户、模块、文件管理、终端这些日常管理全部由
`ksud` 内建的 HTTP 服务提供，App 不实现也不接触这些逻辑。

- **随包带 ksud**：`app/src/main/jniLibs/arm64-v8a/libksud.so` 是 DikSU `v3.3.0-57`
  的 ksud 二进制（6.4 MB，内含 `android14-6.1_kernelsu.ko` 与 WebUI 前端）。App 启动
  提权前把它复制成 `files/ksud`，不需要设备上预装任何管理器。
- **不按包名找管理器**：DikSU 的管理器可以在设备上改成随机包名；只有在没带随包副本时
  才回落到扫描已安装应用的 `libksud.so`（`extractNativeLibs=false` 时直接读 APK）。
- **不传 `--package-name`**：`libksud.so` 里烤着它自己的管理器包名，late-load 末尾用它
  `am start`；传一个猜的包名只会拉错。
- **管理页面只对本机开放**：ksud 绑 `127.0.0.1`，令牌落在 `/data/adb/ksu/webui.token`
  （0600 root）。root 脚本把它拼成 `http://127.0.0.1:<port>/?t=<token>` 写进
  `files/webui.url`（0600，属主是本 App），App 的「管理」按钮直接用 WebView 打开。
  这也是 `INTERNET` 权限唯一的用途，network security config 只对 `127.0.0.1` 放行明文。
- **重启后失效**：`late-load` 是内存态，不刷 boot 就没有持久 root；每次要用管理页面
  先跑一次「立即获取 Root 权限」。页面还活着的时候重复打开没问题（端口与令牌会复用）。

DikSU 的适配点：

| 差异 | 处理 |
|---|---|
| 管理器包名可在设备上随机化（`com.xxxxx.yyyyy`） | 不按包名匹配：优先用随包的 `libksud.so`，其次扫描全部已安装应用 |
| `libksud.so` 里烤着它自己的管理器包名 | **不传** `--package-name` |
| 内核模块仍是 `kernelsu.ko`，路径仍是 `/data/adb/ksu` | 脚本里的 `grep kernelsu /proc/modules`、模块目录逻辑不用改 |
| 官方 ko 矩阵包含 `android14-6.1` | 本机 KMI 正好命中；换成别的内核要换对应 KMI 的 ksud |
| WebUI 需要令牌 | root 脚本读完 `webui.port` / `webui.token` 后写进 App 私有目录 |

> **许可**：`libksud.so` 来自 [wuhudiao/DikSU](https://github.com/wuhudiao/DikSU)
> （GPL-3.0），以独立可执行程序的形式随包分发、被 `exec` 调用，未与 App 代码链接；
> 对应源码见该仓库 `userspace/ksud/`。App 自身仍是 Apache-2.0。若要二次分发，
> 请一并保留 DikSU 的 GPL-3.0 许可与源码出处。

---

## 5. 构建

前置：JDK 21、Android SDK、NDK（或云端 Actions 自带的 ONDK）。

```properties
# local.properties（不入库）
sdk.dir=<Android SDK>
KEYSTORE_PATH=<release keystore>
KEYSTORE_PASS=<...>
KEY_ALIAS=<...>
KEY_PASSWORD=<...>
```

```powershell
$env:JAVA_HOME    = '<JDK>'
$env:ANDROID_HOME = '<Android SDK>'

.\gradlew.bat assembleRelease --no-daemon
```

产物：`app/build/outputs/apk/release/XproSU-v1.1(109)-arm64-v8a-release.apk`

没有正式 keystore 时 release **直接构建失败**，不会回退到 debug 签名 ——
debug 证书是公开的，任何人都能签一个同名包覆盖安装并继承 `/data/data` 下的数据。

云端：`.github/workflows/build.yml`，`main` 的 push 或手动 dispatch 均可。

---

## 6. 与上游 `50d2b72` 的差异

1. `app/build.gradle.kts` —— `versionCode` 固定为手工值（当前 `109`），
   因为无 `.git` 目录构建时 `git rev-list --count HEAD` 会回退成 `1`。
2. `app/.../data/AndroidGhostlockRepository.kt` —— 运行前解密 `assets/offsets.enc`；
   路由由设置页控制（默认 `mcast`）。
3. **授权层整体移除**：`license/` 包（卡密、指纹、GLT2 容器、心跳、日志上传）
   已删除；`BuildConfig.LICENSE_BASE_URL`、network security config、`INTERNET`
   权限一并去掉。
4. **OTA / boot.img 解析**（上游更早版本的功能）不在本工程内。
5. 包名 `com.ghostlock.app` → `com.ghostlock.pro`；UI 重构为 Miuix 卡片式。

---

## 7. 红线

1. **签名密钥固定后再分发** —— 换签名要卸载重装，`/data/data` 里的日志与解出来的
   表都会丢。
2. **不要给引擎加人为超时** —— 这套竞速在慢机上需要的时间是不确定的，任何
   deadline/看门狗都会把「本来能成功」变成「失败」（`docs/private-deploy/` 有对照记录）。
3. **同一开机周期不要二跑** —— race 失败会留下悬空 PI 节点。
4. `src/kernels/offsets.h` 里 `task_cred` **必须显式给值** —— 缺键会回落到 6.6 的
   `0x900`，而它恰等于 6.1 的 `task_seccomp`，会把 root cred 写进 seccomp 字段。
5. **改 `src/` 就做 A/B** —— 时序敏感，任何重排都要与已验证的引擎逐行比对。

---

## 8. 上游参考

| 项 | 值 |
|---|---|
| 仓库 | `https://github.com/YuKongA/ghostlock-app` |
| 基线提交 | `50d2b72`（2026-09-12） |
| 为什么不用上游 `main` | `main` 已重构成 C++ 世代（`src/core/race/`、`route/`、`session/`），app 层只设 2 个环境变量、配置走 JSON profile —— 与本引擎接口不兼容 |
| 本工程与引擎的契约 | `exec` 调用 + `GHOSTLOCK_*` 环境变量 + `GHOSTLOCK_HOME/offsets.json` |
