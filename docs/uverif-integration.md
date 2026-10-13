# U验证（uverif.com）授权接入说明

> **结论**：App 已接完 U验证 的**卡密鉴权闭环**，代码可编译、可构建 Debug/Release，
> 服务端是唯一裁决方。剩余唯一动作是：把自建服务的 6 项凭据填进 `local.properties` 后重新构建。
> 未填凭据时 **Release 一律 fail-closed**（点激活明确提示「未配置授权服务」），不会静默放行。

---

## 1. 协议（AES 模式）

U验证 后台为每个「应用」可配置多种传输加密方式。本工程实现的是官方 Python SDK
对应的 **AES-128-CBC + MD5 签名**模式（与官方 C SDK 的 `app_enc=1` RSA 模式、
uni-app 生成代码的无加密模式不同，**三者不能混用**）。

```
POST {base}/api/user/{app_id}/{app_index}/{app_ver}/{api}
Content-Type: application/x-www-form-urlencoded

body: data=<hex(IV16 ‖ AES-128-CBC-PKCS7(payload))>&sign=<md5(payload + app_key)>

payload = 键值对按插入序 urlencode 拼接，time 固定追加在最后：
          account=..&password=..&udid=..&time=<unix 秒>
```

响应：

```json
{ "code": 0, "msg": "ok", "time": 1760000000, "data": "<hex>", "sign": "<md5>" }
```

- `code == 0` 为成功，其余为业务拒绝（`msg` 可直接展示给用户）；
- `data` 用**同一把 AES 密钥**解密后是 JSON；
- `logon` 的明文形如 `{"token":"..","state":"y","info":{"acctno":"..","fen":0,"vipExpDate":"2026-12-31 23:59:59",..}}`；
  `vipExpDate` 在 **`info` 子对象**里，本实现两者都兼容。

### 接口

| 接口 | 参数 | 用途 |
|---|---|---|
| `logon` | `account` / `password` / `udid` | 卡密即账号：三项都传卡密（`udid` 传本机标识） |
| `heartbeat` | `token` | 保活，服务端据此判定在线 |
| `info` | `token` | 刷新 `state` / `vipExpDate` |

---

## 2. 服务端（自建 U验证 后台）必须做的事

1. 建「应用」，记下 **应用 ID**、**版本索引**（建应用时填的那个，如 `ce`）、**版本号**（如 `1.0.0`）、**应用密钥**。
2. 该应用的**加密方式必须选 AES**，并填一把 **16 字节**密钥 —— 这把密钥要原样填进 `UVERIF_AES_KEY`。
   - 密钥按 UTF-8 计字节数，必须正好 16 字节（例：`QKR6SwTSfWTvidy1`）。
3. 生成卡密（卡密即账号，账号名 = 卡密本身，密码同值）。
4. 若后台开启「在线模式/单点登录」，同一卡密在多台设备上会被踢 —— 这正好是「一机一码」的天然约束。

> 服务端只需 `logon` / `heartbeat` / `info` 三个接口，其余（`goods` / `order` / `pay` …）本工程不调用。

---

## 3. 凭据填写

`app/build.gradle.kts` 在**构建期**把 6 项注入 `BuildConfig`，运行时从 `local.properties`
（或同名环境变量）读取。缺任意一项，或 AES 密钥不是 16 字节 → 客户端为 `null` → 激活报「未配置」。

```properties
# local.properties（不入库，勿外传）
sdk.dir=D\:\\XM\\GJ\\android-sdk
UVERIF_BASE_URL=http://你的服务器IP:端口
UVERIF_APP_ID=1000
UVERIF_APP_INDEX=ce
UVERIF_APP_VER=1.0.0
UVERIF_APP_KEY=<应用密钥>
UVERIF_AES_KEY=<16 字节 AES 密钥>
```

```powershell
.\gradlew.bat assembleDebug -x :buildGhostlockNative --no-daemon
.\gradlew.bat assembleRelease -x :buildGhostlockNative --no-daemon
```

> `-x :buildGhostlockNative` 是因为本机没有 `make`；`.so` 已预置在
> `app/src/main/jniLibs/arm64-v8a/libghostlock.so`，`prepareGhostlockJniLibs` 只做拷贝。

---

## 4. 客户端实现

| 文件 | 职责 |
|---|---|
| `license/UVerifClient.kt` | 协议实现：AES-128-CBC + PKCS7、IV 前置、MD5 签名、URL 组装、`code != 0` 抛 `UVerifRejected`、传输/解析失败抛 `UVerifTransport` |
| `license/DeviceFingerprint.kt` | 本机标识：Widevine `MediaDrm.PROPERTY_DEVICE_UNIQUE_ID` 优先，退化 ANDROID_ID+Build 字段；SHA-256 前 16 hex，格式 `XXXX-XXXX-XXXX-XXXX` |
| `license/LicenseStore.kt` | 凭据落盘：Android Keystore（TEE）AES-GCM 加密后写 SharedPreferences；解密失败即清空视为未授权 |
| `license/LicenseRepository.kt` | `activate()` / `heartbeat()` / `refresh()` / `configured` / `isActivated()`；卡密即账号调 `logon` |
| `ui/GhostlockViewModel.kt` | 激活流程、60 s 保活轮询、进度映射、日志分级 |
| `ui/GhostlockUi.kt` | 授权卡片（设备码 / 到期时间 / 未配置提示）、核心对选择、进度面板 |
| `GhostlockApplication.kt` | 组合根：凭据缺失或 AES 密钥非 16 字节 → `UVerifClient` 为 `null` |

### 运行行为

- **激活**：UI「激活卡密」→ `logon(account=卡密, password=卡密, udid=设备码)` → 成功则 Keystore 加密落盘。
- **保活**：每 60 s `heartbeat` + `info`。
  - 服务端**明确拒绝** → 收回本地授权（`store.clear()`）；
  - **传输失败**（离线 / 服务端不可达）→ 保持现状，不误伤已付费用户（稳定性优先）。
- **换机**：凭据里存了本机标识，与当前设备不符直接作废，配合服务端校验实现一机一码。
- **Debug / Release 分级**：
  - Debug：明文运行日志可见（终端卡片 + 底部日志面板）；
  - Release：不显示任何运行日志，只显示**百分比 + 阶段名**进度；
    R8 + 资源收缩会**连日志字符串一起从 APK 里删掉**（实测 `console_title` / `action_clear` 在 Release 资源表中不存在）。
- **Debug 放行**：仅在 `BuildConfig.DEBUG && 未配置服务` 时放行，便于本地调试；Release 永不放行。

---

## 5. 实测证据（本轮）

| 检查项 | 结果 |
|---|---|
| `assembleDebug` | ✅ `app/build/outputs/apk/debug/GhostLock-v1.1(93)-arm64-v8a-debug.apk`（63,671,182 B） |
| `assembleRelease` | ✅ `app/build/outputs/apk/release/GhostLock-v1.1(93)-arm64-v8a-release.apk`（2,564,725 B，R8 + 资源收缩） |
| 包名 / 入口 | `com.ghostlock.pro` / `com.ghostlock.pro.ui.MainActivity` |
| `usesCleartextTraffic` | `true`（自建服务多为 `http://IP:PORT`，否则 Android 9+ 直接拒连） |
| `INTERNET` 权限 | 存在 |
| Release 日志字符串 | `console_title` / `action_clear` 已从资源表消失（R8 判定 Debug-only 路径为死代码） |
| Release 明文偏移扫描 | `classes.dex` / `libghostlock.so` 中 `task_seccomp` / `off_init_cred` / 偏移数值 = **0 命中** |
| 载荷 | `assets/offsets.glt`（940 B）+ `lib/arm64-v8a/libghostlock.so`（74,840 B）在包内 |

---

## 6. 尚未做（明确记录，避免误解）

1. **未实连**：尚无用户自建服务的 6 项凭据，`logon` 链路只做了协议级核对（官方 C/Go/Python/uni-app 四份 SDK 逐字段比对），**没有对真实服务端跑通一次激活**。
2. **响应 `sign` 未校验**：官方 C SDK 会校验 `md5(code + time + app_key)`。本实现依赖 AES-CBC + PKCS7 + JSON 解析作为隐含完整性校验（伪造的 `data` 无法通过解密），未额外校验 `sign`。若要求更强，可加。
3. **`http://` 明文传输**：为兼容自建 `http` 服务放开了 cleartext。若服务端有证书，建议改 `https://`。
4. **Release 签名**：当前未提供 release keystore，`assembleRelease` 回退用 debug 签名。**卖出第一个卡密前必须固定正式签名**（换签名可能改 Widevine DRM ID → 已绑定卡密全部失效）。
5. **阶段②（载荷按设备加密）**：`ENCRYPTION-PLAN.md` 的 HKDF + ChaCha20-Poly1305「每设备一份载荷」尚未实施；当前 `.glt` 仍是全设备同一份（抗 `strings`，不抗逆向者提取密钥后解密）。
