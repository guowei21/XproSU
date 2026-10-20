# 构建与部署

> 本文是**唯一**的构建/部署操作手册。协议细节见
> [`stage2-protocol.md`](stage2-protocol.md)，商业化设计见
> [`../ENCRYPTION-PLAN.md`](../ENCRYPTION-PLAN.md)，U验证 对接见
> [`uverif-integration.md`](uverif-integration.md)。
>
> 三个部件：**App**（Kotlin/Compose）、**引擎**（C，打进 APK 的
> `libghostlock.so`）、**授权服务端**（`server/gl-license/`，纯 Python 标准库）。

---

## 0. 一句话流程

```
① 服务端：填 config.json（含 U验证 5 项）→ 生成 payload.bin → 生成卡密 → 启动
② App   ：填 local.properties 的 LICENSE_BASE_URL → 构建 → 装到设备
③ 设备  ：打开 App → 登录窗口输入卡密 → 服务端下发本机专属载荷 → 进入主界面
```

---

## 1. 前置条件

| 部件 | 需要 |
|---|---|
| App | JDK 21、Android SDK（compileSdk 37）、`aarch64` 工具链（仅重建引擎时需要） |
| 引擎 | Android NDK r27（含 `clang` / `ld.lld`）。**本机没有 `make`，见 §3.2** |
| 服务端 | Python 3.10+，**无第三方依赖**（不需要 pip install） |
| 设备 | 6.1.145 内核的 vivo X100 Pro（V2324A），Android 14+ |

---

## 2. 服务端部署

### 2.1 目录与配置

```powershell
# 把 server/gl-license 整个目录拷到服务器上，然后：
cd server/gl-license
copy config.example.json config.json
```

`config.json` 的六项要点：

```json
{
  "listen_host": "0.0.0.0",
  "listen_port": 8787,
  "admin_key": "<改成你自己的管理口令>",
  "master_key": "<64 hex，服务端主密钥，生成一次后永不变更>",
  "payload_path": "payload.bin",
  "db_path": "cards.db",
  "uverif": {
    "base_url": "https://<你的U验证地址>",
    "app_id": "<应用 ID>",
    "app_index": "<版本索引>",
    "app_ver": "<版本号>",
    "app_key": "<应用密钥>",
    "aes_key": "<16 字节 AES 密钥，必须与 U验证 后台该应用的设置一致>"
  }
}
```

> **`master_key` 是全局主密钥**：所有设备的载荷密钥都由它派生。
> 泄露 = 所有卡密作废；丢失 = 已发出的载荷再也无法重签。**先备份再上线。**
> 生成方式：`python -c "import secrets;print(secrets.token_bytes(32).hex())"`

> U验证 后台为「应用」**必须选 AES 加密方式**，并填同一把 16 字节密钥。
> 选成 RSA / 无加密 / DES 都连不上（见 `uverif-integration.md` §1）。

### 2.2 生成 `payload.bin`（明文偏移表 → 服务端载荷）

`payload.bin` 是**明文**表，只存在于服务端，绝不进 APK、绝不进仓库。
如果手上只有出货用的 stage-1 容器（`offsets.glt`），先把它解回明文：

```powershell
# 1) 从 stage-1 容器解出明文表（PC 侧工具，不随包分发）
python ..\..\tools\glt1_extract.py <path\to\offsets.glt> -o table.json

# 2) 打成服务端载荷
python admin.py build-payload --table table.json
# -> wrote payload.bin (N bytes, M release(s))
```

### 2.3 生成卡密

```powershell
python admin.py gen --days 365 --count 10
```

卡密格式 `XXXXX-XXXXX-XXXXX-XXXXX`（20 字符 Base32）。数据库里**只存 SHA-256**，
不存原文，所以生成后必须立刻抄走——丢了没法找回，只能重新生成。

### 2.4 启动

```powershell
python server.py --config config.json
# 或后台跑： python server.py --config config.json > gl-license.log 2>&1 &
```

systemd 单元示例（`/etc/systemd/system/gl-license.service`）：

```ini
[Unit]
Description=GhostLock licence service
After=network.target

[Service]
WorkingDirectory=/opt/gl-license
ExecStart=/usr/bin/python3 /opt/gl-license/server.py --config /opt/gl-license/config.json
Restart=always
User=gllicense

[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload && systemctl enable --now gl-license
```

防火墙放行 `listen_port`。若前面套 Nginx/Caddy，记得把请求体大小限制放到 ≥ 64 KB
（服务端自身也限制 64 KB）。

### 2.5 服务端自检（**上线前必须全绿**）

```powershell
cd server\gl-license
python selftest.py       # 密码学 + 线路格式，10 项，必须 ALL PASSED
python uverif_probe.py   # 实连 U验证，确认 AES 握手通（期望 code != 0 + 可读 msg）
python smoke_test.py     # 端到端：Kd → GLT2 → 解密回原文
python wire_smoke.py     # 二进制/JSON 双格式各打一次
```

`uverif_probe.py` 的判读：

| 输出 | 含义 |
|---|---|
| `HANDSHAKE OK — upstream rejected the card as expected` | ✅ 正常。协议全对，只是探针卡密不存在 |
| `UNREACHABLE` | DNS / TLS / 超时，协议没被验证到 |
| 密码学错误 / JSON parse 失败 | `app_key` / `aes_key` / 后台加密方式不匹配 |

---

## 3. App 构建

### 3.1 `local.properties`

```properties
sdk.dir=<Android SDK 路径>
LICENSE_BASE_URL=https://<授权服务对外地址>
```

`LICENSE_BASE_URL` **在构建期烧进 `BuildConfig`**，运行时不可改——否则用户把地址
指向自己的假服务就能绕开全部校验。留空 = 未配置，激活时明确报错，不会静默放行。

> U验证 的 5 项凭据**不在 App 里**。App 只跟自建授权服务说话，U验证 退到
> 服务端到服务端（按设备派生载荷密钥只能在服务端做）。

### 3.2 构建引擎（`libghostlock.so`）

有 `make` + NDK 时：

```powershell
$env:ANDROID_NDK_HOME = '<NDK>'
make ghostlock          # 产出 ./ghostlock
copy ghostlock app\src\main\jniLibs\arm64-v8a\libghostlock.so
```

**没有 `make` 时**（本项目开发机的实际情况）直接用 NDK 的 clang/ld.lld 编，
用 `$env:PI_SCRATCH_DIR` 之外的任意临时目录即可，脚本形状如下：

```powershell
$NDK='D:\XM\GJ\android-ndk-r27d'; $API=35
$PRE="$NDK\toolchains\llvm\prebuilt\windows-x86_64"; $SYS="$PRE\sysroot"
$LIB="$SYS\usr\lib\aarch64-linux-android\$API"
$BIN="$PRE\lib\clang\18\lib\linux\libclang_rt.builtins-aarch64-android.a"
# 逐文件：-c --target=aarch64-linux-android$API --sysroot=$SYS
#         -O2 -flto -Isrc/core -Isrc/kernels -DTARGET_CONFIG_H=<target.h> -fPIE -pthread
# 链接：ld.lld --sysroot=$SYS -EL -z now -z relro --build-id -m aarch64linux -pie
#         -dynamic-linker /system/bin/linker64 -o ghostlock <objs> $BIN -ldl -lc $BIN -ldl
```

`-DTARGET_CONFIG_H=<target.h>` 用**尖括号**，别用引号：PowerShell 传参会吃掉内嵌
双引号，`#include "target.h"` 会变成语法错误。

调试构建加 `-DGL_VERBOSE`：会额外编入 stage-1 容器读取器和
`--crypto-selftest` / `--offsets-verify` 两个离线校验入口。
**发布构建不要加**（那些入口会把字段名带回二进制）。

### 3.3 构建 APK

```powershell
$env:JAVA_HOME='<JDK21>'; $env:ANDROID_HOME='<SDK>'
.\gradlew.bat assembleDebug   -x :buildGhostlockNative --no-daemon
.\gradlew.bat assembleRelease -x :buildGhostlockNative --no-daemon
```

`-x :buildGhostlockNative` 跳过 `make`（§3.2 已手工编好并放进了 `jniLibs/`）。
产物：

```
app/build/outputs/apk/debug/GhostLock-v1.1(93)-arm64-v8a-debug.apk
app/build/outputs/apk/release/GhostLock-v1.1(93)-arm64-v8a-release.apk
```

**Release 签名**：`app/build.gradle.kts` 会读 `local.properties` 的
`KEYSTORE_PATH / KEYSTORE_PASS / KEY_ALIAS / KEY_PASSWORD`。**没有就构建失败**，不回退 debug 签名。

正式 keystore 已生成并接入：

| 项 | 值 |
|---|---|
| 文件 | `<离线保存的 keystore 路径>` —— **在源码树外**（它和 `master_key` 是两把总钥匙，放同一个目录等于一起送人） |
| 别名 | `ghostlock` |
| 算法 | RSA 4096 / SHA256withRSA / PKCS12 |
| 有效期 | 至 2056-10-04（10,950 天） |

`KEYSTORE_PATH` 写的是相对 `app/` 模块的路径（`../../<keystore-dir>/keystore.jks`）。**不要写绝对
路径**：工程路径含非 ASCII，而 `local.properties` 按 ISO-8859-1 解析，中文路径会被读坏。
（找不到 keystore 时 release 构建现在会**直接失败**，不会静默回退 debug 签名。）

⚠️ **keystore 目录与 `local.properties` 立刻离线备份两处**。丢失 = 永远无法再
更新已售出的 App（用户只能卸载重装；且换签名会改 Widevine DRM ID → 已绑定卡密全部失效）。

> 一个 AGP 行为，别误判成配置没生效：`minSdk = 34` 时 `enableV3Signing = true` 会让 AGP
> **只出 v3、省掉 v2**（v3 已覆盖 v2）。实测把 `enableV3Signing` 关掉才会出 v2。

### 3.4 服务端部署（现状）

`server/gl-license/` 已部署在 `<server-host>` 上：

```
CDN(EdgeOne) <license-host> --HTTPS--> <edge-nginx>:8080 --/gl/--> gl-license:8787
```

- 宿主 Python 只有 3.5.3（`gl-license` 需 3.8+），所以跑在容器里：`python:3.12-alpine`，
  代码与数据挂 `/opt/gl-license`，`--network uverif-net`，`-p 127.0.0.1:8787:8787`，
  `--restart unless-stopped`。
- 对外入口走 `uverif-web` 的 nginx：`location ^~ /gl/` → `proxy_pass http://$gl_upstream`，
  用变量 + `resolver 127.0.0.11`，这样 `gl-license` 容器不在时 nginx 仍能启动。
- App 侧 `LICENSE_BASE_URL=https://<license-host>/gl`，全链路 HTTPS、不放行任何明文。
- **8787 那个端口**是 `server.py` 自己的监听端口（`config.json: listen_port`），不是网站
  端口；对外不需要暴露它 —— nginx 在同一个 `uverif-net` 里直接按容器名访问。

运维命令（宿主 Python 太老，管理命令在容器里跑）：

```bash
docker logs --tail 100 gl-license
docker restart gl-license
docker exec gl-license python admin.py list
docker exec gl-license python admin.py gen --days 365 --count 10
docker exec gl-license python admin.py rebind --card XXXXX-XXXXX-XXXXX-XXXXX --device-fp none

# 改完服务端代码必跑这两个
docker exec gl-license python selftest.py
docker exec gl-license python negative_test.py

# 备份
/opt/gl-license/backup.sh
ls -l /opt/gl-license/backups/
```

**管理接口只允许宿主内部访问**：nginx 里有 `location ^~ /gl/api/admin/ { return 403; }`，
公网/CDN 一律 403（实测）。需要远程管理就走 SSH 隧道：

```bash
ssh -L 8787:127.0.0.1:8787 sg
# 本地再 curl http://127.0.0.1:8787/api/admin/list -H 'Authorization: Bearer <admin_key>'
```

**备份**：`/opt/gl-license/backup.sh` 用 sqlite3 的在线备份 API（在容器里跑，避免拷到写了一半的库），
每天 04:17 由 `/etc/cron.d/gl-license-backup` 触发，`cards.db` / `config.json` / `payload.bin`
各保留最近 14 份在 `/opt/gl-license/backups/`。⚠️ **备份和原库在同一块盘上**，要抗整机故障必须
再往异机同步一份。

**权限**：`config.json` 与 `payload.bin` 必须 `600`，`cards.db` 用 `640`。`payload.bin` 就是
明文偏移表，而这台机器上还跑着 `3x-ui` / `cliproxyapi` 这类第三方面板容器，权限一松就是全盘泄漏。

⚠️ **改 `default.conf` 不要用 `mv` / `sed -i` 换文件**：它是单文件 bind mount，绑的是
**inode**。换文件后容器里看到的仍是旧内容，现象是 `nginx -t` 通过、`reload` 无报错，
但新 `location` 不生效。就地写（`cat new > conf`）或改完 `docker restart uverif-web`。

---

## 4. 端到端联调清单

装到设备后按顺序过一遍，每步都有可观察的结果：

| # | 操作 | 期望 |
|---|---|---|
| 1 | 冷启动 App | 直接进**登录窗口**（不是主界面） |
| 2 | 看登录窗口的设备码 | `XXXX-XXXX-XXXX-XXXX`，与「关于」无关、可复制 |
| 3 | 输入错误卡密 | 停在登录窗口，显示服务端返回的原因 |
| 4 | 输入正确卡密 | 提示激活成功 → 自动进主界面 |
| 5 | 主界面授权卡 | 状态「已永久激活」+ 有效期 |
| 6 | 点主按钮 | 进度推进到 100%，`su` 可用 |
| 7 | 杀掉 App 重开 | 直接进主界面（不重复要求激活） |
| 8 | `adb shell am start -n com.ghostlock.pro/.ui.MainActivity` | 未授权时被弹回登录窗口 |
| 9 | 清 App 数据后重开 | 回到登录窗口，且**旧卡密绑定的设备码不变** |

引擎侧离线校验（调试构建，PC 上经 adb 跑）：

```bash
adb push ghostlock-verbose /data/local/tmp/glv && adb shell chmod 755 /data/local/tmp/glv
adb shell "/data/local/tmp/glv --crypto-selftest"
#   chacha20_selftest / poly1305_selftest / chacha20_poly1305_selftest 全 = 0

adb shell "GHOSTLOCK_RELEASE=<release> /data/local/tmp/glv --offsets-verify \
  /data/local/tmp/<blob> <kd_hex> <device_fp_hex> <card_tag_hex>"
#   verify.load=0 且各字段与明文表一致
```

---

## 5. 排错

| 现象 | 原因 | 处理 |
|---|---|---|
| 登录窗口提示「未配置授权服务」 | 构建时 `LICENSE_BASE_URL` 为空 | 填 `local.properties` 后重新构建 |
| 激活报 `HTTP 404` | 服务端路径或地址不对 | 确认 `LICENSE_BASE_URL` 指向 `server.py` 的根 |
| 激活报 `1004 上游校验服务不可用` | U验证 连不上 | 在服务器上跑 `python uverif_probe.py` |
| 激活报「该卡密无法解锁本机载荷」 | 服务端 `master_key` 变过，或设备指纹变了 | 核对 `master_key` 是否被改；确认是否换过签名/刷过机 |
| 激活成功但跑提权报 `not activated` | 载荷文件没写进去 | 检查 App 私有目录可写；看 `offsets.glt` 是否存在 |
| 引擎报 `not a GLT2 container` | 设备上留着 stage-1 的旧文件 | 清除 App 数据，重新激活 |
| 引擎报 `bound to a different device` | 载荷被拷到别的设备 | 正常拦截，不是故障 |
| 引擎报 `card key does not match this payload` | 载荷与当前卡密不匹配 | 正常拦截；确认这台设备用哪张卡激活的 |
| `gradlew` 报路径含非 ASCII | 工程路径有中文 | `gradle.properties` 里 `android.overridePathCheck=true` 已开 |

---

## 6. 运维

| 任务 | 命令 |
|---|---|
| 列出卡密（只显示哈希） | `python admin.py list` |
| 解绑 / 改绑 | `python admin.py rebind --card XXXXX-XXXXX-XXXXX-XXXXX --device-fp <64hex\|none>` |
| 补卡 | `python admin.py gen --days 365 --count N` |
| 备份 | 备份 `config.json`（尤其 `master_key`）与 `cards.db` |

**手动解绑是刻意保留的**：误绑、换机、损坏都需要救济；「不允许解绑」约束的是
用户侧没有入口，不是管理员没有权限。

**永远不要**：把 `master_key`、`payload.bin`、`cards.db` 放进任何交付物；
把 U验证 凭据写进 App；在没有备份 `master_key` 的情况下换服务器。
