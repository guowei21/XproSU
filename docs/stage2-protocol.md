# 阶段② 协议冻结（GLT2 / GLP / 激活 API）

> **状态：冻结。** 本文件是客户端（Kotlin）、引擎（C）、服务端（Python）三方的唯一接口依据。
> 任何一方改动都必须先改本文件，并同步更新 §7 测试向量。
>
> 设计依据见 [`../ENCRYPTION-PLAN.md`](../ENCRYPTION-PLAN.md) §3–§4。

---

## 1. 目标

把「门（卡密鉴权）」和「锁（数据加密）」焊成一体：

```
现在（阶段①）  : 偏移表密文全设备同一份 + 密钥在 .so 里  → 拆包即得
阶段②之后      : 偏移表按设备加密，密钥由服务端派生下发 → 没激活 = 手里没有数据
```

**没有内置载荷。** APK 里不再有任何可用的偏移数据；未激活时引擎拿不到明文，
不是「被 if 拦住」，是**数据不存在**。

---

## 2. 角色与密钥

| 名称 | 长度 | 谁持有 | 说明 |
|---|---|---|---|
| `master_key` | 32 B | **仅服务端** | 随机生成一次，永不下发、不进 APK |
| `card_key` | 变长字符串 | 用户 / 服务端 | 卡密原文；服务端只存 `SHA-256(card_key)` |
| `device_fp` | 32 B | 设备 / 服务端 | 见 §3 |
| `Kd` | 32 B | 服务端算出 → 加密下发给该设备 | `HKDF-SHA256(master_key, salt=SHA256(card_key), info=device_fp, L=32)` |
| `Kp` | P-256 密钥对 | 设备 TEE（私钥不可导出） | 用于包裹 `Kd`；公钥随激活请求上传 |
| `expire` | u64 秒 | 服务端 | 卡密到期时间；`0` = 永久 |

**派生（全部 SHA-256 / HKDF-SHA256，RFC 5869）**

```
salt_card = SHA-256(card_key)                    # 32 B
Kd        = HKDF-SHA256(ikm=master_key, salt=salt_card, info=device_fp,      L=32)
kek       = HKDF-SHA256(ikm=ECDH_x,     salt=salt_card, info="GL-KDW1",      L=32)
```

`info=device_fp` 与 `salt=salt_card` 同时绑定 → 换设备或换卡密都得不到同一个 `Kd`。

---

## 3. 设备指纹 `device_fp`

**唯一来源**：Widevine `MediaDrm.PROPERTY_DEVICE_UNIQUE_ID` 的**原始 32 字节**。
取不到就 fail-closed（拒绝激活）——**没有退化方案**：退化的
`SHA-256(ANDROID_ID | BRAND | MODEL | …)` 里 ANDROID_ID 按「签名 + 用户」计算，
换一次签名重装就等于换了台机器，同时给「一机一号」和「一机一次试用」开后门。

- `device_fp` 是**二进制 32 字节**，线路上用 **小写 hex（64 字符）** 表示。
- 它是**绑定凭证**：谁读到原始值，谁就能替这台设备重放一次激活。因此
  **任何管理端响应都不再回传原始值**（2026-10-13 起）：后台 / JSON 管理 API / CLI
  只给 `device_fp_mask = SHA-256(小写 hex 字符串)[:16].upper()`。
- UI 与工单用的「设备码」就是这个 `device_fp_mask`（App 侧 `DeviceFingerprint.code()`，
  与 `server.py:mask_device_fp` 逐字节一致）：推导不回 32 字节指纹，**不参与**任何
  密码学计算，也不能用于绑定/换绑。
- 引擎侧拿到的是**原始 32 字节**（App 经 `GHOSTLOCK_DEVICE_FP` 传），用于比对 GLT2
  容器头（`src/core/offsets_bin.c` 的 `GLT2_DEVICE_FP_OFF`）。
- 稳定性：设备级 provisioning，卸载重装 / 清数据 / 恢复出厂**通常不变**，但这不是官方
  承诺（软件 Widevine、刷机、云手机可能会变）。因此绑定语义是：
  **同一个 `device_fp` 允许换公钥**（重装后 Keystore 必出新密钥对），
  **不同 `device_fp` 一律拒绝**（`1002`），且**不提供换设备通道**（`allow_device_rebind=false`）。

---

## 4. GLP —— 服务器上的明文载荷（`payload.bin`）

服务器持有一份**明文**表（不进 APK、不进仓库）。所有整数小端。

```
GLP 头 (8 B)
  0..3   magic  "GLP1"
  4      version = 1
  5      reserved = 0
  6..7   entry_count u16

entry 头 (8 B)  × entry_count
  0..3   release_hash u32   = FNV-1a-32(release 字符串)
  4..5   field_count u16
  6..7   reserved = 0

field (10 B) × field_count
  0..1   id u16             见 §4.1
  2..9   value u64          明文数值
```

`release_hash` 用 FNV-1a-32（offset basis `0x811C9DC5`，prime `0x01000193`），
与引擎 `glt_release_hash()` 一致 —— **release 字符串本身不进文件**。

### 4.1 字段 id（与 `src/core/offsets_bin.c` 的 `enum glt_fid` 完全一致）

```
0x11 kernel_phys_load      0x12 pselect_waiter_shift
0x21 off_init_task         0x22 off_init_cred        0x23 off_root_task_group
0x24 off_selinux_enforcing 0x25 off_selinux_blob_sizes
0x26 off_security_hook_heads
0x27 off_slide_nfulnl_logger 0x28 off_slide_loggers_0_1 0x29 off_slide_boot_id
0x31 off_tp_sys_exit_tp    0x32 off_tp_sys_exit_funcs
0x41 task_prio             0x42 task_normal_prio      0x43 task_sched_task_group
0x44 task_pi_lock          0x45 task_pi_waiters       0x46 task_pi_top_task
0x47 task_pi_blocked_on    0x48 task_pid              0x49 task_tgid
0x4A task_atomic_flags     0x4B task_real_cred        0x4C task_cred
0x4D task_comm             0x4E task_tasks            0x4F task_seccomp
0x51 compact_waiter        0x52 mm_struct_sz
```

---

## 5. GLT2 —— 按设备加密的容器

```
GLT2 文件 = header(64) ‖ nonce(12) ‖ ciphertext(n) ‖ tag(16)

header (64 B, 全部小端)
  0..3    magic  "GLT2"
  4       version = 2
  5       flags   = 0x02  (AEAD)
  6..7    reserved = 0
  8..15   expire u64            # 0 = 永久
  16..47  device_fp[32]
  48..63  card_tag[16]          # SHA-256(card_key) 的前 16 字节

nonce       12 B   随机，每份密文唯一，绝不复用
ciphertext  n B    ChaCha20-Poly1305(Kd, nonce, AAD=header, plaintext=GLP)
tag         16 B   Poly1305
```

**`AAD = header` 是「一机一码 + 一卡一密」的密码学实现**：`device_fp`、`card_tag`
与 `expire` 都在 header 里，被 Poly1305 认证。改设备指纹、改卡密绑定、改到期时间
→ **解密直接失败**。

引擎在解密**之前**还要做两次明文比对，这两条 AEAD 自己挡不住：

1. `header.device_fp == 本机 device_fp` —— 挡「把 blob 连同 Kd 一起拷到别的设备」；
2. `header.card_tag == SHA-256(用户输入的卡密)[:16]` —— 挡「跳过登录直接喂密钥」。

第 2 条是「卡密同时管门和偏移解密」的落点：容器与卡密在密码学上绑死，登录分支被
patch 掉也拿不出这个值，引擎拒绝解密。注意 `Kd` 本身也已经通过 HKDF 的
`salt = SHA-256(card_key)` 与卡密绑定，所以两把钥匙缺一不可 —— 换成另一张卡的 `Kd`
会在认证阶段失败，伪造绑定值会在比对阶段失败。

---

## 6. `Kd` 的包裹（ECIES / ECDH-ES）

客户端**不能**直接收明文 `Kd`（自建服务多为 `http://`，明文可嗅探）。

```
wrapped = eph_pub(65) ‖ nonce(12) ‖ ct(32) ‖ tag(16)        # 共 125 B

eph_pub      P-256 一次性公钥，未压缩点 0x04‖X(32)‖Y(32)
ECDH_x       = X 坐标(ECDH(eph_priv, Kp_pub))                # 32 B
kek          = HKDF-SHA256(ikm=ECDH_x, salt=SHA256(card_key), info="GL-KDW1", L=32)
nonce        12 B 随机
AAD          = eph_pub (65 B)
plaintext    = Kd (32 B)
```

客户端在 AndroidKeyStore 里生成 **EC P-256**（`secp256r1`）密钥对，私钥不可导出；
`KeyAgreement("ECDH")` + `Cipher("ChaCha20/Poly1305/NoPadding")` 解出 `Kd`。

---

## 7. 测试向量（三方必须逐字节一致）

### 7.1 HKDF-SHA256（RFC 5869 Test Case 1）

```
ikm  = 0b0b…0b (22 B of 0x0b)
salt = 000102030405060708090a0b0c (13 B)
info = f0f1f2f3f4f5f6f7f8f9 (10 B)
L    = 42
OKM  = 3cb25f25faacd57a90434f64d0362f2a
       2d2d0a90cf1a5a4c5db02d56ecc4c5bf
       34007208d5b887185865
```

### 7.2 ChaCha20-Poly1305 AEAD（RFC 8439 §2.8.2）

```
plaintext = "Ladies and Gentlemen of the class of '99: If I could offer you
             only one tip for the future, sunscreen would be it."
aad       = 50515253c0c1c2c3c4c5c6c7
key       = 808182838485868788898a8b8c8d8e8f
            909192939495969798999a9b9c9d9e9f
iv        = 4041424344454647   (4 B fixed field, §2.8 用 12 B nonce 时省略)
nonce     = 070000004041424344454647   (12 B)
ciphertext = d31a8d34648e60db7b86afbc53ef7ec2
             a4aded51296e08fea9e2b5a736ee62d6
             3dbea45e8ca9671282fafb69da92728b
             1a71de0a9e060b2905d6a5b67ecd3b36
             92ddbd7f2d778b8c9803aee328091b58
             fab324e4fad675945585808b4831d7bc
             3ff4def08e4b7a9de576d26586cec64b
             6116
tag        = 1ae10b594f09e26a7e902ecbd0600691
```

### 7.3 P-256 ECDH（本机用 JDK 交叉验证，见 `tools/verify_crypto/`）

随机标量对拍：Python 侧 `scalar_mult(G, d)` 与 JDK `KeyAgreement("ECDH")`
必须得到相同 X 坐标。**不是固定向量，而是逐次随机对拍**（避免抄错常数）。

### 7.4 端到端固定向量（`tools/verify_crypto/vectors.json`）

`master_key` / `card_key` / `device_fp` / `expire` 固定，输出 `Kd`、`GLT2` 全文件 hex、
`wrapped` hex。三方实现都必须复现同一串字节。

---

## 8. 激活 API（App ↔ 自建服务）

自建服务是 App 唯一的对端；U验证 只在**服务端到服务端**使用。

### 8.0 线路格式：二进制，不是 JSON

**App 只发二进制。** JSON 的键名（`card`、`device_fp`、`token`、`wrapped`…）会
自描述整套授权数据结构，留在 dex 里等于把协议白送出去；字段一律改成**不连续的不透明
标签 + 二进制值**（Kotlin 侧 `license/GlBlob.kt`，服务端 `wire.py`）：

```
0..3    magic   u32 LE = 0x9E4B37A1
4       version u8     = 1
5       kind    u8     1 = 请求, 2 = 响应
6..7    code    u16 LE 业务码（请求恒 0）
8..9    count   u16 LE TLV 条目数
10..11  reserved u16   = 0
之后    count × (tag u16 LE | len u16 LE | value)
```

| 方向 | tag | 值 |
|---|---|---|
| 请求 | `0x21` | 卡密（UTF-8） |
| 请求 | `0x22` | device_fp（64 hex 文本） |
| 请求 | `0x23` | pubkey（130 hex 文本，未压缩 P-256 点） |
| 请求 | `0x24` | app_ver |
| 请求 | `0x35` | token（heartbeat） |
| 响应 | `0x31` | token |
| 响应 | `0x32` | expire（**u64 LE 二进制**） |
| 响应 | `0x33` | blob（GLT2 全文件原始字节） |
| 响应 | `0x34` | wrapped（125 B 原始字节） |
| 响应 | `0x41` | msg（UTF-8，失败原因） |

`Content-Type: application/octet-stream`。**服务端同时接受 JSON**（便于 curl 调试），
并按请求的格式回；响应的 `code` 在二进制包里走 header 字段。

> 混淆的是**字段**，不是机密性。真正的机密性来自：本地记录整块经 Keystore AES-GCM
> 加密后落盘，线路上的载荷由 GLT2 的 AEAD 保护，`Kd` 由 ECIES 包裹。

### 8.1 `POST /api/activate`

请求（二进制包，kind=1）：

```
0x21 card | 0x22 device_fp | 0x23 pubkey | 0x24 app_ver
```

`pubkey` = 未压缩 P-256 点，`0x04‖X(32)‖Y(32)`，65 B → 130 hex。

成功响应（kind=2，code=0）：

```
0x31 token | 0x32 expire(u64 LE) | 0x33 blob | 0x34 wrapped
```

失败响应：header 的 `code` 非 0，附 `0x41` msg。

**等价的 JSON 形式**（仅供调试，服务端仍接受）：

```json
{"card":"XXXX-XXXX","device_fp":"<64 hex>","pubkey":"<130 hex>","app_ver":"1.1"}
{"code":0,"msg":"ok","token":"<32 hex>","expire":1760000000,"blob":"<hex>","wrapped":"<hex>"}
```

| code | 含义 |
|---|---|
| 1001 | 卡密无效 |
| 1002 | 卡密已绑定其它设备 |
| 1003 | 卡密已过期 |
| 1004 | 上游校验服务不可用 |
| 1005 | 请求参数错误 |

### 8.2 `POST /api/heartbeat`

请求 `0x35 token` → 成功 `0x32 expire`；失效则 header `code=1002` + `0x41 msg`。

```json
{"token":"<32 hex>"}   →  {"code":0,"expire":1760000000}
                       →  {"code":1002,"msg":"授权已失效"}
```

### 8.3 管理端（只你自己用，App 里没有入口）

```
POST /api/admin/rebind   Authorization: Bearer <admin_key>
     {"card":"XXXX","device_fp":"<64 hex>|null"}     # null = 解绑
POST /api/admin/gencard  Authorization: Bearer <admin_key>
     {"days":365,"count":10}  → {"code":0,"cards":["...", ...]}
POST /api/admin/list     Authorization: Bearer <admin_key>
     {}                       → {"code":0,"cards":[{"card_hash":"…","device_fp":"…","expire":…,"state":"…"}]}
```

---

## 9. 引擎接口变化

| 项 | 变化 |
|---|---|
| 环境变量 | 新增 `GHOSTLOCK_KEY`（`Kd` 的 64 hex）、`GHOSTLOCK_DEVICE_FP`（64 hex）、`GHOSTLOCK_CARD`（`SHA-256(卡密)` 前 16 字节，32 hex） |
| 容器 | 只接受 `GLT2`；`GLT1` 路径仅在 `-DGL_VERBOSE` 调试构建里保留 |
| `GLT_KEY` | **删除**（阶段①的固定密钥不再进二进制，实测 `.so` 内 0 命中） |
| 解析器 | 复用；仅「字段值是否与密钥流异或」一处分支 |
| S1 六条校验 | **一行不改**（校验的是解析后的结构体，与加密层解耦） |
| 调试入口 | `--crypto-selftest` / `--offsets-verify` 只在 `GL_VERBOSE` 构建存在 |

---

## 10. 不做什么（明确边界）

- 不做 OLLVM（计划 §6 阶段④）—— 会让时序敏感的引擎成功率下降，必须真机 A/B 后再上。
- 不做定期联网强制下线（阶段⑤）—— 现在是「激活时联网一次，之后离线可用」。
- **上限**：买家自己 root + dump 内存，仍可拿到明文表。这是本地软件的根本上限，
  见 `ENCRYPTION-PLAN.md` §0.2。阶段② 挡的是「复制粘贴级别的盗版」与「转卖 APK」。

---

## 11. 试用与到期（本版新增，冻结）

### 11.1 `expire` 语义

GLT2 头 bytes 8..15，u64 LE。整头是 AAD，客户端改不了。

| 值 | 含义 |
|---|---|
| `0` | **永久** |
| `> 0` | unix 秒 |
| `0xFFFFFFFFFFFFFFFF` | 保留，不得产生 |

服务端**禁止**把"解析失败"退化成 `0`：上游 `vipExpDate` **缺失或为空串** → 永久；
字段**存在但无法解析** → 拒绝激活（`1011`）。否则一次上游格式变动就把所有限时卡变成永久卡。

### 11.2 GLT2 `flags`（头 byte 5）

| 值 | 含义 | 引擎行为 |
|---|---|---|
| `0x02` | 付费/永久容器 | **不**检查 `expire`（服务端才是权威；时钟错的真机不该丢付费授权） |
| `0x03` | 试用容器（`0x01` 位） | **强制**检查 `expire`，过期即拒绝加载 |

`hdr[5] & GLT2_FLAG_TRIAL`（`0x01`）是引擎唯一的判断依据，付费路径一个字节都没变。

### 11.3 `POST /api/trial`

请求与 `/api/activate` 同构（`0x21 card` = 客户端生成的随机 20 字节 hex、`0x22 device_fp`、
`0x23 pubkey`、`0x24 app_ver`）。服务端**不调用上游 U验证**，直接用请求里 `card` 的值当 card_key。
响应同构（`0x32 expire`、`0x33 blob`、`0x34 wrapped`、`0x41 msg`），`flags=0x03`、`expire = now + 3600`。

限流两条，缺一不可：

- `trials.device_fp` 主键 → 一台机器一次（清数据重装、重启都能拿回同一窗口）
- 每 IP 24h 最多 3 次成功发放 —— `device_fp` 是客户端自报的，能被 hook 伪造，必须补第二维度

### 11.4 `/api/heartbeat` 响应新增 `0x36` state

1 字节：`1` = 有效，`0` = 已停用/已吊销。客户端收到 `0` 立即 `clear()`（收回凭据 + 删载荷）。

### 11.5 线路 tag 表（最终）

| 方向 | tag | 含义 |
|---|---|---|
| 请求 | `0x21` | card |
| 请求 | `0x22` | device_fp |
| 请求 | `0x23` | pubkey |
| 请求 | `0x24` | app_ver |
| 请求 | `0x35` | token |
| 响应 | `0x31` | token |
| 响应 | `0x32` | expire (u64 LE) |
| 响应 | `0x33` | blob |
| 响应 | `0x34` | wrapped |
| 响应 | `0x36` | state (u8) |
| 响应 | `0x41` | msg |

### 11.6 客户端本地记录（二进制，magic `0x3D71C5E9`）

| tag | 字段 | 类型 |
|---|---|---|
| `0x51` | deviceId | bytes |
| `0x52` | cardKey | bytes（**已 `trim().uppercase()` 归一化**） |
| `0x53` | token | bytes |
| `0x54` | state | u8：`1` = 付费激活，`2` = 试用中，`0` = 已停用 |
| `0x55` | expireAt | u64 LE，`0` = 永久 |
| `0x56` | activatedAt | bytes |

> `0x54` / `0x55` 相对旧版是不兼容变更（原来都是字符串）。旧记录解析失败一律按未授权处理。

### 11.7 卡密归一化（两侧必须一致）

App 与服务端都必须 `trim()` + `uppercase()` 后再用于：上传、本地存储、`SHA-256` 派生 `card_tag`。
不一致的后果不是"报错"，而是**激活界面显示成功、引擎报 `card key does not match this payload`**。

### 11.8 错误码补充

| 码 | 含义 |
|---|---|
| `1009` | 试用已结束 |
| `1010` | 试用次数已达上限（本机已试用过 / 本 IP 超限） |
| `1011` | 上游到期时间异常（字段存在但无法解析） |
