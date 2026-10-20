# XproSU 授权服务端（gl-license）

零第三方依赖的卡密授权 + 按设备加密载荷下发服务。只用 Python 3 标准库
（`crypto.py` 里的 AES / ChaCha20-Poly1305 / HKDF / P-256 全部纯 Python 实现）。

接口依据（冻结，不要改）：

- `docs/stage2-protocol.md`：GLP 载荷、GLT2 容器、Kd 派生、ECIES 包裹、激活/会话 API、错误码

## 现行实现（2026-10-13 冻结，与代码一致）

| 项 | 现状 |
|---|---|
| 上游依赖 | **无**。U验证 已整体移除：`server.py` / `store.py` / `admin.py` 里 `uverif` 命中为 0，卡密权威完全在本地 `cards.db` |
| 卡密校验 | 只查本地表：不存在 → `1001 卡密无效`；`disabled/revoked` → `1001 卡密已失效`；到期 → `1003` |
| `expire` | 绑定/换钥时一并写入；`0` = 永久。心跳回 `0x32 expire` + `0x36 state` |
| chunked 请求 | 检测到 `Transfer-Encoding` 直接关闭连接并返回 `411`，不解码 |
| 管理接口 | `/api/admin/{gencard,importcards,list,disable,enable,revoke,delete}`；**没有 rebind/unbind** |
| token | 30 天过期；heartbeat 联查卡密 `state`，`disabled/revoked` → `0x36 state=0`；disable/revoke/delete 都会级联删 token（设备立即掉线） |
| **绑定语义** | 卡密 ⇄ `device_fp`（Widevine 设备 ID）：**同 `device_fp`** 允许换新公钥（卸载重装 / 清数据 / 恢复出厂自动放行），**不同 `device_fp`** 一律 `1002` |
| 同机换钥限速 | `pubkey_policy=rotate`（默认）、`pubkey_max_rotations=10`、`pubkey_rotation_cooldown=30` |
| 指纹脱敏 | 管理端只回 `device_fp_mask` = `SHA-256(小写 hex 指纹)[:16].upper()`（与 App 授权卡片"设备码"逐字节一致）；dashboard 只回 `admin_key_fp` / `master_key_fp` |
| 激活审计 | `activation_audit` 表 + `cards.pubkey_rotations / prev_pubkey / last_pubkey_at`；每次绑定 / 换钥 / 拒绝落一行（含 IP、UA、旧新公钥） |
| 可疑信号 | 换钥且来源 IP 变化时服务端打 `SECURITY new-ip rekey`；dashboard 的 `security` 块给"30 分钟内同卡多 IP 数 / 24h 换钥与拒绝次数 / 最近 20 条事件" |
| 会话 | `admin_sessions` 7 天有效；启动时清理过期行并每账号只留最近 10 条 |
| **已移除** | `/api/trial` 试用接口、`trials` 表（本期清理）、`uverif.py` / `uverif_probe.py` / `run_selftest.ps1`、`CardStore.rebind()` |
| **同机换绑（新）** | `device_fp` 相同 = 同一台设备（卸载重装/清数据/恢复出厂都不变），允许其换新公钥并把 `Kd` 封给**本次请求的公钥**；`device_fp` 不同仍按一机一码拒绝 `1002`。受 `pubkey_policy`（`rotate`/`pin`）、`pubkey_max_rotations`、`pubkey_rotation_cooldown` 三个配置约束 |
| **绑机不可解除（新）** | 服务端**不存在**解绑/换绑行为，且**不是配置开关**：`/api/admin/rebind` 路由已删（→ `404 未知接口`）、后台动作 `unbind` 已删（→ `1005 未知操作`）、`admin.py` 无 `rebind` 子命令、`CardStore.rebind()` 已删。绑定只由**同 `device_fp`** 的激活写入（重装/清数据/恢复出厂自动放行），不同设备一律 `1002`。要换机：`revoke` + 重新发卡 |
| **指纹脱敏（新）** | 任何管理端响应都不再回传原始 `device_fp`（后台/JSON API/CLI 只给 `device_fp_mask`＝`SHA-256(小写 hex)[:16].upper()`，与 App 授权卡片"设备码"逐字节一致）；dashboard 也不再回明文 `admin_key`，只回指纹 |
| **激活审计（新）** | 新增 `activation_audit` 表与 `cards.pubkey_rotations / prev_pubkey / last_pubkey_at`：每次绑定、换绑、拒绝都落一行（`bound`/`rotated`/`rejected`，含 IP、UA、旧公钥） |
| 线路 tag | 响应新增 `0x36` = state(u8)；其余 tag 表见 `wire.py` |


## 文件清单

| 文件 | 职责 |
|---|---|
| `crypto.py` | HKDF / ChaCha20-Poly1305 / AES-128-CBC / P-256 / ECIES 等纯标准库实现 |
| `selftest.py` | 密码学自检（RFC/NIST 向量 + 随机 P-256 对拍 + JDK 交叉验证） |
| `payload.py` | GLP 载荷与 GLT2 容器的读写 |
| `store.py` | SQLite 卡密表（只存 `SHA-256(卡密)`，绝不存原文） |
| `server.py` | HTTP 服务（`/api/activate`、`/api/session`、`/api/heartbeat`、管理接口） |
| `admin.py` | 命令行管理工具（生成卡密、列表、禁用/启用/吊销、生成载荷） |
| `smoke_test.py` | 本地端到端冒烟测试，产出 `vectors.json` 固定向量 |
| `negative_test.py` | 负向路径测试（绑定/换设备/会话重签/到期/禁用/chunked/心跳 state） |
| `config.json` | 运行配置（**master_key 是真实密钥，必须备份**） |
| `config.example.json` | 配置模板（`master_key` / `listen_port` / `admin_key` 等） |

## 依赖

- Python 3.8+（本机已用 3.12.10 验证）
- 无任何 pip 第三方包

## 1. 生成 master_key

`config.json` 已预生成一个随机 `master_key`。正式部署前建议重新生成并**立即备份**：

```powershell
python -c "import secrets; print(secrets.token_bytes(32).hex())"
```

把结果填进 `config.json` 的 `master_key`。

> ⚠️ `master_key` 泄露 = 所有已下发卡密的载荷密钥全部作废；丢失 = 已激活设备无法再续期/重装激活。
> 换 key 后旧设备手里的 Kd 不变，但服务端派生出的 Kd 会变，等价于换了一整代密钥。

## 2. 配置 config.json

服务端唯一的配置入口。字段与默认值见 `config.example.json`：

| 字段 | 说明 |
|---|---|
| `master_key` | 32 字节（64 位 hex）。**真实密钥，必须离线备份** |
| `listen_host` / `listen_port` | 监听地址与端口（默认 `0.0.0.0:8787`） |
| `db_path` / `payload_path` | 卡密库与载荷文件路径 |
| `admin_key` | 管理接口 `Authorization: Bearer <admin_key>` 的凭据 |
| `admin_user` / `admin_pass_hash` | 后台 Web 登录账号与口令哈希 |

> 卡密权威完全在本地 `cards.db`，服务端**不依赖任何上游校验服务**。

## 3. 生成明文载荷 payload.bin

准备一个明文表 JSON（字段名→值，字段名用 `docs/stage2-protocol.md` §4.1 的名字）：

```json
{
  "arm64-6.6.56": {
    "kernel_phys_load": 2228224,
    "pselect_waiter_shift": 5,
    "off_init_task": 34667328,
    "task_cred": 368
  }
}
```

```powershell
python admin.py build-payload --table .\table.json
```

生成的 `payload.bin` 路径由 `config.json` 的 `payload_path` 决定。

## 4. 生成卡密

```powershell
python admin.py gen --type test      --count 10   # 测试卡：1 小时，首次绑定开始倒计时
python admin.py gen --type permanent --count 10   # 永久卡（不计时）
python admin.py list
```

卡密格式：20 位 Base32 大写（A-Z2-7），每 5 位一个 `-`，例如 `AAAAA-BBBBB-CCCCC-DDDDD`。

## 5. 启动服务

```powershell
python server.py
# 或指定配置
python server.py .\config.json
```

默认监听 `0.0.0.0:8787`（见 `config.json`）。App 端 `local.properties` 的
`LICENSE_BASE_URL` 指向本服务即可（`http://IP:8787`）。

### systemd 示例（Linux 部署参考）

```ini
[Unit]
Description=XproSU license server
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/ghostlock-license
ExecStart=/usr/bin/python3 /opt/ghostlock-license/server.py /opt/ghostlock-license/config.json
Restart=on-failure
User=ghostlock

[Install]
WantedBy=multi-user.target
```

## 6. 管理端命令

```powershell
python admin.py gen --type permanent --count 10           # 生成卡密
python admin.py list                                      # 列表
# 换机请走"吊销 + 重新发卡"：绑定不可解除（本服务没有 rebind/unbind）
python admin.py build-payload --table .\table.json        # 生成 payload.bin
```

HTTP 管理接口（`Authorization: Bearer <admin_key>`）：

```
POST /api/admin/gencard  {"type":"permanent", "count":10}
POST /api/admin/list     {}
```

## 7. App 二进制线路与 curl JSON 调试

App 使用二进制线路（见 `wire.py`，与客户端 `GlBlob.kt` 逐字节一致）：请求体以
magic `9E4B37A1`（小端）开头。服务端读取请求体后，前 4 字节等于 magic 就按二进制
解析，否则按 JSON 解析；响应也按请求格式原样返回（二进制回
`application/octet-stream`，JSON 回 `application/json`）。

curl 调试仍用 JSON：

```powershell
curl.exe -X POST http://127.0.0.1:8787/api/heartbeat -H "Content-Type: application/json" --data "{\"token\":\"00000000000000000000000000000000\"}"
```

用 Python 发二进制请求：

```python
import urllib.request
import wire

body = wire.encode(wire.KIND_REQUEST, 0, [(wire.TAG_TOKEN, b"00000000000000000000000000000000")])
req = urllib.request.Request(
    "http://127.0.0.1:8787/api/heartbeat",
    data=body,
    headers={"Content-Type": "application/octet-stream"},
    method="POST",
)
with urllib.request.urlopen(req) as resp:
    kind, entries = wire.decode(resp.read())
    print(kind, entries)
```

## 8. 自检与冒烟测试

```powershell
python selftest.py        # 必须全部 PASS
python smoke_test.py      # 端到端链路，产出 vectors.json
```

`vectors.json` 是与本配置 `master_key` 对应的固定向量（`kd_hex` / `glt2_hex` / `wrapped_hex`），
三方实现（App Kotlin / 引擎 C / 服务端 Python）应能逐字节复现。

## 9. 排错

| 现象 | 处理 |
|---|---|
| 激活返回 `1001 卡密无效` | 卡密不在本地 `cards.db`，或已被禁用/吊销 |
| 激活返回 `1002 卡密已绑定其它设备` | 该卡已绑到**另一台**设备。绑定不可解除：同 device_fp 的重装/清数据会自动放行；确有换机需求时 `revoke` 该卡后重新发卡 |
| 激活返回 `1003 卡密已过期` | 测试卡已到期；永久卡此错误不应出现，检查 `expire` 字段 |
| 激活返回 `1005` | 参数格式错，或未执行 `build-payload`（`/api/session` 会因缺载荷返回「服务暂不可用」） |
| 启动报 `master_key must be 64 hex` | `config.json` 的 `master_key` 不是 64 位 hex |
| `selftest.py` FAIL | 先看哪条向量对不上；实现以冻结规范为准，不要改向量迁就实现 |

## 安全注意

- `config.json`、`payload.bin`、`cards.db` 都不要进仓库或外发。
- 自建服务多为 `http://`，卡密与载荷在链路上可被嗅探；载荷本身经 ECIES 包裹，
  但卡密明文建议走内网或 HTTPS 反代。
- 卡密原文从不落盘，只存 `SHA-256(卡密)`。
