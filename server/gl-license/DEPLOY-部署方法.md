# XproSU / XproSU 授权服务端部署手册（standalone 生产版）

> 版本：2026-10-13 生产改造版 —— 已彻底移除 U验证（uverif）上游依赖，
> 卡密签发/绑定/禁用/吊销全部在本地 `cards.db` 完成。
> 生产实例后台：https://yz.765163599.xyz/admin/ ；客户端 API 前缀：/gl/

---

## 0. 架构总览

```
[客户端 App]
   | HTTPS（二进制 GlBlob 线路）
   v
[外层网关（域名/TLS，按环境配置）]
   | 映射到宿主机 :8080
   v
[uverif-web 容器（nginx:alpine）:8080]
   |- /admin/  ----------> [gl-license:8787] Web 后台 + /admin/api/*
   '- /gl/xxx  -(剔前缀)-> [gl-license:8787] /xxx  客户端 API
[gl-license 容器（python:3.12-alpine）]
   '- /opt/gl-license 挂载到 /app（cards.db / payload.bin / config.json）
```
---

## 1. 文件清单（本目录）

| 文件 | 用途 |
|---|---|
| `server.py` | 授权服务主程序：`/api/activate`、`/api/heartbeat`、`/api/admin/*`、Web 后台后端 |
| `store.py` | 卡密/token 状态机（SQLite `cards.db`）：unbound→bound→disabled→revoked |
| `admin.py` | 命令行管理：gen / list / import / disable / enable / revoke / delete / encrypt-payload / build-payload（**没有 rebind**：绑定不可解除） |
| `admin_ui.html` | Web 后台单页（挂载于 `/admin/`） |
| `crypto.py` | 密码学原语：HKDF-SHA256、ChaCha20-Poly1305、ECIES、sha256 等 |
| `payload.py` | GLP 明文载荷 / GLT2 按设备加密容器 读写 |
| `wire.py` | 二进制线路编解码（与客户端 `GlBlob.kt` 逐字节一致；magic `9E4B37A1`） |
| `config.example.json` | 配置模板 → 复制为 `config.json` 后填值 |
| `selftest.py` / `smoke_test.py` / `negative_test.py` / `wire_smoke.py` / `audit_suite.py` | 自检 / 冒烟 / 负向 / 线路 / 安全审计（17 项） |
| `vectors.json` | 密码学测试向量 |
| `backup.sh` | 备份脚本（cards.db / config.json / payload.bin；保留最近 14 份） |
| `OPS_README.md` | 运维速查（发卡/禁用/换绑/回滚） |
| `README.md` | 旧版说明（含已废弃的 U验证 章节，仅存档） |
| `nginx/default.conf` | nginx 反代模板（`/admin/`、`/gl/` 两条路由） |
| `nginx/uverif-live-default.conf` | 生产实例实际挂载版（额外含 OrcaBridge `/v1`、`/health`，新机可删） |
| `_staging/e2e_regression.py` | 端到端回归脚本 |

## 2. 前置条件

- Linux 服务器 + Docker（`docker` CLI 可用）
- 容器镜像：`python:3.12-alpine`、`nginx:alpine`
- 可选：域名 + TLS（在外层网关终结）
- 宿主系统 Python **不需要**装依赖（所有命令走容器执行）

---

## 3. 部署步骤（从零开始）

### 3.1 放置代码

```bash
mkdir -p /opt/gl-license /opt/uverif/nginx
cp -a ./* /opt/gl-license/
```

### 3.2 创建 Docker 网络

```bash
docker network create uverif-net
```

两个容器都接入该网络，nginx 通过容器名 `gl-license` 找到后端。

### 3.3 生成并填写配置 `config.json`

生成密钥（示例）：

```bash
python3 -c "import secrets; print(secrets.token_hex(32))"                       # master_key（64位hex）
python3 -c "import secrets; print(secrets.token_urlsafe(32))"                   # admin_key（长随机串）
python3 -c "import hashlib; print(hashlib.sha256(b'你的后台密码').hexdigest())"  # admin_pass_hash
```

复制模板并填写：

```bash
cp /opt/gl-license/config.example.json /opt/gl-license/config.json
chmod 600 /opt/gl-license/config.json
```

| 字段 | 说明 |
|---|---|
| `listen_host` / `listen_port` | 监听地址，默认 `0.0.0.0:8787` |
| `master_key` | 64 位 hex（32字节）。载荷密钥派生根。泄露=卡密作废；丢失=设备无法续期 |
| `admin_key` | HTTP 管理接口 Bearer 密钥（长随机串） |
| `admin_user` / `admin_pass_hash` | 后台登录账号 / `sha256(密码)` hex |
| `payload_path` / `db_path` | 载荷 / 卡库文件名 |

### 3.4 启动 gl-license 容器

```bash
docker run -d --name gl-license \
  --network uverif-net --restart unless-stopped \
  -p 127.0.0.1:8787:8787 \
  -v /opt/gl-license:/app -w /app \
  python:3.12-alpine \
  python server.py /app/config.json
```

端口只绑本机；挂载 `/opt/gl-license → /app`（数据全落宿主机）。

### 3.5 生成载荷 `payload.bin`

准备明文偏移表 `table.json`（字段名见 `docs/stage2-protocol.md` 4.1 节），然后：

```bash
docker exec gl-license python3 /app/admin.py build-payload --table /app/table.json
```

输出由 `payload_path` 决定（默认 `/app/payload.bin`）。**缺 payload.bin 时激活会返回 1005。**

### 3.6 自检

```bash
docker exec gl-license python3 /app/selftest.py
docker exec gl-license python3 /app/smoke_test.py
docker exec gl-license python3 /app/audit_suite.py   # 17 项安全审计
```

### 3.7 启动 nginx 反代（uverif-web）

```bash
docker run -d --name uverif-web \
  --network uverif-net --restart unless-stopped \
  -p 8080:8080 \
  -v /opt/uverif/nginx/default.conf:/etc/nginx/conf.d/default.conf:ro \
  nginx:alpine
```

（用 `nginx/default.conf` 模板；生产实例版为 `nginx/uverif-live-default.conf`，多出 OrcaBridge 路由，与本服务无关。）

### 3.8 公网入口

将域名 HTTPS 映射到宿主机 `:8080`（TLS 由外层网关/CDN 终结）。之后：

- 后台：`https://<域名>/admin/`（账号 = `admin_user`，密码 = 后台密码）
- 客户端 API：`https://<域名>/gl/api/activate`、`/gl/api/heartbeat`

---

## 4. 发卡与日常运维（完整版见 `OPS_README.md`）

```bash
# 发卡：100 张一年卡，批次 2026Q1
docker exec gl-license python3 /app/admin.py gen --days 365 --count 100 --batch 2026Q1
# 列表 / 导入 / 禁用 / 启用 / 吊销（没有换绑：绑定不可解除）
docker exec gl-license python3 /app/admin.py list
docker exec gl-license python3 /app/admin.py import --file /app/cards.txt --days 365 --batch EXT
docker exec gl-license python3 /app/admin.py disable --card XXXXX-XXXXX-XXXXX-XXXXX
docker exec gl-license python3 /app/admin.py enable  --card XXXXX-XXXXX-XXXXX-XXXXX
docker exec gl-license python3 /app/admin.py revoke  --card XXXXX-XXXXX-XXXXX-XXXXX
```

- 卡密格式：20 位 Base32（A-Z、2-7），每 5 位一个横杠，如 `AAAAA-BBBBB-CCCCC-DDDDD`。
- 禁用/吊销 → 级联删 token → 设备 60 秒内心跳失败 → 客户端自动清除本地授权。
- **绑定不可解除**：同 device_fp 的重装/清数据自动放行（换新公钥），不同 device_fp 一律 `1002`；要换机只能 `revoke` + 重新发卡。

## 5. 客户端对接

- App 授权服务地址指向 `https://<域名>/gl`（nginx 剥离 `/gl` 前缀）。
- 激活上行：`card` + `device_fp`（32 字节 Widevine ID 的 64 位 hex）+ `pubkey` + `app_ver`。
- 服务端派生：`Kd = HKDF-SHA256(master_key, sha256(card), device_fp, 32)`。
- 线路：二进制 GlBlob；服务端兼容 JSON（便于 curl 调试）。

## 6. 备份 / 恢复

```bash
bash /opt/gl-license/backup.sh        # 保留最近 14 份
# crontab 建议： 30 4 * * * /bin/sh /opt/gl-license/backup.sh >/dev/null 2>&1
```

恢复：停容器 → 将备份的 `cards.db / config.json / payload.bin` 放回 `/opt/gl-license/` → 起容器。

---

## 7. 状态码速查

| code | 含义 | 处理建议 |
|---|---|---|
| 1001 | 卡密无效 / 已失效 | 核对卡密、卡状态 |
| 1002 | 卡密已绑定其它设备 / 授权已失效 | 后台换绑或换卡；被踢设备重新激活 |
| 1003 | 卡密已过期 | 续期 / 换卡 |
| 1005 | 参数错误 / 服务暂不可用 | 检查请求格式；确认 payload.bin 已生成 |

## 8. 安全清单

- `master_key`、`admin_key`、`config.json`：不进仓库、不外发、`chmod 600`。
- 8787 只绑 `127.0.0.1`；公网只暴露 8080（外层网关收口）。
- 公网 `/gl/api/admin/*` 应拦截（生产用 nginx 403；管理走 SSH / 本机 curl）。
- 备份目录 `chmod 700`、文件 `chmod 600`（backup.sh 已处理）。
- 后台登录有速率限制，会话存 `admin_sessions` 表。

## 9. 排障 FAQ

- **容器起不来/重启**：`docker logs gl-license`；常见为 config 字段缺失或 master_key 非 64 位 hex。
- **激活返回 1005**：确认 `/app/payload.bin` 已生成且 `payload_path` 指向它。
- **后台打不开**：确认 nginx 在 `uverif-net` 网络、`/admin/` 反代目标 `gl-license:8787`。
- **客户端连不上**：确认外层映射 `:8080`、客户端 base 为 `https://<域名>/gl`。

## 10. 与 98 原包（旧版）的差异

- `server/gl-license/` 全量替换为 2026-10-13 生产版：server.py 约 30KB 并新增
  `admin_ui.html`、`audit_suite.py`、`OPS_README.md`、`nginx/`、`backup.sh`、本手册。
- 移除旧版 `uverif.py`、`uverif_probe.py`、`run_selftest.ps1`、`tools_java_crosscheck/`
  （U验证 已解耦，不再需要）。
- 客户端 `app/` 源码未改动，哈希与 98 原包一致。
