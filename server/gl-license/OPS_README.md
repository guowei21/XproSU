# GhostLock gl-license 运维速查（standalone 版）

> 2026-10-13 改造：**已彻底移除 U验证（uverif）上游依赖**。
> 卡密的签发、绑定、禁用、吊销全部在本地 `cards.db` 完成，不再创建账号。

## 一、日常运维命令（在服务器上运行）

所有命令都在 `/opt/gl-license` 目录下、**通过容器执行**（宿主 Python 太老）：

```bash
# 发卡：100 张一年期卡，批次号 2026Q1
docker exec gl-license python3 /app/admin.py gen --days 365 --count 100 --batch 2026Q1

# 查看所有卡
docker exec gl-license python3 /app/admin.py list
docker exec gl-license python3 /app/admin.py list --batch 2026Q1

# 导入外部卡（一行一个，可用发卡平台的卡）
docker exec gl-license python3 /app/admin.py import --file /app/cards.txt --days 365 --batch EXT

# 禁用卡（可恢复；立即踢下线，用户需重新激活）
docker exec gl-license python3 /app/admin.py disable --card XXXXX-XXXXX-XXXXX-XXXXX

# 重新启用
docker exec gl-license python3 /app/admin.py enable --card XXXXX-XXXXX-XXXXX-XXXXX

# 吊销卡（不可逆；解绑设备）
docker exec gl-license python3 /app/admin.py revoke --card XXXXX-XXXXX-XXXXX-XXXXX

# 换绑/解绑：本服务**不提供**（绑定不可解除）。要换机 → revoke 后重新发卡
```

## 二、HTTP 管理接口（本机直接调用；公网已被 nginx 403）

```bash
curl -s -X POST http://127.0.0.1:8787/api/admin/list \
  -H "Authorization: Bearer <admin_key>" -H "Content-Type: application/json" -d '{}'

# 禁用
curl -s -X POST http://127.0.0.1:8787/api/admin/disable \
  -H "Authorization: Bearer <admin_key>" -H "Content-Type: application/json" \
  -d '{"card":"XXXXX-XXXXX-XXXXX-XXXXX"}'
```

## 三、卡密生命周期

```
unbound ──激活──> bound ──禁用──> disabled ──启用──> bound
                    │
                    └──吊销──> revoked（终态，不可逆）
```

- **禁用/吊销/换绑** 都会**级联删除该卡的 token** → 设备 60 秒内心跳失败 → 客户端自动清除本地授权。
- **删卡（DELETE cards 行）** 同样立即生效（孤儿 token 检测，`card_exists=0` → `state=0`）。

## 四、验证命令

```bash
# 服务状态
docker ps | grep gl-license
docker logs gl-license --tail 20

# 健康测试（本机）
curl -s -X POST http://127.0.0.1:8787/api/heartbeat \
  -H "Content-Type: application/json" -d '{"token":"<token>"}'
# 期望: {"code":0,"expire":...,"state":1}
```

## 五、回滚（万不得已）

```bash
# 2026-10-13 改造前的完整快照：
ls /root/gl-swap-20261013-141343/     # server.py store.py admin.py config.json
ls /root/gl-backup-20261013-140705/   # + cards.db payload.bin
ls /root/uvirif-db-backup/            # uverif MySQL 全库 dump

# 回滚步骤：
cd /opt/gl-license
cp /root/gl-swap-20261013-141343/server.py server.py
cp /root/gl-swap-20261013-141343/store.py store.py
cp /root/gl-swap-20261013-141343/admin.py admin.py
cp /root/gl-swap-20261013-141343/config.json config.json   # 这个 config 带 uverif 段
docker restart gl-license
docker start uverif-php uverif-db && docker update --restart=unless-stopped uverif-php uverif-db
```

## 六、安全备注

- `admin_key` / `master_key` 建议轮换（本次未换，换 master_key 会导致所有已激活设备需要重新激活）
- uverif-php / uverif-db 已停止且设为 `restart=no`（不会开机自启）
- uverif-web（nginx）**保留运行**——它是 `/gl/` 的公网反代入口
- 公网 `/gl/api/admin/*` 已被 nginx 403；管理操作请走 SSH 或本机 curl