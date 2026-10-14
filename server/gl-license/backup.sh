#!/bin/sh
# XproSU 授权服务端备份：cards.db / config.json / payload.bin
# cards.db 用 sqlite3 的在线备份 API（在容器里跑），避免拷贝到写了一半的库。
set -e
D=/opt/gl-license
B=$D/backups
mkdir -p "$B"
chmod 700 "$B"
TS=$(date +%Y%m%d-%H%M%S)

docker exec -i gl-license python - "$TS" <<'PYEOF'
import sqlite3, sys, os
ts = sys.argv[1]
os.makedirs('/app/backups', exist_ok=True)
src = sqlite3.connect('/app/cards.db')
dst = sqlite3.connect('/app/backups/cards-%s.db' % ts)
src.backup(dst)
dst.close(); src.close()
PYEOF

cp -a "$D/config.json" "$B/config-$TS.json"
cp -a "$D/payload.bin" "$B/payload-$TS.bin"
chmod 600 "$B"/* 2>/dev/null || true

# 各保留最近 14 份
for pat in cards-*.db config-*.json payload-*.bin; do
  ls -1t "$B"/$pat 2>/dev/null | tail -n +15 | xargs -r rm -f
done
echo "$(date '+%F %T') backup ok: $TS"
