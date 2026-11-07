#!/system/bin/sh
# 只清理本工具自己的临时文件与日志副本。
# 明确不碰：/data/adb/ksu、/data/adb/modules、/data/adb/modules_update、
# 任何 KSU 模块与 ksud；ic-syms.txt 也保留（解析偏移的结果）。
set -u
TMP=/data/local/tmp
cd "$TMP" 2>/dev/null || exit 0

n=0
for f in ic-timer-a* ic-lpe-a*.sh ic-app-a*.log ic-syms-a* ksud-h* \
         ic-boot-a*.img ic-clean-a*.sh ic-safe-h*.sh ksu-h*.sh; do
    [ -e "$f" ] || continue
    rm -rf "$f" 2>/dev/null && n=$((n + 1))
done

if [ -d ic-dropdir ]; then
    rm -rf ic-dropdir 2>/dev/null && n=$((n + 1))
fi

echo "cleaned=$n"
