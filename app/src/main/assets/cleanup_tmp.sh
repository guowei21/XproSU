#!/system/bin/sh
# 只清理本工具自己的临时文件与日志副本。
# 明确不碰：/data/adb/ksu、/data/adb/modules、/data/adb/modules_update、
# 任何 KSU 模块与 ksud 安装体；ic-syms.txt 也保留（解析偏移的结果）。
set -u
TMP=/data/local/tmp
cd "$TMP" 2>/dev/null || exit 0

n=0
left=0
for f in ic-timer-a* ic-lpe-a*.sh ic-syms-a* ksud-h* ic-done-a* \
         ic-boot-a*.img ic-clean-a*.sh ic-safe-h*.sh ksu-h*.sh; do
    [ -e "$f" ] || continue
    if rm -rf "$f" 2>/dev/null; then n=$((n + 1)); else left=$((left + 1)); fi
done

# ksud-h* 是 handing off 时落下的 root 属主副本，shell 删不掉。只有真拿到 root
# 才顺手补一刀；拿不到就如实计入 leftover，交给调用方提示。
if [ "$left" -gt 0 ] && command -v su >/dev/null 2>&1; then
    su -c 'rm -f /data/local/tmp/ksud-h*' >/dev/null 2>&1 && left=0
fi

# 运行日志保留最近 3 份：它是排错证据，不能跟着清理一起没。
ls -t ic-app-a*.log 2>/dev/null | tail -n +4 | while IFS= read -r f; do
    rm -f "$f" 2>/dev/null
done

if [ -d ic-dropdir ]; then
    rm -rf ic-dropdir 2>/dev/null && n=$((n + 1))
fi

# 进程残留只报告、不 kill：park_forever 挂住的载荷是故意不退出也不回收的，
# 强杀会走内核回收路径。要真正清干净只有重启。
procs=$(ps -A 2>/dev/null | grep -c '[i]c-timer')
[ -n "$procs" ] || procs=0

echo "cleaned=$n"
echo "leftover=$left"
echo "procs=$procs"
