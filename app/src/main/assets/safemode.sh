#!/system/bin/sh
# safemode.sh -- disable (or restore) every KernelSU/Magisk module.
#
#   sh safemode.sh            touch <module>/disable for every module
#   sh safemode.sh --restore  undo only the modules this tool disabled
#
# KernelSU skips a module whose directory contains a `disable` file.  The
# list of modules we touched is kept in /data/adb/ksu/ic-disabled-modules.txt
# so --restore never re-enables a module the user had disabled themselves.
#
# Needs root: run it from the exploit payload (the handoff does this when
# IC_SAFE_MODE=1) or through `su`.  As adb shell it exits with a clear note.

MODE="${1:-}"
if [ "$(id -u 2>/dev/null)" != "0" ]; then
	if command -v su >/dev/null 2>&1; then
		exec su -c "sh $0 $MODE"
	fi
	echo "[safe] root required (no su yet). Run this after a successful handoff,"
	echo "[safe] or enable 安全模式 before starting the exploit."
	exit 1
fi

LIST=/data/adb/ksu/ic-disabled-modules.txt
mkdir -p /data/adb/ksu 2>/dev/null

if [ "$MODE" = "--restore" ]; then
	if [ ! -f "$LIST" ]; then
		echo "[safe] no $LIST; nothing to restore"
		exit 1
	fi
	n=0
	while IFS= read -r d; do
		[ -n "$d" ] || continue
		[ -d "$d" ] || continue
		rm -f "$d/disable" 2>/dev/null && n=$((n + 1))
	done < "$LIST"
	rm -f "$LIST" 2>/dev/null
	echo "[safe] restored $n module(s)"
	exit 0
fi

: > "$LIST" 2>/dev/null
n=0
for d in /data/adb/modules/* /data/adb/modules_update/*; do
	[ -d "$d" ] || continue
	case "$d" in *.disable_all) continue ;; esac
	[ -f "$d/disable" ] && continue
	if touch "$d/disable" 2>/dev/null; then
		echo "$d" >> "$LIST"
		n=$((n + 1))
	fi
done
echo "[safe] disabled $n module(s); list=$LIST"
echo "[safe] modules stay disabled until 'sh safemode.sh --restore'"
