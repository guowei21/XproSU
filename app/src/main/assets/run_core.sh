#!/system/bin/sh
# run_core.sh -- 0.12 refactor launcher: run the profile core directly as the
# Shizuku shell user-service identity (uid 2000 / u:r:shell:s0, enforcing).
#
# The core owns the whole plan: kmem trace oracle -> cred leak -> UAF plant
# with read-back verification and retry -> zero write of uid+gid -> setuid(0)
# -> exec of the proof shell.  This script only reports the identity the run
# happened under and relays the core's log (the app's ADB client streams stdout
# app log and /sdcard/Download).
#
# The binary embeds one kernel profile.  It refuses to run when `uname -r`
# does not match that profile unless IC_ALLOW_ANY_KERNEL=1 is set, and it
# also rejects an implausible KASLR slide before any write.
set -u
trap '' PIPE HUP INT TERM

BIN="${IC_BIN:-/data/local/tmp/ic-timer}"
[ -x "$BIN" ] || { echo "missing $BIN" >&2; exit 1; }

echo "[core] start uid=$(id -u 2>/dev/null) ctx=$(cat /proc/self/attr/current 2>/dev/null)"
echo "[core] kernel=$(uname -r 2>/dev/null)"
echo "[core] device=$(getprop ro.product.device 2>/dev/null) model=$(getprop ro.product.model 2>/dev/null)"
echo "[core] build=$(getprop ro.build.display.id 2>/dev/null)"
echo "[core] memtotal=$(sed -n 's/^MemTotal:[[:space:]]*\([0-9]*\).*/\1/p' /proc/meminfo 2>/dev/null) kB"

# KSU handoff: the App prepends its handoff script to PAYLOAD_CMD when a
# manager is selected.  Late-loading the manager's kernel module needs root
# with the full capability set, which is the fake-cred endgame ("ksu" mode);
# the shell path only reaches uid 0 inside u:r:shell:s0 without caps.
MODE=
if [ "${IC_KSU:-0}" = "1" ]; then MODE=ksu; fi
case "${PAYLOAD_CMD:-}" in
    *ksu_handoff*|*ksu-h*) MODE=ksu ;;
esac
if [ -n "$MODE" ]; then
    echo "[core] mode=ksu payload=$(echo "${PAYLOAD_CMD:-}" | head -c 80)"
    "$BIN" "$MODE" 2>&1
else
    "$BIN" 2>&1
fi
rc=$?
echo "[core] exit=$rc"
exit "$rc"
