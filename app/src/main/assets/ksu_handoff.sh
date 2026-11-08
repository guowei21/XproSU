#!/system/bin/sh
# ksu_handoff.sh -- hand this exploit's root to a KernelSU-family manager.
#
#   sh ksu_handoff.sh [package] [kmi] [safe_mode]
#
#   package   empty = auto-detect every installed KSU-family manager
#   kmi       empty = derive from uname -r (6.1.x -> android14-6.1)
#   safe_mode 1 = disable every /data/adb/module*/<id> before late-load
#
# What changed for 0.11 (the X300/t61269 lessons):
#   * ksud is re-extracted from the manager APK on every run.  The old script
#     preferred /data/adb/ksu/bin/ksud, which can be a stale copy from an
#     older manager and then fails with a harmless-looking rc=0.
#   * SukiSU/7kimisu randomise or rename the embedded payload, so the whole
#     lib/arm64 directory is scanned; each large .so is executed with
#     --version / late-load --help and the one that answers "uapi" wins.
#   * Every installed manager is tried, not just the first detected one:
#     a kernel that pins one manager's signature rejects the others, and
#     trying all of them is what turns a silent rc=0 into a loaded module.
#   * Module visibility is not required: some KSU forks hide /proc/modules.
#     su -c id and /sys/module/* count as success too.
#   * SAFE_MODE touches <module>/disable for every module (KernelSU skips a
#     module with that file) and records the list so --restore can undo it.
#   * ksud install + launching the manager run after the module is live, so
#     the manager's "越狱模式" page can install the userspace su if needed.

PKG="$1"
KMI="$2"
SAFE="${3:-0}"
if [ "${KSU_SAFE_MODE:-0}" = "1" ]; then SAFE=1; fi
TAG="[ksu]"
say() { echo "$TAG $*"; }

KNOWN="me.weishu.kernelsu com.sukisu.ultra org.bakasu.bakasu \
com.resukisu.resukisu com.sakisu.sakisu com.sevenk.core \
com.sevenkimimasy.love me.inkdye.vivoksu com.rifsxd.ksunext me.yuki.fina \
com.kowx712.kowsupro"

KERNEL=$(uname -r 2>/dev/null)
if [ -z "$KMI" ]; then
	case "$KERNEL" in
	6.1.*) KMI=android14-6.1 ;;
	5.10.*) KMI=android12-5.10 ;;
	5.15.*) KMI=android13-5.15 ;;
	6.6.*) KMI=android15-6.6 ;;
	6.12.*) KMI=android16-6.12 ;;
	*) KMI= ;;
	esac
fi
say "kernel=$KERNEL kmi=${KMI:-auto} safe_mode=$SAFE"

BINDIR=/data/adb/ksu/bin
mkdir -p "$BINDIR" 2>/dev/null
if [ ! -d "$BINDIR" ]; then
	say "cannot create $BINDIR (not root? SELinux?)"
	exit 5
fi

# 暂存的 ksud 副本放 /data/local/tmp，不往 /data/adb/ksu 里写临时文件。
# 该目录由 App 运行结束后的自动清理统一回收（shell 拥有目录，可删 root 文件）。
STAGE=/data/local/tmp

# ---------------------------------------------------------------- helpers
apk_of() {
	p=$1
	a=$(pm path "$p" 2>/dev/null | sed -n 's/^package://p' | head -n 1)
	if [ -z "$a" ]; then
		for d in /data/app/*/"$p"-*/; do
			[ -d "$d" ] || continue
			a=$(ls "$d"/*.apk 2>/dev/null | head -n 1)
			[ -n "$a" ] && break
		done
	fi
	[ -n "$a" ] && [ -f "$a" ] && echo "$a"
}

installed() {
	[ -n "$(apk_of "$1")" ]
}

module_present() {
	[ -d /sys/module/kernelsu ] || [ -d /sys/module/ksu ] && return 0
	grep -qiE '^(kernelsu|ksu|sukisu|suki)[[:space:]]' /proc/modules 2>/dev/null
}

su_works() {
	for s in /data/adb/ksu/bin/su /data/adb/ksu/bin/ksud \
		 /system/bin/su /system/xbin/su $(command -v su 2>/dev/null); do
		[ -x "$s" ] || continue
		case "$s" in
		*ksud) timeout 6 "$s" su -c id 2>/dev/null | grep -q 'uid=0' && return 0 ;;
		*) timeout 6 "$s" -c id 2>/dev/null | grep -q 'uid=0' && return 0 ;;
		esac
	done
	return 1
}

ksu_live() {
	module_present && return 0
	su_works && return 0
	return 1
}

wait_live() { # seconds
	n=$1
	while [ "$n" -gt 0 ]; do
		ksu_live && return 0
		sleep 1
		n=$((n - 1))
	done
	ksu_live
}

# Try every ksud-shaped payload in the manager's extracted native lib dir.
# Emits the staged path on stdout; returns 1 when nothing usable exists.
find_fresh_ksud() {
	p=$1
	LAST=""
	apk=$(apk_of "$p")
	[ -n "$apk" ] || return 1
	libdir=$(dirname "$apk")/lib/arm64
	[ -d "$libdir" ] || libdir=$(dirname "$apk")/lib/arm64-v8a
	stage="$STAGE/ksud-h$$"

	# Preferred names first, then any large .so (SukiSU renames it).
	list=""
	for f in "$libdir/libksud.so" "$libdir/libksuinit.so" "$libdir"/*.so; do
		[ -f "$f" ] || continue
		sz=$(wc -c < "$f" 2>/dev/null)
		[ "${sz:-0}" -gt 1000000 ] || continue
		list="$list $f"
	done
	for f in $list; do
		cp -f "$f" "$stage.$p" 2>/dev/null || continue
		chmod 755 "$stage.$p" 2>/dev/null
		[ -x "$stage.$p" ] || continue
		ver=$(timeout 5 "$stage.$p" --version 2>&1 | head -n 2 | tr '\n' ' ')
		help=$(timeout 5 "$stage.$p" late-load --help 2>&1 | head -n 20)
		case "$ver $help" in
		*uapi*|*UAPI*|*late-load*|*--kmi*)
			printf '%s\n' "$stage.$p"
			return 0 ;;
		esac
		# A libksud.so that refuses --version is still the manager's own
		# payload; keep it as a last resort.
		case "$f" in
		*libksud.so) LAST="$stage.$p" ;;
		esac
	done
	if [ -n "${LAST:-}" ] && [ -x "$LAST" ]; then
		printf '%s\n' "$LAST"
		return 0
	fi
	# No extracted lib (some managers keep it in the APK only).
	if [ -n "$apk" ] && command -v unzip >/dev/null 2>&1; then
		unzip -p "$apk" lib/arm64-v8a/libksud.so > "$stage.apk" 2>/dev/null &&
			chmod 755 "$stage.apk" 2>/dev/null &&
			{ printf '%s\n' "$stage.apk"; return 0; }
	fi
	return 1
}

late_one() { # bin args...
	bin=$1
	shift
	out=$(timeout 180 "$bin" late-load "$@" 2>&1)
	rc=$?
	if [ -n "$out" ]; then
		printf '%s\n' "$out" | sed 's/^/[ksu]   /'
	else
		say "  late-load($*) rc=$rc (empty output)"
	fi
	wait_live 20
}

safe_mode_apply() {
	[ "$SAFE" = "1" ] || return 0
	list=/data/adb/ksu/ic-disabled-modules.txt
	mkdir -p /data/adb/ksu 2>/dev/null
	: > "$list" 2>/dev/null
	n=0
	for d in /data/adb/modules/* /data/adb/modules_update/*; do
		[ -d "$d" ] || continue
		case "$d" in *.disable_all) continue ;; esac
		[ -f "$d/disable" ] && continue
		if touch "$d/disable" 2>/dev/null; then
			echo "$d" >> "$list"
			n=$((n + 1))
		fi
	done
	say "safe-mode: disabled $n module(s); list=$list"
	say "safe-mode: use 'sh cleanup.sh --restore-modules' to undo"
}

# ---------------------------------------------------------------- flow
safe_mode_apply

# sig_enforce must be 0 for an unsigned kernelsu.ko to load; run_lpe.sh
# clears it before the chain when the kernel reports 1.
say "module bypass: sig_enforce=$(cat /sys/module/module/parameters/sig_enforce 2>/dev/null || echo '?') modules_disabled=$(cat /proc/sys/kernel/modules_disabled 2>/dev/null || echo '?')"

# The X300 flow stops the vendor anti-root HAL before installing the
# userspace; OriginOS uses the same name when it is present.  Harmless when
# absent, and it is not restarted (a reboot brings it back).
if [ "$(getprop init.svc.riskdetect 2>/dev/null)" = "running" ]; then
	timeout 10 stop riskdetect 2>/dev/null
	say "riskdetect: stopped -> $(getprop init.svc.riskdetect 2>/dev/null)"
fi

if ksu_live; then
	say "KernelSU already live (module=$([ -d /sys/module/kernelsu ] && echo yes || echo hidden))"
fi

# Candidate order: explicitly selected manager first, then every other
# installed known manager.  This is the main fix for a kernel that pins one
# fork's signature: a wrong first choice must not end the handoff.
CANDS=""
if [ -n "$PKG" ]; then
	if installed "$PKG"; then
		CANDS="$PKG"
	else
		say "warning: $PKG is not installed"
	fi
fi
for p in $KNOWN; do
	[ "$p" = "$PKG" ] && continue
	installed "$p" && CANDS="$CANDS $p"
done
# 7kimisu's two ids: keep whichever is actually installed, not both failures.
if [ -z "$CANDS" ]; then
	say "no known manager APK installed; falling back to /data/adb/ksu/bin/ksud"
	CANDS=""
fi

DONE=0
for p in $CANDS; do
	[ "$DONE" = "1" ] && break
	apk=$(apk_of "$p")
	[ -n "$apk" ] || continue
	say "manager candidate: $p ($apk)"
	KS=$(find_fresh_ksud "$p")
	if [ -z "$KS" ]; then
		say "  no fresh ksud inside $p; skipping"
		continue
	fi
	say "  fresh ksud: $KS"
	say "  version: $(timeout 5 "$KS" --version 2>&1 | head -n 1)"

	if ! ksu_live; then
		late_one "$KS" --allow-shell --kmi "$KMI" --package-name "$p" ||
			late_one "$KS" --allow-shell --package-name "$p" ||
			late_one "$KS" --allow-shell --kmi "$KMI" ||
			late_one "$KS" --allow-shell
	fi
	# Even when the LKM is already live, install the userspace from this
	# manager: that is what creates /data/adb/ksu/bin/su on a stock device.
	if module_present || ksu_live; then
		out=$(timeout 180 "$KS" install 2>&1)
		rc=$?
		if [ -n "$out" ]; then
			printf '%s\n' "$out" | sed 's/^/[ksu]   /'
		else
			say "  install rc=$rc (empty output)"
		fi
		if [ -x "$BINDIR/ksud" ]; then
			say "  userspace now: $(timeout 5 "$BINDIR/ksud" --version 2>&1 | head -n 1)"
		fi
		wait_live 30
		# Opening the manager lets its 越狱模式 page finish the userspace
		# install when ksud alone cannot (seen on 7kimisu/ReSukiSU).
		am force-stop "$p" 2>/dev/null
		monkey -p "$p" -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1
		say "  launched $p"
	fi
	if ksu_live; then
		DONE=1
		PKG_OK=$p
	fi
done

if [ "$DONE" != "1" ]; then
	# No APK at all: use an installed ksud, but say that it was not freshly
	# extracted (the one case where we cannot guarantee the manager match).
	for c in /data/adb/ksu/bin/ksud /data/adb/ksud; do
		[ -x "$c" ] || continue
		say "fallback ksud: $c"
		if ! ksu_live; then
			late_one "$c" --allow-shell ${KMI:+--kmi "$KMI"}
		fi
		timeout 120 "$c" install 2>&1 | sed 's/^/[ksu]   /'
		wait_live 20
		ksu_live && { DONE=1; PKG_OK="(installed ksud)"; }
		break
	done
fi

# ---------------------------------------------------------------- verdict
say "modules:"
grep -iE '^(kernelsu|ksu|sukisu|suki)' /proc/modules 2>/dev/null | sed 's/^/[ksu]   /'
for d in /sys/module/kernelsu /sys/module/ksu; do
	[ -d "$d" ] && say "  sysfs: $d"
done
say "su:"
for s in /data/adb/ksu/bin/su /system/bin/su /system/xbin/su $(command -v su 2>/dev/null); do
	[ -x "$s" ] || continue
	say "  $s -> $(timeout 8 "$s" -c id 2>&1 | head -n 1)"
	break
done
say "diag /data/adb/ksu:"
ls -l /data/adb/ksu /data/adb/ksu/bin 2>&1 | sed 's/^/[ksu]   /' | head -n 25
for f in /data/adb/ksu/log/*; do
	[ -f "$f" ] || continue
	say "log $f:"
	tail -n 10 "$f" 2>/dev/null | sed 's/^/[ksu]   /'
done
dmesg 2>/dev/null | grep -iE 'module|sig_enforce|signature|kernelsu|reject|denied' | tail -n 20 | sed 's/^/[ksu] dmesg /'
dmesg 2>/dev/null | tail -n 10 | sed 's/^/[ksu] dmesg /'

if su_works; then
	say "handoff OK (${PKG_OK:-${PKG:-default}})"
	# 暂存副本由 App 侧的清理负责，这里不动 /data/adb/ksu。
	exit 0
elif ksu_live; then
	say "handoff PARTIAL: KSU live, su not usable yet"
	say "  (open the manager; its 越狱模式 page installs the userspace)"
	exit 6
else
	say "handoff UNCONFIRMED: no live KernelSU found"
	say "  (if the manager now shows 越狱模式, the load completed after this check)"
	exit 7
fi
