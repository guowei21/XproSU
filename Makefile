API ?= 35

# Auto-detect NDK
ifeq ($(OS),Windows_NT)
  NDK_ROOT ?= $(subst \,/,$(firstword $(wildcard     $(subst \,/,$(LOCALAPPDATA))/Android/Sdk/ndk/*     $(subst \,/,$(ANDROID_HOME))/ndk/*     D:/AndroidSDK/ndk/*)))
  override NDK_ROOT := $(subst \,/,$(NDK_ROOT))
  PREBUILT := windows-x86_64
  CLANG_BASE := aarch64-linux-android$(API)-clang
  NDK_CC := $(NDK_ROOT)/toolchains/llvm/prebuilt/$(PREBUILT)/bin/$(CLANG_BASE).cmd
else
  NDK_ROOT ?= $(or $(ANDROID_NDK_HOME),$(ANDROID_NDK_ROOT))
  PREBUILT := linux-x86_64
  NDK_CC := $(NDK_ROOT)/toolchains/llvm/prebuilt/$(PREBUILT)/bin/aarch64-linux-android$(API)-clang
endif

SRCS := \
  src/core/main.c \
  src/core/offsets_json.c \
  src/core/util.c \
  src/core/fops.c

# Headers also trigger a rebuild (e.g. a freshly --register-ed src/kernels/<release>/offsets.h).
HDRS := $(wildcard src/core/*.h src/core/*/*.h src/kernels/*.h src/kernels/*/*.h)

# Device offsets are selected at runtime from uname -r.
TARGET_CONFIG ?= target.h

# ── 加固开关（企业级默认开）──────────────────────────────────────────────
#
# HARDEN=1（默认）打开整套编译期/链接期加固；HARDEN=0 产出与旧版逐指令可比的
# 对照引擎。为什么要留这个开关：这台引擎靠 futex 竞速取胜，加固会改变指令布局、
# 栈帧大小与寄存器分配，**可能把"稳定成功"变成"偶尔成功"**，而这种退化不会崩溃，
# 只会降低成功率。所以换加固版本前必须在真机上跑 A/B，比较成功率。
#
# 逐项对应关系：
#   -fstack-protector-strong      栈溢出（canary 覆盖含数组的函数）
#   -fstack-clash-protection      大栈分配跳过 guard page
#   -D_FORTIFY_SOURCE=2           libc 的 *_chk 变体（memcpy/strcpy 等边界）
#   -fvisibility=hidden           不导出非必需符号，缩小动态符号表
#   -fno-common                   重复 tentative 定义直接报错而非静默合并
#   -ftrivial-auto-var-init=zero  未初始化栈变量归零，消掉"未初始化即利用"
#   -mbranch-protection=standard  ARMv8.3 PAuth + BTI（返回地址签名/间接跳转校验）
#   -ffunction-sections -fdata-sections + --gc-sections  裁掉不可达代码
#   -Wl,-z,noexecstack            栈不可执行
#   -Wl,-z,separate-code          代码段与数据段分离映射（缓解 ret2dir/刷写）
#   -Wl,--icf=safe                安全范围内合并等价函数，抬高逆向成本
#   -Wl,-z,relro -Wl,-z,now       立即重定位，GOT 只读
HARDEN ?= 1

ifeq ($(HARDEN),1)
CFLAGS_HARDEN := -fstack-protector-strong -fstack-clash-protection \
  -D_FORTIFY_SOURCE=2 -fvisibility=hidden -fno-common \
  -ftrivial-auto-var-init=zero -mbranch-protection=standard \
  -ffunction-sections -fdata-sections
LDFLAGS_HARDEN := -Wl,-z,noexecstack -Wl,-z,separate-code -Wl,-z,relro \
  -Wl,-z,now -Wl,--as-needed -Wl,--gc-sections -Wl,--icf=safe -Wl,-O2
else
CFLAGS_HARDEN :=
LDFLAGS_HARDEN :=
endif

# CFLAGS_EXTRA lets a local build add flags without editing this file, e.g.
#   make ghostlock CFLAGS_EXTRA=-DGL_VERBOSE
#   make ghostlock HARDEN=0            # 出对照引擎，用于真机 A/B
CFLAGS = -O2 -flto -Wall -Wno-unused-parameter -Wno-sign-compare -Wno-unused-function \
  -Isrc/core -Isrc/kernels -DTARGET_CONFIG_H=\"$(TARGET_CONFIG)\" \
  $(CFLAGS_HARDEN) $(CFLAGS_EXTRA)
LDFLAGS := -fPIE -pie -pthread -flto $(LDFLAGS_HARDEN)

# Release builds drop .symtab: the engine's own global and function names
# (p0_kernel_phys_load, g_init_cred_image, ...) otherwise ship in the binary.
# The engine never introspects itself -- no dlsym, dladdr or backtrace -- so
# stripping is safe.  -DGL_VERBOSE keeps the names for a debugging session.
ifneq (,$(findstring GL_VERBOSE,$(CFLAGS_EXTRA)))
else
LDFLAGS += -s
endif
.PHONY: all clean product

all: ghostlock

ghostlock: $(SRCS) $(HDRS)
	@echo "Using NDK compiler: $(NDK_CC)"
	@echo "Target config: $(TARGET_CONFIG)"
	$(NDK_CC) $(CFLAGS) $(LDFLAGS) $(filter %.c,$^) -o ghostlock

product: ghostlock
	@echo "=== ghostlock binary ready: ./ghostlock ==="
	@echo "构建 APK: .\gradlew.bat :app:assembleDebug"

clean:
	rm -f ghostlock
