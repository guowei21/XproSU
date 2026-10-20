> **说明**：这是随 R15 源码包附带的工作笔记（源码地图 + 红线）。文中 `scripts/sym_6157.txt` 现位于 `reference/kernel-57/sym_6157.txt`；§8 的校验值表为历史记录，**最终产物校验值以本项目根 README §7（实测重算）为准**。

# GhostLock R15 — 源码包（vivo iQOO V2339FA / Dimensity 9300+ / 6.1.145-android14-11-maybe-dirty 专用版）

> 这是**最后一次在目标设备上完整跑通**的版本（R15，2026-10-02 验证：W1→VR→W2→W3→root→KernelSU ready 全流程成功）。
> 后续 R16/R17 的改动已全部回退，本包源码重编译与 R15 产物**字节级一致**（sha256 `d9ff9c43…`）。

---

## 1. 这是什么

GhostLock 是 CVE-2026-43499（futex PI UAF）提权的 native 引擎。整体流程：

```
W1: SELinux enforcing → permissive（写 selinux_enforcing）
VR: vr.ko 中和（vivo 模块，防 ksud 被杀）
W2: cred → init_cred（拿到 root cred）
W3: seccomp 清零（TIF_SECCOMP + seccomp mode）
root 脚本: 写 ksud / late-load → KernelSU 就绪
```

核心写原语：kernelsnitch 泄漏 `mm_struct` + order-3 页喷雾 + **三条可选触发路线**（pselect / tcp / mcast）诱导内核走 PI-chain 完成写。

- **引擎是数据驱动的**：所有内核偏移来自外部 `offsets.json`，so 本身不含机型数据。
- 本包对应的机型数据在 `offsets/offsets-6.1.145-maybe-dirty-R15.json`。

## 2. 目录结构（每个文件的作用）

```
r15/
├── src/                        # 全部 native 源码（编译产物 = libghostlock.so）
│   ├── core/
│   │   ├── main.c              # ★ 主流程编排：W1→VR→W2→W3 阶段机、
│   │   │                       #   waiter_thread（三路线调度）、root 脚本
│   │   │                       #   生成、MTK/XRing SoC 识别、soc_family 探测
│   │   ├── fops.c              # ★ 三条写路线的实现：
│   │   │                       #   pselect 路线 / tcp punch 路线 /
│   │   │                       #   mcast 路线（do_mcast_fake_lock_route，
│   │   │                       #   当前机型用的就是它，seq=16 才命中是正常现象）
│   │   ├── util.c              # ★ spray/payload 核心：prepare_skb_payload（
│   │   │                       #   伪造 rt_mutex/cred/fops 布局）、
│   │   │                       #   prepare_good_kernel_page、日志函数、
│   │   │                       #   futex_op/sched_setattr 系统调用封装
│   │   ├── common.h            # 公共宏：data_addr（image 地址→运行时地址）、
│   │   │                       #   SLIDE_* 宏、路线选择声明、常量
│   │   ├── target.h            # ★ 编译期内建偏移默认值（仅当 json 缺字段时
│   │   │                       #   才被用，正常都由 json 覆盖；值是 6.6 模板的，
│   │   │                       #   对 6.1.145 机型不适用，别直接信它）
│   │   ├── offsets.h           # struct kernel_offsets 定义 + 内建机型注册表
│   │   ├── offsets_json.c/.h   # 自带的最小 JSON 解析器（读 offsets.json，
│   │   │                       #   故意不依赖 cJSON，保持 so 无外部依赖）
│   │   ├── runtime_struct_offsets.h  # _RSO 宏：json 值优先，0 则回落 target.h
│   │   └── kernelsnitch/       # futex PI 泄漏引擎（上游 kernelsnitch 的
│       │                       #   定制版：mm_struct 泄漏 + futex_hash）
│       ├── kernelsnitch.c/.h   # 主引擎
│       ├── futex_hash.c/.h     # futex 私有 hash（影响 PI 链定位）
│       ├── utils.c/.h          # 通用辅助
│       └── timeutils.h         # 时间辅助
│   └── kernels/                # 内建机型偏移表（编译期回落用）
│       ├── offsets.h           # 汇总：#include 各机型条目，按 uname -r 匹配
│       └── <release>/offsets.h # 每个内核 release 一个条目（都是其他机型的）
│                               #   注意：6.1.145-maybe-dirty 故意没有条目，
│                               #   必须走外部 json（R14 教训，见 §6 红线）
├── tools/
│   ├── build.sh                # ★ so 编译脚本（见 §3）
│   ├── lld_link.sh             # lld 链接封装（build.sh 内部调用）
│   └── repack_apk.py           # ★ APK 重打包脚本（见 §4）
└── offsets/
    └── offsets-6.1.145-maybe-dirty-R15.json   # ★ 本机型的权威偏移数据
```

**注意**：`src/core/*.bak_before_mcast_fix` 是改 mcast 前的备份，不参与编译，可删。

**关键依赖关系**（改代码前先看这个）：

- `runtime_struct_offsets.h` 的 `_RSO(field, fallback)` 是偏移的总入口：**json 有值用 json，json 为 0 用 target.h**。
- `SLIDE_INIT_TASK` 是唯一参与 exploit 逻辑的 SLIDE 宏（`fops.c:396`）；`SLIDE_NFULNL_LOGGER` / `SLIDE_LOGGERS_0_1` / `SLIDE_SYSCTL_BOOTID` **只出现在 util.c 的日志打印里**，改错不影响功能，只会误导排查。
- json 字段 → 内存访问的对应：`off_init_task/init_cred/root_task_group` 走 util.c:413-415；`off_selinux_enforcing` 走 main.c:1230（W1 写目标）；`off_tp_sys_exit_tp/funcs` 走 vr.ko 中和。

## 3. so 编译方法

环境：Alpine Linux（aarch64 PRoot）+ clang 19 + NDK r29 sysroot（手工 lld 链接，不跑完整 NDK build）。

```bash
# 产物：一个静态链接的 aarch64 ELF，stripped 后即 libghostlock.so
sh tools/build.sh /tmp/ghostlock_build/ghostlock_r15
```

- 脚本内部：clang 交叉编译 `src/core/*.c` + `src/core/kernelsnitch/*.c` → `.o`，然后 `lld_link.sh` 手工链接。
- 验证产物：`sha256sum` 应为 `d9ff9c43c6073c47ff10c67b063074813cfb2035348f79ddca3546c9d01051b5`（105456B）。
- 若环境不同（Ubuntu + NDK 官方 toolchain），把 clang 换成 `$NDK/toolchains/llvm/prebuilt/*/bin/clang`，链接参数不变即可。

## 4. APK 打包方法

**原理**：GhostLock 的 so 是 json 驱动的引擎，APK 只是容器。所以更新引擎不需要动 Kotlin 层，直接**替换 base.apk 里的 so 再重签**。

```bash
# 1) 重打包：把新 so 塞进模板 APK（丢 META-INF，后面重签）
python3 tools/repack_apk.py \
    base_1_.apk \                      # 模板 APK（原版 v1.1(93)）
    GhostLock-r15-unsigned.apk \
    /tmp/ghostlock_build/ghostlock_r15

# 2) 签名（debug keystore，与设备已装版本同签名，才能覆盖安装保留数据）
java -jar uber-apk-signer.jar \
    --apks GhostLock-r15-unsigned.apk \
    --ks <your-keystore.jks> --ksAlias <key-alias> \
    --ksPass <storepass> --ksKeyPass <keypass> \
    --skipZipAlign -o out/
# 产物: out/GhostLock-r15-signed.apk
```

`repack_apk.py` 的三个关键点（都是 INSTALL_FAILED 的血泪教训）：
- 每个 entry **保留原压缩方式**（unzip 后再压会改变 STORED/DEFLATED 属性）；
- STORED 条目按 Android 要求对齐：`.so` → 16384、`resources.arsc` → 4096、其余 4；
- 必须丢掉 `META-INF/`（旧签名不丢，新签名写不进去）。

**安装**：
```bash
adb install -r out/GhostLock-r15-signed.apk
# 或 shizuku: pm install -r xxx.apk
```

## 5. offsets.json 部署方法

so 启动时按顺序找 json：app 私有目录 `files/offsets.json` → `/data/local/tmp/offsets.json`。

- **正常路径**：把 `offsets/offsets-6.1.145-maybe-dirty-R15.json` 的**内容**写到
  `/data/user/0/com.ghostlock.app/files/offsets.json`（app 进程身份可写）。
- **无 root 但有 Shizuku**：`run-as com.ghostlock.app sh -c 'cat /data/local/tmp/xx.json > files/offsets.json'`
  （注意目标文件属主必须是 u0_a405，600 权限；root 属主的文件 run-as 读不了）。
- 校验：md5 应为 `d939ddfa91c32b2bb70339453f14bfbb`。

字段速查（R15 数据，`_text=0xffffffe214600000` 基准）：

| 字段 | 值 | 用途 |
|---|---|---|
| off_init_task | 0x0210fb40 | fops.c:396 waiter_task 锚点 |
| off_init_cred | 0x02122430 | main.c:108 g_init_cred_image |
| off_root_task_group | 0x0234a740 | util.c:414 |
| off_selinux_enforcing | 0x0247fb98 | W1 直接写目标 |
| off_tp_sys_exit_tp / funcs | 0x022f3600 / 0x022f3640 | vr.ko 中和（6.1: funcs=tp+0x40） |
| off_slide_nfulnl_logger / loggers_0_1 / boot_id | 0x02102f00 / 0x022d4e28 / 0x02276810 | 仅日志打印（见 §2 说明） |

## 6. 已知问题与红线（改代码前必读）

1. **mcast seq=1..15 errno=99、seq=16 才成功是正常现象**（EADDRNOTAVAIL，机制如此），不要"修"它。
2. **R16 教训**：`off_slide_*` 三个字段在源码里只有 printf 引用，当时把它们的值改成 kallsyms 真值后连崩三次 —— 虽然静态分析证明与改动无关（崩在 sched_setattr PI-walk），但**没有对照实验前不要再动任何 json 字段**。
3. **已知残留风险**（上游 issue #78 / #201 同机型报告）：race 失败会在内核留悬空 PI 节点（"幽灵"），**连续跑第二次容易崩**，崩后需要重启设备清状态。上游修复 `b8ce3954 fix(race): enforce attack resource lifetimes`（ghost disarm）在本包**未移植**——当时单独验证失败，回退了。
4. `console-ramoops-0`、`.ghostlock_policy.*` 是 root 属主，run-as 读不了，要 root 会话才能看 panic 全文。
5. `target.h` 的内建默认值是 6.6 模板的，对本机型**不适用**，仅作 json 缺字段时的回落，别直接信。

## 7. 版本历史（简要）

- R9-R12: 修 neutralize 地址、脚本 devmem 宽度、execl EFAULT
- R14: 撤内建表，全走 json；`off_tp_sys_exit_tp` 新增、`funcs=tp+0x40` 修正
- **R15: 稳定版**（本包）。加 offsets audit 日志（11 字段打印 json/builtin/img_off 三列）
- R16: 改 `off_slide_*` 三字段为 kallsyms 真值 → 连崩三次 → 回退
- R17: 移植上游 ghost disarm → 失败 → 回退

## 8. 产物校验值

| 文件 | 校验 |
|---|---|
| libghostlock.so (R15) | sha256 `d9ff9c43c6073c47ff10c67b063074813cfb2035348f79ddca3546c9d01051b5` / 105456B |
| GhostLock-r15.apk | md5 `6372cd4a2c4d2478761c50c55bd95019` / sha256 `ac1853db7b464afd…` / 19797449B |
| offsets-r15 (json) | md5 `d939ddfa91c32b2bb70339453f14bfbb` |
| debug.keystore | SHA256 `<cert-sha256>` |
