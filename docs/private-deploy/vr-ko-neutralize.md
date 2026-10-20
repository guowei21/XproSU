# vr.ko 中和方法（源码级详解）

> 适用：vivo 机型（PD2324 / V2339FA 等）。本文描述本项目引擎里的实现（`src/core/main.c`、
> `src/core/fops.c`），以及与偏移表（`offsets/`）的配合关系。改 VR 相关代码/字段前先读完本文。

## 1. 背景与症状

`vr.ko` 是 vivo 系统里的内核模块，对 App 来源的进程做两层防护：

1. **任务打标**：fork/clone 时给任务结构打 tag（tag A @ `+0x06`、tag B @ `+0x2c`）。
2. **退场探针**：在 `__tracepoint_sys_exit`（sys_exit tracepoint）上挂了回调；当"被打标"的进程
   后来持有 euid 0（提权成功）时，在进程退出路径上把进程杀掉。

**症状**：提权链本身成功，但 `ksud` / KernelSU late-load 进程被静默击杀——表现出来像"无关崩溃"或
"KernelSU 没加载起来"，极容易被误判为别的问题。因此 **VR 中和是提权后能真正留下 root 的必要条件**。

## 2. 三层机制（按执行顺序）

```
W1（SELinux permissive）
 └─ (c) per-task 打标清除  ← W2 校验 euid 之前执行（双保险）
W2（cred → init_cred）
W3（seccomp 清零）
 └─ (a) 全局中和：__tracepoint_sys_exit.funcs = 0   ← 必须在 late-load 之前
root 脚本运行
 └─ (b) devmem 兜底：物理地址再写一次零 + 读回校验
ksud late-load → KernelSU ready
```

### (a) 全局中和（主路径）

**原理**：把 `funcs` 指针清零后，`sys_exit` 探针回调永不触发 → vr.ko 的退场击杀失效。

- **地址推导**（`main.c`，注释原文："offsets.json carries the ABSOLUTE
  `__tracepoint_sys_exit` … funcs field lives at +0x40 on 6.1 / +0x48 on 6.6"）：

  ```
  tp_off   = offsets.off_tp_sys_exit_tp        # __tracepoint_sys_exit，相对 KIMAGE_TEXT_BASE
  funcs_va = data_addr(KIMAGE_TEXT_BASE + tp_off) + 0x40      # android14-6.1
  ```

  兼容旧表：若只提供 `off_tp_sys_exit_funcs`（绝对 funcs 偏移），走 legacy 分支直接写。
- **写入**：`do_one_write(funcs_va, "VR: sys_exit tp->funcs", 1, 1)`
  （leaf=1 / mode=1 = "向目标地址写 0"），失败重试 5 次。
- **偏移缺失的后果**（原文注释）：skipped → `vr.ko stays armed and ksud dies at late-load`。
  引擎会大声报错：`vr.ko neutralize SKIPPED: offsets.json has no off_tp_sys_exit_tp / off_tp_sys_exit_funcs`。
- **成功日志**：`vr.ko sys_exit tracepoint funcs zeroed (attempt N)`。

> 这就是 6.1.124 v1 偏移"必失败"的原因：v1 表里没有这两个键（值=0）。v2 起齐全（见根 README §2.2）。

### (b) root 脚本 devmem 兜底

root 脚本（`write_root_script()` 生成）在拿到 root 后、late-load 前执行：

```sh
TP_PHYS=$(cat /data/local/tmp/_gl_tp_phys)     # 引擎预写：p0_kernel_phys_load + tp_off + 0x40
OLD=$(devmem "$TP_PHYS" 8)                      # 读（宽度单位=字节，最大 8）
devmem "$TP_PHYS" 8 0                           # 写零
NEW=$(devmem "$TP_PHYS" 8)                      # 读回
# 三态日志：OK / partial / FAILED（devmem/STRICT_DEVMEM 不可用时会 FAILED）
```

- 物理地址换算：`TP_PHYS = p0_kernel_phys_load + tp_off + funcs_off`
  （MTK 机型 `p0_kernel_phys_load = KIMAGE_TEXT_BASE − MTK_VADDR_BASE`，即 0x80000000）。
- 引擎把该值写入 `/data/local/tmp/_gl_tp_phys`（文件方式传递，避免环境变量泄漏到子进程链）。
- 历史坑：早期 `devmem` 宽度写成 `64` 被内核直接拒绝——**宽度是字节数**。

### (c) per-task 打标清除（W2 前，双保险）

`main.c` 中 "vivo vr.ko anti-root per-task bypass (ported from root.c)"：

```c
/* 1) 清 thread_info.flags 整字：同时覆盖 tag A(@+0x06) 与 VR_SYSCALL_TP_FLAG(0x400) */
do_one_write(child_task + TASK_THREAD_INFO_FLAGS_OFF, "VR: flags+tagA", 1, 1);
/* 2) 对齐清 0x28 字，覆盖 tag B(@+0x2c) */
do_one_write((child_task + VR_TAG_B_OFF) & ~7ULL, "VR: tagB", 1, 1);
```

- 常量（`main.c` 顶部默认值）：`VR_TAG_A_OFF 0x06`、`VR_TAG_B_OFF 0x2c`、
  `VR_SYSCALL_TP_FLAG 0x400`、`TASK_THREAD_INFO_FLAGS_OFF 0x00`。
- 模块探测：读 `/proc/modules`，模块名以 `vr` 开头（"vr " / "vr_"）即认为加载；读不到则保守假定已加载。
- 调试开关：`GHOSTLOCK_SKIP_VR=1` 跳过本步骤（日志：`VR: skipped by GHOSTLOCK_SKIP_VR`）。
- 失败日志：`VR.ko tag clear failed; child may be killed during W2 verify`。

## 3. 偏移表配合与自检

| 字段 | 用途 | 6.1.57 | 6.1.124 | 6.1.145 |
|---|---|---|---|---|
| `off_tp_sys_exit_tp` | `__tracepoint_sys_exit`（kbase 相对） | 0x22320a0 | 0x22d19c0 | 0x22f3600 |
| `off_tp_sys_exit_funcs` | funcs 字段（= tp + 0x40） | 0x22320e0 | 0x22d1a00 | 0x22f3640 |

- 自检断言（`scripts/gen_v2.py`、`scripts/gen_builtin.py` 内）：`funcs − tp == 0x40`；
  且 `__tracepoint_sys_exit − __tracepoint_sys_enter == 0x48`（结构间距校验）。
- `off_security_hook_heads` / `off_selinux_blob_sizes` 与 VR 无关（审计打印用）。

## 4. 失败模式速查

| 现象 | 原因 | 处理 |
|---|---|---|
| late-load 进程被杀、KernelSU 起不来 | 全局中和没做/写失败 | 检查偏移两键是否存在；看日志 `neutralize SKIPPED/FAILED` |
| 探针注册时段内核 panic | 写错位置（历史：+0x10 打到 static_call_key；6.6 应为 +0x48） | 核对 `funcs` 偏移与结构间距断言 |
| `partial` / `FAILED`（devmem） | STRICT_DEVMEM / 权限 | devmem 只是兜底；主路径 (a) 成功即 OK |
| W2 校验时子进程被杀 | per-task 打标未清 | 检查 `VR.ko tag clear failed` 日志；确认 `GHOSTLOCK_SKIP_VR` 没被误设 |

## 5. 源码索引（当前树）

| 位置 | 内容 |
|---|---|
| `src/core/main.c`（VR 阶段） | per-task 打标清除（~L1295 起）、全局中和（~L1451 起） |
| `src/core/main.c`（root 脚本） | devmem 兜底段（~L630 起），`TP_PHYS` 文件写入（~L986 起） |
| `src/core/fops.c` | `do_one_write` 的写原语与重试逻辑（VR 调用点依赖它） |
| `src/core/offsets_json.c` + `util.c` | json 解析与 `AUDIT` 字段打印（`tp_sys_exit_tp/funcs` 两行） |
| `src/kernels/offsets.h` | `off_tp_sys_exit_tp/funcs` 字段注释（layout 说明） |
| `scripts/gen_builtin.py` | 三版本 `funcs==tp+0x40` 断言 |
