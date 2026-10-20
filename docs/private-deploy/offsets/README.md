# 偏移表索引（offsets/）

> 本目录是整个项目的"数据核心"：引擎按 `release`（`uname -r` 全串）选条目；
> 外部部署的 json 优先于 so 内建表，外部 json 缺少的字段会回落内建值（tp 字段有专项保护）。
> 校验值（实测）见根 `README.md` §7。

| 文件 | 版本 | 用途 / 状态 |
|---|---|---|
| `offsets-57+124+145-combined.json` | 57 + 124 + 145 | ★ **本项目权威源**：三条设备验证条目合并。`scripts/gen_builtin.py` 的输入 |
| `offsets-6.1.124-v2.json` | 6.1.124 | ★ PD2324 部署用（v2：补 `tp_sys_exit` 两键，修复 VR 阶段必失败问题） |
| `offsets-6.1.145-maybe-dirty-R15.json` | 6.1.145 | 上游 R15 原始表（11 符号，含 tp 两键） |
| `offsets-import-r15-6.1.57+6.1.145.json` | 57 + 145 | 上游导入文件（57 = 设备验证条目，145 = R15 线） |

> 已删（2026-10-08 精简）：`offsets-124+145-combined.json`（中间合并表，被三版本表取代）、
> `offsets-6.1.145-fixed.json`（R15 表逐字节内容相同的重排版）、`offsets-6.1.124-local.json`
> （v1 坏表，缺 tp 两键导致 VR 阶段必失败——教训见根 README §2.2）。

## 条目结构与关键字段

单条目 JSON（数组）。头部标量：`release`（全串匹配键）、`kernel_phys_load`（MTK=0x80000000）、
`pselect_waiter_shift`、`compact_waiter`（6.1=1）、`mm_struct_sz`（6.1=0x400）。

`symbols` 11 键（全部被引擎使用）：

| 键 | 语义 |
|---|---|
| `off_init_task` / `off_init_cred` | `init_task` / `init_cred`（raw cred 替换目标） |
| `off_root_task_group` | `root_task_group` |
| `off_selinux_enforcing` | `selinux_state`（enforcing 在结构体偏移 0） |
| `off_security_hook_heads` / `off_selinux_blob_sizes` | 仅审计打印（见 docs/build.md §6 的 0x200 历史项） |
| `off_tp_sys_exit_tp` / `off_tp_sys_exit_funcs` | **vr.ko 中和关键**（funcs = tp + 0x40，6.1） |
| `off_slide_nfulnl_logger` / `off_slide_loggers_0_1` / `off_slide_boot_id` | 日志/slide 路径（只影响打印，见根 README §6.2 红线） |

`struct_fields`：33 键；其中 15 个 `task_*` 被解析器使用，其余被忽略（保留全量以防引擎版本差异）。

## 生成与验证

| 目标 | 命令 |
|---|---|
| 重新生成 6.1.124（v2） | `python3 scripts/gen_v2.py`（逐符号 EXACT；可逐字节复现发布版） |
| 验证 6.1.57 | `python3 scripts/verify57.py`（对 `reference/kernel-57/sym_6157.txt` 钉子） |
| 烘焙内建表 | `python3 scripts/gen_builtin.py`（合并表 → `src/kernels/` 三条目 + 调度器） |
| 新机型 | 见 `docs/build.md` §5（ksg.py / build_offsets.py 流程） |
