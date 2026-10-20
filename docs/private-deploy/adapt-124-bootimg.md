> **历史文档（2026-10-08）**：文中路径为当时会话工作目录（<workspace>/bootimg/ 等）；对应文件现已归档到本项目的 `reference/kernel-124/`、`offsets/`、`scripts/`。正文未改动。

# offsets 适配报告 — PD2324 boot.img (kernel 6.1.124)

生成时间: 2026-10-08 · 工作目录 `<workspace>/bootimg/`

## 一句话结论

原 JSON (`offsets-6.1.145-local.json`) 是给 **6.1.145** 内核的；本机 boot.img 内核实测为 **6.1.124**。
- `struct_fields`（33 项）：**基本通用**，逐项经本机 BTF 验证全部一致 ✓
- `symbols`（9 项）：**不通用**，两内核存在成组漂移（+0x17188 ~ +0x22B98），已按本机内核逐项实测适配 → `offsets-6.1.124-local.json`

## 测了什么 / 怎么测的

| 步骤 | 结果 |
|---|---|
| 解析 boot.img 头 | `ANDROID!` v4, page 4096, kernel @0x1000, ramdisk_size=0, 无 dtb |
| 解压内核 | lz4 (legacy frame) → `kernel.Image` = 36,813,312 B |
| 内核版本 | `Linux version 6.1.124-android14-11-maybe-dirty (build-user@build-host)` |
| kallsyms 提取 | 112,084 符号；相对基址 `kallsyms_relative_base = 0xFFFFFFC008000000` |
| 基址校验 | `_text`=+0x0, `_stext`=+0x10000, `linux_banner` 符号与镜像内字符串**逐字节吻合** ✓ |
| BTF | 从镜像切出 5,769,202 B（原 JSON 标 5,836,866，因版本不同） |
| 结构体对账 | cred / seccomp / page / slab / task_struct / rt_mutex_waiter 全部一致 |

## 符号适配明细（offset = 相对 0xFFFFFFC008000000）

| JSON 键 | JSON 原值 (6.1.145) | 本机实测 (6.1.124) | 漂移 | 状态 |
|---|---|---|---|---|
| off_init_task | 34667328 | **34536128** (0x20EFAC0) | +0x20080 | 实测✓ |
| off_init_cred | 34743344 | **34612144** (0x21023B0) | +0x20080 | 实测✓ |
| off_root_task_group | 37005120 | **36865856** (0x2328740) | +0x22000 | 实测✓ |
| off_security_hook_heads | 23276752 | **23182152** (0x161BB48) | +0x17188 | 实测✓ |
| off_selinux_blob_sizes | 23278560 | **23183960** (0x161C258) | +0x17188 | 实测✓ |
| off_selinux_enforcing | 38271896 | **38129664** (0x245D000) | +0x22B98 | 推断*|
| off_slide_nfulnl_logger | 34615040 | **34483832** (0x20E2E78) | +0x20088 | 实测✓ |
| off_slide_boot_id | 36136976 | **38266384** (0x247E610) | — | 候选**|
| off_slide_loggers_0_1 | 36523560 | **34483656** (0x20E2DC8) | — | 候选**|

\* 本机内核**没有** `selinux_enforcing` 符号；SELinux 开关存放于 `selinux_state.enforcing`，BTF 确认该字段位于结构体**偏移 0**，故取值 `selinux_state` 地址 0x245D000（漂移量与本区组一致）。如果你的工具是"写 1 字节/4 字节到该地址关闭 SELinux"，此值可用。备选（语义存疑，不推荐）：`selinux_enforcing_boot` = 0x208A9D8（initdata，启动后被释放，不适用）。

\** 说明：
- `off_slide_boot_id`：本机唯一 boot_id 对象是 `sysctl_bootid`（/proc/sys/kernel/random/boot_id 的存储）。但它在两个内核里的相对位置差了约 2MB，与其它符号的漂移规律不符，无法 100% 确认两个 JSON 值指向同一对象。若你的工具是"读 /proc 拿到 boot_id 值 → 内存扫描定位"，本机应使用 0x247E610。
- `off_slide_loggers_0_1`：本机 `loggers` 数组 = 0x20E2DC0；按 `[0][1]` 元素语义给出 +8 = 0x20E2DC8。若你的工具实际用数组基址，请改为 0x20E2DC0。

## struct_fields 校验（BTF / 本机 6.1.124）

33/33 全部一致 —— 含 `sizeof(mm_struct)=968`、`struct_page_*`、`slab_cache`、`cred_*`、`seccomp_*`、全部 `task_*`、全部 `waiter_*`。

名称备注：本机 BTF 中 `rt_mutex_waiter` 的字段名为 `tree_entry` / `pi_tree_entry`（值 0 / 24，与 JSON 键 waiter_tree / waiter_pi_tree 取值一致）。

## 未验证 / 保留项

| 键 | 保留值 | 说明 |
|---|---|---|
| compact_waiter | 1 | 工具逻辑参数，静态数据无法验证，按原值保留 |
| pselect_waiter_shift | 1 | 同上 |
| mm_struct_sz | 1024 | 推测为 mm_struct 的 slab 取整桶（968→1024），两内核一致，保留 |
| btf_size | **5769202** | 已按本机 BTF 实测替换（原 5836866 是 6.1.145 的） |
| kernel_phys_load | 2147483648 | 0x80000000，未改动（需实测） |
| kimage_text_base | 1.8446743798965862E19 | 与实测 base 0xFFFFFFC008000000 完全一致（浮点回写精确），保留 |

## 产物文件

| 文件 | 说明 |
|---|---|
| `offsets-6.1.124-local.json` | **适配后的配置（用这个）** |
| `kernel.Image` | 解压出的内核镜像（36.8MB） |
| `kernel.btf` | 从内核切出的 BTF（5,769,202B） |
| `kallsyms_manual.txt` | 112,084 个符号全量（地址/类型/名字） |
| `btf_fields.txt` | 关键结构体字段偏移完整 dump |

## 没做的 & 可选的下一步

1. 两个 vivo 官方全量包（PD2324C 15.1.11.2 / PD2324F 16.2.11.1）里的 `payload.bin` 各约 9–10GB，理论上可流式解包抽出 boot 分区镜像，**直接验证原 JSON 是否就是 16.2.11.1 的内核（6.1.145）**——若要 100% 锁死三个存疑键的语义，做这一步。
2. 若有该工具（用这个 JSON 的提权程序）的源码/文档，把 `off_slide_boot_id`、`off_slide_loggers_0_1` 的实际用法发来，我可以精确校准。
