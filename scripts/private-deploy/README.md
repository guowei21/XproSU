# scripts/ — 偏移与构建辅助工具

所有脚本已做路径可移植化（自动定位项目根），可直接在项目任意目录下运行。数据依赖：
`reference/kernel-124/`（kernel.Image / kallsyms / BTF）、`reference/kernel-57/sym_6157.txt`（57 kallsyms）。

## 核心（日常用）

| 脚本 | 作用 | 用法 | 备注 |
|---|---|---|---|
| `gen_builtin.py` | 把 `offsets/offsets-57+124+145-combined.json` 烘焙为 `src/kernels/` 三条内建 + 重写调度器；含全量交叉校验 | `python3 scripts/gen_builtin.py [--no-prune]` | 幂等；默认会清理不在清单里的内建目录（加 `--no-prune` 保留） |
| `gen_v2.py` | 生成 6.1.124（v2）偏移，逐符号 EXACT 断言 | `python3 scripts/gen_v2.py [kallsyms] [template] [out]` | 可逐字节复现发布版 |
| `verify57.py` | 6.1.57 条目 vs 设备 kallsyms 逐符号钉子（含 funcs−tp / lag 断言） | `python3 scripts/verify57.py [json] [sym]` | 期望输出 `ALL OK` |
| `build_offsets.py` | 通用偏移生成（6.1/6.6/6.12） | `python3 scripts/build_offsets.py --kallsyms <k> --release "<r>" [--template <json>] [--merge] [-o <out>]` | 原 R15 工具；`--merge` 写回 template 数组 |

## 数据提取（换机/内核 OTA 后使用）

| 脚本 | 作用 | 用法 |
|---|---|---|
| `parse_boot.py` | boot.img 结构探测/解析 | `python3 scripts/parse_boot.py <boot.img> [outdir]`（产出 `kernel.extracted` 或 `kernel.payload` 到 outdir，默认当前目录） |
| `lz4decomp.py` | LZ4 legacy 帧内核解压 | `python3 scripts/lz4decomp.py <kernel.payload> [out_Image]`（默认与输入同目录 `Image`） |
| `ksg.py` | 从内核 `Image` 手工解完整 kallsyms（57 流程） | 在其目录放 `Image` 后运行；产出 `sym_6157.txt`（格式 `%016x %c %s`） |
| `kallsyms_manual.py` / `kallsyms_full.py` | 从 `reference/kernel-124/kernel.Image` 解 kallsyms（124 流程） | `python3 scripts/kallsyms_manual.py` |
| `btf_dump.py` / `btf_ext.py` | BTF 结构提取（struct_fields 对账） | `python3 scripts/btf_dump.py`（输出到 `reference/kernel-124/btf_fields.txt`） |

## 诊断 / 报告（只读）

| 脚本 | 作用 |
|---|---|
| `test_parser.c` | 宿主侧 `offsets_json.c` 解析器冒烟（不随项目带二进制）：`gcc -I src/core -o /tmp/test_parser scripts/test_parser.c src/core/offsets_json.c && /tmp/test_parser <json> <release>` |
| `sym57_check.py` | 打印 57 表各值落在设备 kallsyms 的什么位置（EXACT / 邻近） |
| `cmp57145.py` | 57/145/124 逐字段差异表（含内部间距指纹） |

## 回归基线（改动后必跑）

```sh
python3 scripts/verify57.py                        # → ALL OK
cp offsets/offsets-6.1.124-v2.json /tmp/v2.bak && python3 scripts/gen_v2.py && \
  cmp offsets/offsets-6.1.124-v2.json /tmp/v2.bak  # → 无输出（逐字节一致；无参=原位重写发布版）
python3 scripts/gen_builtin.py --no-prune          # → 对现有树无 diff（幂等）
```
