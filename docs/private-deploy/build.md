# 构建详解 — GhostLock 私有化树（6.1.57 / 6.1.124 / 6.1.145）

> 本文由原 R15 源码包 `BUILD.md` 更新而来：路径已按标准项目布局调整，技术内容保留并补充本机实测结果。
> 快速入口：`sh tools/build.sh`（零参数可复现）；主文档见根 `README.md` §3。

## 0. 组件与脚本

- 引擎源码：`src/core/`（`main.c` / `fops.c` / `util.c` / `offsets_json.c` + 头文件）、
  `src/kernels/`（三条内建表 + 调度器 `src/kernels/offsets.h`）。
- 构建脚本：`tools/build.sh`（两段式：编译 → 手工链接）、`tools/build_r15.sh`（一键构建+自查）、
  `tools/lld_link.sh`（复刻 NDK clang 驱动的链接命令）。
- 上游原版脚本（路径写死版）留档：`tools/upstream/build.sh.orig`、`tools/upstream/lld_link.sh.orig`。

## 1. 依赖

| 依赖 | 说明 |
|---|---|
| clang / ld.lld | 默认使用 NDK r29 自带 clang 21 + LLD 21（脚本把 `$NDK/bin` 前置到 PATH） |
| NDK r29 sysroot | 本机：`/opt/android-ndk-cache/android-ndk-r29/toolchains/llvm/prebuilt/linux-aarch64`（`NDK=` 可覆盖） |
| python3 | 偏移工具链（scripts/）与重打包脚本 |

> 系统 clang 18 + 同一 sysroot 也能构建（旧指纹 `fb98636f…` 即此类产物）；推荐脚本默认的 NDK clang 21，
> 与已验证指纹一致。`API=35`（可用环境变量覆盖）。

## 2. 编译

```sh
# 两段式（推荐）：默认输出 /tmp/ghostlock_build/ghostlock
sh tools/build.sh /tmp/out/libghostlock.so

# 或一键：
sh tools/build_r15.sh /tmp/out/r15
```

可覆盖：`NDK=<toolchain>`、`API=35`、`WORK=<中间目录>`、`TMPDIR=<临时目录>`。

**内部流程**（`build.sh`）：

1. `clang -c` 交叉编译四个翻译单元：`src/core/main.c`、`offsets_json.c`、`util.c`、`fops.c`
   （`-O2 -flto -fPIE -pthread -Isrc/core -Isrc/kernels -DTARGET_CONFIG_H="target.h"`）；
2. `lld_link.sh` 手工链接（复刻 NDK clang 驱动、剔除 host 注入项）：

```
ld.lld --sysroot=$SYS -EL --fix-cortex-a53-843419 -z now -z relro -z max-page-size=16384 \
  --hash-style=gnu --build-id --eh-frame-hdr -m aarch64linux -pie -dynamic-linker /system/bin/linker64 \
  -o OUT crtbegin_dynamic.o -L… --as-needed <objs> libclang_rt.builtins -ldl -lc \
  libclang_rt.builtins -ldl crtend_android.o
```

关键点：`--fix-cortex-a53-843419`（A53 勘误）、`-z max-page-size=16384`（16K 页）、
`-z now -z relro`（加固）、builtins 出现两次（参数、顺序不要动——与上游产物同构的前提）。

## 3. 指纹对照（本机实测）

| 构建对象 | sha256 | 大小 | 环境 |
|---|---|---|---|
| 本私有化树（3 条内建） | `5293b118cb5726c4323667bee8ab18ce5d926b2869864973257e20a44f27156e` | 94,688 B | NDK r29 clang 21（零参数可复现） |
| 重编版（进入 124 验证 APK） | `fb98636fef4d94bd6f55b6503c54110a6d64f0456dc8a76465274ed01d0dd13e` | 103,440 B | 系统 clang 18 + NDK r29 sysroot（烘焙前树） |
| 上游原始树参考 | `d9ff9c43c6073c47ff10c67b063074813cfb2035348f79ddca3546c9d01051b5` | 105,456 B | Alpine clang 19（历史） |

> **指纹不用于功能判断**：换工具链版本、改任何源码（哪怕注释参与编译的宏）或改动内建表都会改变指纹。
> 查看编译器版本：`readelf -p .comment <so>`。功能验收以真机为准（见根 README §4/§5）。

## 4. 复现检查表（改代码后的最小回归）

```sh
sh tools/build.sh /tmp/out.so          # 未改 src/ 时 sha256 应 = 5293b118…
python3 scripts/verify57.py            # 57 偏移逐符号钉子 → ALL OK
python3 scripts/gen_v2.py /tmp/v2.json # 与 offsets/offsets-6.1.124-v2.json 逐字节一致
python3 scripts/gen_builtin.py --no-prune   # 幂等：对现有树无 diff
```

## 5. 内建表与外部表（加机型时看这里）

- 引擎查找顺序：app 私有目录 `files/offsets.json`（外部，**优先**）→ `/data/local/tmp/offsets.json`
  → 内建表（`uname -r` **全串**匹配）→ 都没有则报错退出。
- 外部 json 允许只写部分字段：内建条目存在时，json 未提供的字段回落内建值（tp 字段有专项保护，防止被空值擦除）。
- 新增/更新机型：
  1. 取目标内核 kallsyms：root 会话 `cat /proc/kallsyms`；或解 boot.img → `Image` → `python3 scripts/ksg.py`（在其目录放 `Image` 运行）；
  2. `python3 scripts/build_offsets.py --kallsyms kallsyms.txt --release "<uname -r>"`（可 `--merge` 进现有表）；
  3. 把条目并入 `offsets/offsets-57+124+145-combined.json` → `python3 scripts/gen_builtin.py` → 重新构建。
- 结构差异注意：`STRUCT_OFFSETS_6_1 / 6_6 / 6_12` 三套宏；`compact_waiter`（6.1=1）；
  `mm_struct_sz`（6.1=0x400）；`funcs = tp + 0x40`（6.1）/ `+0x48`（6.6+，probestub 引入后）。脚本内有断言，不要绕过。

## 6. 历史遗留与可选验证

- **0x200 歧义（历史项）**：6.1.145 的 `security_hook_heads` / `selinux_blob_sizes` 两键，仓库内条目与
  设备验证 JSON 相差 `0x200`；两者均为**审计打印用字段**，且设备成功跑用的是 JSON 值（本树按 JSON 值固化）。
  若要 100% 裁决，可解 vivo 官方全量包（PD2324C 15.1.11.2 / PD2324F 16.2.11.1 的 `payload.bin` 约 9–10GB）直接比对。
- 早期“不含 `-maybe-dirty` 内核”的上游表已被本项目的三条设备验证条目取代（见根 README §2）。
- 已知限制与红线：见根 `README.md` §6（连跑限制、R16 教训、mcast seq=16 现象等）。
