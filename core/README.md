# core/ — 6.1 内核重构基线（vendored, MIT）

`timer98260.c` 来自 **molanp/CVE-2026-98260-vivo-s60-poc**（MIT），
其头部注明改编自 **woshigenm/CVE-2026-98260**（MIT）等移植版。
保留原始版权声明，见 `LICENSE.molanp`。

选它作为重构基线的原因：

- 6.1.145 上端到端验证通过（timer UAF → fake cred → SELinux permissive →
  full cap → ksud late-load）；
- 单文件、无外部依赖，包含 tracefs 事件 ID 自发现、线性映射基址投票、
  两段式 socket 喷（phase1 在 exec 前、phase2 由 victim 页 free 触发）、
  `scan_page_alloc_ours` 命中校验（pfn + 喷线程 tid + order）、
  verify-and-repair 回读；
- 端游为 shell 与 fake 两种落地，fake 路径直接对接 KernelSU late-load。

`tools/derive_offsets.py` / `tools/disasm_kernel.py` 同样来自该仓库，用于从
boot.img/Image 推导目标机偏移。

## 构建

```sh
CC=$ANDROID_NDK/toolchains/llvm/prebuilt/windows-x86_64/bin/aarch64-linux-android24-clang
$CC -O2 -static -pthread -Wall -Wextra core/timer98260.c -o t98260
```

## 待做（refactor-98260 分支）

1. 把 `timer98260.c` 里写死的 PD2571（6.1.145）偏移抽成 profile 文件，
   由 `uname -r` 选择（格式参考 dada-cve 的 kernel_profiles，但内容按
   本仓库自有数据重写）；
2. 并入本仓库已有的 vivo 6.1 机型偏移表与 KSU 交接脚本；
3. 把 APK 侧（Shizuku 投放/运行）切到新 core；
4. 5.10 支持作为第二优先级：沿用本仓库已测出的 5.10 偏移与忙轮询 killer。
