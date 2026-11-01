# 上游同步方案（XproSU ← ghostlock-app）

> 上游：`YuKongA/ghostlock-app`，本地参考克隆在 `vendor/ghostlock-app`（已 unshallow，587 个提交）
> 本工程 fork 点：`50d2b72`（2026-09-12，"pselect: fix compact route on 6.1"）
> 上游当前：`437b3b2`（2026-10-27）
> 本文所有数字都是实测值，可用 `tools/sync/upstream_report.py` 复现

---

## 0. 结论先行

**不能 merge，只能分层移植。** 三条理由，都是结构性的：

1. 上游从 `50d2b72` 之后把整个 native 引擎从 C 重写成 C++。`src/core/main.c` / `fops.c` / `util.c` 在 HEAD 上已经不存在，取而代之的是 `src/core/attack/ops.cpp`、`src/core/session/*.cpp`、`src/core/race/pi_race.cpp`。本工程依赖的 `exec + GHOSTLOCK_* 环境变量 + offsets.json` 契约，上游换成了 JSON profile + stdio 状态协议。
2. 上游把内核偏移从编译期头文件改成了运行时 profile：`src/kernels/*/offsets.h` 从 43 个降到 **0 个**，同一份数据变成 `app/src/main/assets/kernel_profiles/*.conf`（**85 个**，HOCON 格式）。
3. 本工程的私有化层（本地实测绝对基址、AES 封装的偏移表、设备收窄）在上游完全没有对应物，任何 merge 都会把它们当"冲突"。

所以同步 = **按层挑，不按分支合**。收益最大、风险最低的是第 1 层（结构偏移数据），其次是第 2 层（引擎补丁），App 层价值最低。

---

## 1. 现状测量

### 1.1 上游 `50d2b72..HEAD` 的规模

| 项 | 值 |
|---|---|
| 提交数 | 494 |
| 文件改动 | 419 |
| 增删 | +43,572 / −7,651 |
| 触碰 `src/core/*.c|*.h` 的提交 | 137（最终全部被 `.cpp` 取代，不是可移植补丁） |
| 提交主题前五 | `refactor(native)` 107、`docs(native)` 56、`docs` 29、`docs(analysis)` 18、`test(native)` 14 |

也就是说，上游这 494 个提交里 **107 个是 native 重构**，这是"架构换代"，不是"迭代更新"。

### 1.2 本工程 `src/core` 与上游 `50d2b72` 的差异

| 文件 | 增 | 删 |
|---|---|---|
| `main.c` | 352 | 12 |
| `fops.c` | 230 | 9 |
| `util.c` | 42 | 1 |
| `common.h` | 8 | 0 |
| `target.h` | 7 | 0 |
| `offsets_json.c` | 2 | 0 |
| 未改动 | `offset.h`、`offsets_json.h`、`runtime_struct_offsets.h`、`kernelsnitch/*` | |

**注意**：`README.md` 写的"`src/` 逐文件保留"只对 `original-core` 那条线成立；相对 `50d2b72` 实际有 641 行改动。以后维护 `src/core` 时要按"我们的 fork"对待，不能假设等于上游。

### 1.3 App 层差异

| 上游 `com.ghostlock.app` | 增 | 删 |
|---|---|---|
| `data/AndroidGhostlockRepository.kt` | 221 | 345 |
| `ui/GhostlockUi.kt` | 809 | 508 |
| `ui/GhostlockViewModel.kt` | 197 | 377 |
| `domain/repository/GhostlockRepository.kt` | 45 | 22 |
| `ui/MainActivity.kt` | 29 | 41 |
| `GhostlockApplication.kt` | 15 | 4 |
| `domain/usecase/GhostlockUseCases.kt` | 7 | 36 |
| `domain/model/GhostlockModels.kt` | 3 | 29 |
| `domain/usecase/FormatLogUseCase.kt` | 3 | 3 |

本地独有：`data/LocalOffsets.kt`、`data/DeviceLogStore.kt`、`data/ManagerScanner.kt`、`domain/model/SupportedKernels.kt`。
上游独有：`domain/usecase/OffsetMatching.kt`（我们的偏移匹配在仓库层内联）。

---

## 2. 私有化层：本工程真正独有的部分

这七项是"私有化部署"的实体，与上游没有任何对应物，**任何同步动作都不得触碰**。

### 2.1 偏移数据与封装（核心）

| 路径 | 作用 |
|---|---|
| `docs/private-deploy/offsets/*.json` | 57 / 124 / 145 三条 release 的实测偏移源表，另含 R15 变体 |
| `app/src/main/assets/offsets.enc` | 上述表经 AES-256-GCM（AAD=`XSO1`）密封后的随包资产，4,973 字节 |
| `app/src/main/kotlin/.../data/LocalOffsets.kt` | 运行时解密，密钥 = `SHA-256("XproSU/local-offsets/v1")` |
| `tools/pack_offsets_local.py` | 打包期密封工具 |
| `src/kernels/offsets.h` | 三条内建兜底表（导入失败时用） |
| `src/kernels/<release>/offsets.h` | 三条 release 的编译期结构 |

**私有化的实质不是"有偏移表"，而是表里这三个字段必须本地实测**：

```
kimage_text_base    实测（上游 profile 里是 null，靠运行时推导）
kernel_phys_load    实测（同上）
btf_size            实测（用于 KernelSnitch 校验）
```

上游 `kernel_profiles/*.conf` 里 `kernel_phys_load = null`、`kernel_phys_offset = null`，它靠 runtime 推导。我们直接写死实测值 —— 这是"在目标机型上一次跑通"的代价，也是本版本相对上游的差异所在。

### 2.2 设备收窄

`domain/model/SupportedKernels.kt` 只认三条 `uname -r`：

```
6.1.57-android14-11-maybe-dirty
6.1.124-android14-11-maybe-dirty
6.1.145-android14-11-maybe-dirty
```

上游 HEAD 的 85 个 profile 覆盖 5.10 / 5.15 / 6.1 / 6.6 / 6.12 全系（含 Android 15/16、GKI 4K 页）。**收窄是刻意选择**，不随上游扩张。

### 2.3 去授权化

| 项 | 状态 |
|---|---|
| `license/` 包、卡密、指纹、GLT2 容器、心跳、日志上传 | 已删除 |
| `BuildConfig.LICENSE_BASE_URL` | 已删除 |
| `INTERNET` 权限 | 未申请（上游 `AndroidManifest.xml` 仍申请） |
| `network_security_config.xml` | 未使用（webui 分支才有） |

注意：上游 `50d2b72` 本身也没有 `license/` 包，所以这一项是相对**更早的 XproSU 收费版**的私有化，不是相对上游。

### 2.4 包名与版本号

- 包名 `com.ghostlock.app` → `com.ghostlock.pro`
- `app/build.gradle.kts` 的 `versionCode` 手工固定（当前 `214`）；无 `.git` 目录时 `git rev-list --count` 会退化成 1
- release 构建强制要求正式 keystore，缺失直接失败，绝不回退 debug 签名

### 2.5 私有化构建链

`tools/private-deploy/build.sh`、`build_r15.sh`、`lld_link.sh`、`repack_apk.py`，配套说明在 `docs/private-deploy/`（8 篇 markdown + 引擎快照 `docs/private-deploy/engine/`）。

### 2.6 历史遗留：`server/gl-license/`

20 个文件，约 250 KB，Python 标准库实现的旧卡密授权服务（`server.py`、`store.py`、`crypto.py`、`admin_ui.html` 等）。

本版 App 不再调用它。它和上游无关，也和当前构建无关，**建议移出主仓**（见 §6.3）。

### 2.7 我们自己加的引擎修复（也不在上游）

| 提交 | 内容 |
|---|---|
| `3884fd4` | 兼容模式开关通过 `.ghostlock_ksu.log` 之外的文件传递（原先被最小 `envp` 掐掉，功能一直是死的） |
| `0136372` | 移交 `/data/adb/ksu` 布局 + `post-fs-data`，App 侧补"打开根管理器"跳转 |
| `46e98a6` | 执行管理器**自己的** `libksud.so` 真实路径，而不是 App 私有目录的副本 |

---

## 3. 上游演进：哪些东西理论上可移植

### 3.1 偏移数据（收益最高）

上游 HEAD：`app/src/main/assets/kernel_profiles/`，85 个 `.conf`（HOCON）。结构：

```hocon
include "credential-6x.conf"
include "kernelsnitch-6x.conf"
release = "6.1.145-android14-11-geaa643a2c0ee-ab14763719"
schema_version = 1
kernel_major = 6
kernel_phys_load = null
kernel_phys_offset = null
route { tcp_zerocopy { compact_waiter = 1 } }
fallback { to = "select_stack"  route { select_stack { waiter_shift = 1 } } }
kernelsnitch { mm_struct_sz = 1024 }
task_struct {
  prio = 132   normal_prio = 140   sched_task_group = 840
  pi_lock = 2340   pi_waiters = 2360   pi_top_task = 2376   pi_blocked_on = 2384
  pid = 1584   tgid = 1588   atomic_flags = 1520
  real_cred = 2096   cred = 2104   comm = 2120   tasks = 1360
}
```

与我们的 `offsets.json` 的映射关系（实测）：

| 上游 `.conf` | 我们的键 | 能否自动同步 |
|---|---|---|
| `task_struct.*` 14 个字段 | `struct_fields.task_*` | ✅ 1:1，纯数值搬运 |
| `kernelsnitch.mm_struct_sz` | `mm_struct_sz` | ✅ |
| `route.tcp_zerocopy.compact_waiter` | `compact_waiter` | ✅ |
| `fallback.select_stack.waiter_shift` | `pselect_waiter_shift` | ✅ |
| `credential-6x.conf` 的 `cred { copy_size = 136, caps_offset = 48, … }` | 我们的 `cred_uid=4` / `cred_caps=40` / `cred_security=120` / `cred_securebits=36` | ❌ **策略不同** |
| `kernel_phys_load` / `kernel_phys_offset` | `kernel_phys_load` / `kimage_text_base` | ❌ 上游是 `null` + 运行时推导 |
| — | `btf_size`、`symbols.off_*`（10 项）、`waiter_*`（6 项） | ❌ 上游无对应 |

**关键结论**：上游能给的是"结构体布局"，给不了"绝对地址"。后者必须每台目标机实测 —— 这正是私有化部署不可替代的部分。

`cred` 尤其要注意：上游已改成**整块拷贝**（`copy_size = 136`, `caps_offset = 48`），我们是**逐字段写入**。两种策略不能混用，`cred_*` 四个键继续本地维护。

### 3.1.1 实测结果（2026-11-01）

用 `conf_to_offsets.py` 跑了两组，结论明确：

| 输入 profile | 映射到 | 结构字段 | 标量 | 差异 |
|---|---|---|---|---|
| `6.1.145-android14-11-geaa643a2c0ee-ab14763719.conf` | 我们的 `6.1.145-…-maybe-dirty` | 14 | 3 | **0** |
| `6.1.134-android14-11-maybe-dirty.conf` | 我们的 `6.1.124-…-maybe-dirty` | 14 | 3 | **0** |

也就是说：**同一 6.1 KMI 下，上游独立测得的 `task_struct` 布局与我们本地实测逐键相同**，跨小版本也相同。这有两层含义：

1. A 层同步在 6.1 系列上主要是"交叉验证"而不是"更新数据" —— 两边独立测得同一组数，说明谁都没错。
2. 真正会产生差异的是**跨 KMI**（将来支持 6.6 / 6.12 时 `task_struct` 布局才变），那时 A 层才有"搬运"的意义。

这个结果也反过来印证 §2.1：上游 `.conf` 缺的正是绝对基址，而那部分我们本来就不指望它。

### 3.2 引擎补丁

137 个提交动过 C 源文件，但它们的结局是"文件被删"。逐条筛，只有一小部分是**与架构无关的逻辑修复**，例如：

- `d2ab286 feat(app): pick any KernelSU-family manager that ships libksud.so` —— 我们已经在 `ManagerScanner` 里实现（还多支持了 APK 内提取）
- `b8ce395 fix(race): enforce attack resource lifetimes` —— 资源生命周期，需人工读后判断能否搬到 C
- `a951814 feat(profile): configurable kernel_phys_offset` —— 上游开始支持手填基址，思路可直接借鉴

移植判定标准：**能否在不引入 C++ 会话/route/profile 抽象的前提下表达**。不能的话就不移植，只记录结论。

### 3.3 App 层

价值最低。上游 App 已改为 Shizuku 通道 + profile 选择 + 状态回调（`statusCallback`），我们的 App 是 exec + 日志流。`ManagerScanner` 是唯一已经对齐过的模块（我们版本还多了 APK 内提取）。

唯一值得跟进的是：上游新加的 `OffsetMatching.kt`（release 匹配策略）如果比我们的严格，可以抄。

### 3.4 明确不做

- C++ native 架构（`attack/` `session/` `route/` `race/` `profile/`）
- profile/HOCON 运行时（我们编译期 + offsets.json 双轨已经稳定）
- Shizuku 通道
- 设备面扩张到 5.10 / 5.15 / 6.6 / 6.12

---

## 4. 同步矩阵

| 层 | 内容 | 频率 | 方式 | 验收 | 风险 |
|---|---|---|---|---|---|
| A 偏移数据 | 85 个 `.conf` 的 `task_struct`/`kernelsnitch`/`route` 字段 | 每月 | 脚本转换 + 人工确认，重新 pack `offsets.enc` | 三条 release 的 `offsets.json` 与旧版逐键 diff，只有预期键变化 | 低（纯数据，不进 `src/`） |
| B 引擎补丁 | `fix(native)`/`fix(race)` 中可表达为 C 的部分 | 每季 | 逐条 cherry-pick 到 `src/core`，一次一条 | 真机 A/B：同一台机、同一次开机周期、新旧引擎各跑一次 | **高**（时序敏感） |
| C App 逻辑 | `ManagerScanner`、偏移匹配、日志策略 | 每季 | 人工读 diff 后手改（包名要映射） | 单元测试 + 真机 | 中 |
| D 架构 | C++ 重写、profile 系统、Shizuku | 不同步 | 只读参考 | — | — |

---

## 5. 机制

### 5.1 基线标记

在 `vendor/ghostlock-app` 里打一个只读 tag，锁住我们知道"从哪分叉"的那一刻：

```powershell
cd vendor\ghostlock-app
git tag -f xprosu-fork 50d2b72
```

主仓根目录再记一行事实（避免下次重新考古）：

```
docs/upstream-sync/baseline.md
  fork point : 50d2b72 (2026-09-12)
  fork date  : 2026-10
  引擎世代   : C（上游已于 50d2b72 之后全面 C++ 化）
```

### 5.2 拉取

`vendor/ghostlock-app` 已经是完整克隆（587 个提交），走仓库级代理即可：

```powershell
cd vendor\ghostlock-app
git fetch --prune origin
```

### 5.3 体检脚本 `tools/sync/upstream_report.py`

一条命令回答"这次上游带来了什么，哪些跟我有关"：

```
输入：vendor/ghostlock-app（git 仓库），基线 50d2b72
输出：
  1. 新增/变更的 kernel_profiles/*.conf 列表（→ A 层）
  2. 触碰 src/core/*.c|*.h 的提交（→ B 层候选，按 fix/feat 分类）
  3. 触碰 app/**.kt 的提交（→ C 层候选）
  4. 触碰 Makefile / build.gradle.kts / AndroidManifest.xml 的提交（→ 需人工判定）
  5. 新增的顶层目录/文件（→ 判定是否属于 D 层）
```

脚本不修改任何东西，只出清单。它的价值是让"要不要同步"变成一次阅读而不是一次考古。

### 5.4 偏移转换脚本 `tools/sync/conf_to_offsets.py`

```
输入：vendor/ghostlock-app 的 kernel_profiles/<release>.conf
输出：与 docs/private-deploy/offsets/*.json 同 schema 的条目，缺失键显式保留旧值

规则（已实测确认）：
  task_struct.<k>        → struct_fields.task_<k>
  kernelsnitch.mm_struct_sz → mm_struct_sz
  route.tcp_zerocopy.compact_waiter → compact_waiter
  fallback.select_stack.waiter_shift → pselect_waiter_shift
  kernel_phys_load/kernel_phys_offset = null → 保留本工程实测值，不覆盖
  cred { … }             → 跳过（策略不同），保留本地逐字段值
  顶层缺失键             → 保留本地值，不删
```

转换后必须重新生成资产，否则 App 里还是旧表：

```powershell
python tools\pack_offsets_local.py app\src\main\assets\offsets.enc `
    docs\private-deploy\offsets\offsets-57+124+145-combined.json
```

### 5.5 每次同步留痕

```
docs/upstream-sync/2026-11-01.md
  上游范围 : 50d2b72..437b3b2
  A 层     : 采纳 N 条 profile 的 task_struct 字段，diff 见下表
  B 层     : 审查 M 条，采纳 K 条（列出 commit + 移植说明），拒绝 M-K 条（列出理由）
  C 层     : …
  风险     : …
```

拒绝理由必须写。否则下一个季度会把同一个提交再读一遍。

---

## 6. 执行计划

### 阶段一：偏移数据同步（零风险，建议先做）

1. 跑 `tools/sync/upstream_report.py`，拿到 85 个 `.conf` 里与我们三条 release **同 release 字符串**的交集。
2. 对交集跑 `conf_to_offsets.py`，逐键 diff。预期只有 `struct_fields.task_*` 一类数值变动。
3. 重新 pack `offsets.enc`，构建，真机跑一次确认。
4. 留痕到 `docs/upstream-sync/`。

预期结果：**大多数情况下没有交集**（我们的三条是 vendor 定制的 `-maybe-dirty` release，上游 85 条是 GKI 主线 hash）。所以阶段一的真实价值是"确认没有可同步项"，而不是"同步了一批数据"。这一步做完，A 层就不再是未知数。

### 阶段二：引擎补丁审查

1. `upstream_report.py` 列出 137 个 C 相关提交，按 `fix(` / `feat(` 分组。
2. 逐条判定三档：可直接移植 / 需改写 / 不适用。
3. 可移植的排优先级，一次只移植一条，每次都做真机 A/B（`HARDEN=0` 出对照引擎）。
4. 拒绝的写进 `docs/upstream-sync/rejected.md`，附理由。

**红线**：`src/` 任何改动都要 A/B。竞速时序敏感，任何重排都可能把"能成功"变成"偶发失败"。

### 阶段三：结构解耦（长期）

目标是把私有化层变成"叠加层"，让上游同步不再触碰核心文件：

1. 把 `LocalOffsets` / `offsets.enc` 的加载抽象成 `OffsetSource` 接口，引擎侧保留 `offsets.json` 导入这一条通路不变。
2. 把 `src/kernels/offsets.h` 的三条内建表改成由 JSON 生成，减少手改两处。
3. `server/gl-license/` 移出主仓（`git rm -r --cached` + 独立私有仓），主仓只留一行指向它的说明。

### 6.3 关于 `server/gl-license/`

它现在是死代码：App 不调用、构建不引用、CI 不执行。留在主仓的代价是每次同步都要在 419 个改动文件里辨认它。建议：

```powershell
# 先确认没有任何引用
Select-String -Path (Get-ChildItem -Recurse -Include *.kt,*.kts,*.yml *.sh -File) -Pattern 'gl-license'
```

确认无引用后移到独立私有仓，主仓保留 `docs/private-deploy/r15-package-notes.md` 里的历史说明。

---

## 7. 红线

1. **不 merge 上游分支**。上游 HEAD 与本工程没有共同的可合并接口，`git merge` 只会产出几千行冲突。
2. **不动私有化七项**（§2）。任何同步 PR 里出现 `LocalOffsets.kt`、`offsets.enc`、`SupportedKernels.kt`、`build.gradle.kts` 的签名段改动，直接退回。
3. **不在同一次提交里同时改 `src/` 和 `app/`**。真机 A/B 需要能单独回退引擎。
4. **不引入上游的 profile 运行时**。两套偏移来源（编译期内建 + `offsets.json` 导入）已经够复杂，加第三套会让"为什么用了这张表"无法追踪。
5. **绝对基址只信实测**。上游 `kernel_phys_load = null` 是运行时推导，我们没有那条路；任何从上游抄来的基址都必须当 0 处理。

---

## 8. 一页速查

```
上游更新了？
  ├─ kernel_profiles/*.conf 变了     → A 层，跑 conf_to_offsets.py，只取 task_struct/kernelsnitch/route
  ├─ src/core/*.cpp 变了             → D 层，只读，除非能表达成 C
  ├─ fix(native)/fix(race) 提交       → B 层，逐条人工判定 + 真机 A/B
  ├─ app/**.kt 变了                  → C 层，读 diff 手改（包名 app→pro）
  └─ AndroidManifest/权限变了        → 先看是不是又加了 INTERNET，加了就拒
```
