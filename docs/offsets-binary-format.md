# 偏移表二进制容器（.glt）— 阶段① 堵漏

> 本文档描述 `src/core/offsets_bin.c` + `tools/pack_offsets.py` 这一对实现，
> 以及它**能**和**不能**挡住什么。所有数字都是实测值。

---

## 1. 它解决什么

改造前，交付的 APK 里偏移表是**明文**，且有两个副本：

| 泄漏点 | 位置 | 实测 |
|---|---|---|
| 1 偏移数值 | `libghostlock.so` 的 `.rodata` | 33/33 符号值以明文 u64 存在 |
| 2 偏移键名 | `.so` 字符串表 | 33/33 键名明文（`off_init_task`、`task_cred`…） |
| 3 键名第二份 | `classes*.dex` 的 `KernelOffsets` 等模型类 | 30/36 明文 |
| 7 明文 JSON | app 私有目录 | 全部字段 |

后果：**任何人拿到 APK，`strings` 一遍就能复原整张表，连破解都不用。**

容器把键名换成数字 ID、把数值 XOR 掉 ChaCha20 密钥流，并把 release 构建里的
地址日志编译掉。`strings` / `grep` / `xxd` 再也读不出表。

### 1.1 它**不是**什么（重要）

**这不是加密，挡不住「大量外传」。**

密钥 `GLT_KEY` 是 `offsets_bin.c` 里的编译期常量，反汇编就能拿到；而且 `.glt`
如果随 APK 分发，解开 APK 就能原样复制到别的设备上照样能用。

| 威胁 | 阶段① 之后 |
|---|---|
| 拿到 APK → `strings` → 复原整张表 | ✅ **挡住**（这是本阶段唯一的真实收益） |
| 拿到日志 → 复原整张表 | ✅ 挡住（日志分级） |
| 解开 APK 拿到 `.glt` → 拷到别的机器 | ❌ 仍可用 |
| 反汇编 `.so` → 读出密钥 → 解表 | ❌ 挡不住 |

**真正的一机一码要等阶段②**：把 `GLT_KEY` 换成服务器按设备派生的
`Kd = HKDF-SHA256(master, salt=card_id, info=device_fp)`，并把 header 放进
`AAD`、追加 Poly1305 tag。届时「拷走 `.glt`」会**解密失败**，而不是「应用层判断失败」。

容器的结构就是按这个目标设计的（见 §6），阶段② 只换载荷层，不改格式骨架。

---

## 2. 文件布局

全部小端序。

```
header  16 字节
  0  magic[4]        "GLT1"
  4  version         u8   = 1
  5  flags           u8   bit0 = 载荷已混淆（必须为 1）
  6  entry_count     u16
  8  salt            u64  每份文件一个，参与密钥流 nonce

entry    8 字节（每个条目）
  0  release_hash    u32  FNV-1a-32(release)
  4  field_count     u16
  6  reserved        u16  = 0

field   10 字节（每个字段）
  0  id              u16
  2  value           u64  = 明文 ^ 密钥流
```

**release 字符串不落盘** —— 只存 FNV-1a-32 哈希（种子 `0x811C9DC5`，乘子
`0x01000193`）。引擎用 `uname -r` 算同一个哈希去匹配。

条目按 `release` 排序，所以同样的输入永远产出同样的文件（salt 固定时逐字节可复现）。

---

## 3. 字段 ID

只搬运**引擎真正读的 30 个字段**。JSON 文档里另有约 18 个
`struct_fields`（`cred_*`、`seccomp_*`、`waiter_*`、`struct_*`）没有任何代码解引用，
不搬运——容器更小，泄漏面也更小。

| ID | 字段 | 宽度 |
|---|---|---|
| `0x11` | `kernel_phys_load` | u64 |
| `0x12` | `pselect_waiter_shift` | i32 |
| `0x21`–`0x29` | `off_init_task` / `off_init_cred` / `off_root_task_group` / `off_selinux_enforcing` / `off_selinux_blob_sizes` / `off_security_hook_heads` / `off_slide_nfulnl_logger` / `off_slide_loggers_0_1` / `off_slide_boot_id` | u64 |
| `0x31`–`0x32` | `off_tp_sys_exit_tp` / `off_tp_sys_exit_funcs` | u64 |
| `0x41`–`0x4F` | 15 个 `task_*`（`task_prio` … `task_seccomp`） | u32 |
| `0x51` | `compact_waiter` | u8 |
| `0x52` | `mm_struct_sz` | u32 |

ID 刻意**不按结构体顺序编号**，文件布局本身不透露字段语义。

未知 ID 被忽略（不是报错）：新打包器可以加字段，旧引擎仍能读它认识的部分。

---

## 4. 密钥流

```
nonce   = LE32(entry_index) || LE64(salt)     共 12 字节
keystream = ChaCha20(key = GLT_KEY, counter 从 0)
每个字段取 8 字节：value_plain = value_obf ^ LE64(ks[8i..8i+8])
```

ChaCha20 是 RFC 8439 标准实现（`src/core/chacha20.c`，20 轮、32 位计数器、
96 位 nonce），**带 RFC 8439 §2.3.2 官方测试向量自检**，自检不过就直接拒绝加载。
阶段② 复用同一个原语，只是换密钥来源并加 Poly1305。

---

## 5. 读取流程与闸门

```
load_offsets_bin(path, release, out, release_buf, cap)
  1 读文件（上限 1 MiB）
  2 校验 magic / version / flags 位
  3 按 FNV-1a-32 匹配 release
  4 逐字段解密 → 写入 struct kernel_offsets
     （未出现的字段保持调用方预置值，与 JSON 路径语义一致）
  5 out->uname_r = release_buf
  6 gl_validate_offsets_entry(out, release)   ← 与 JSON 路径同一套闸门
```

第 6 步是关键：**S1 六条闸门函数被导出成 `gl_validate_offsets_entry()`，
两条导入路径共用同一份实现，没有复制**。闸门校验的是解析后的结构体，不是原始
字节，所以容器格式不需要自己的一份校验逻辑。

失败一律返回 `-1` 并打印具体原因（`offsets container REJECTED: ...`），
调用方原有的「回退内建表 / 干净退出」逻辑不变。

---

## 6. 阶段② 怎么接

改两处，格式骨架不动：

1. `GLT_KEY` 换成从 Keystore/服务器拿到的 `Kd`（`HKDF-SHA256(master, salt=card_id, info=device_fp)`）
2. header 加 `device_fp(32) | expire(8)`，`AAD = header`，尾部追加 `tag(16)` Poly1305

之后：改设备 → AAD 不匹配 → **解密失败**；改到期时间 → 同样失败。
`flags` 位已经留好，可以直接加 `GLT_FLAG_AEAD` 区分两代文件。

---

## 7. 实测证据

宿主：MuMu 实例 0（Android 15.0，x86_64）—— 只用来跑**纯解析代码的单元测试**，
不跑 exploit（模拟器跑不了 arm64 内核漏洞）。构建：NDK r27d
`x86_64-linux-android35-clang`。

### 7.1 ChaCha20 自检

```
./glt_equiv_test --selftest
chacha20 RFC 8439 self-test: PASS
```

### 7.2 与 JSON 路径逐字节等价（决定性）

`tools/glt_equiv_test.c` 对同一个 release 分别调用两条路径，比较
`struct kernel_offsets`（192 字节，`uname_r` 指针置空后 `memcmp`）：

| 输入文档 | 条目 | 结果 |
|---|---|---|
| `offsets-57+124+145-combined.json` | 3 | **identical ×3** |
| `offsets-6.1.124-v2.json` | 1 | **identical ×1** |
| `offsets-6.1.145-maybe-dirty-R15.json` | 1 | **identical ×1** |
| `offsets-import-r15-6.1.57+6.1.145.json` | 2 | **identical ×2** |
| 不存在的 release | — | 两条路径都拒绝 |

**7/7 条目逐字节相同，0 不一致。**

### 7.3 篡改与结构损坏

| 篡改 | 结果 |
|---|---|
| 截断到 20 字节 | `REJECTED: truncated entry header` ✅ |
| 清掉 `flags` 的混淆位 | `REJECTED: payload not obfuscated` ✅ |
| 破坏 magic | `REJECTED: bad magic` ✅ |
| 翻转值区一个有效字节 | 解出的结构体与 JSON 不一致（测试报 MISMATCH）|

> **注意第 4 行**：值被篡改时**没有完整性校验**，只能靠 S1 的非零/关系闸门偶然拦到。
> 这是阶段① 的已知缺口，正是阶段② 的 Poly1305 要补的。

### 7.4 日志分级（泄漏点 4/5）

`util.c` / `main.c` / `fops.c` 里打印地址的调用全部改走 `gl_addr_*()`，
release 构建下展开为空，`-DGL_VERBOSE` 恢复。

```
make ghostlock                        → 94,672 B  release
make ghostlock CFLAGS_EXTRA=-DGL_VERBOSE → 99,352 B  verbose
```

`llvm-strings` 逐串比对，16 条地址泄漏串：

```
AUDIT %-22s json=          release=0  verbose=1
--- offsets audit          release=0  verbose=2
p0 profile pid=            release=0  verbose=1
p0 kernel_phys_load=       release=0  verbose=1
page %016zx stores ...     release=0  verbose=1
=== %s === target=0x       release=0  verbose=1
vr.ko neutralize: __tracepoint   release=0  verbose=1
vr.ko neutralize (legacy   release=0  verbose=1
init_cred image=           release=0  verbose=1
child_task=0x              release=0  verbose=1
mcast route enter observe= release=0  verbose=1
tcp route enter observe=   release=0  verbose=1
pselect route setup ...    release=0  verbose=1
obs seq=...addr=           release=0  verbose=1
route missing page=        release=0  verbose=2
perf task: 0x              release=0  verbose=1
```

功能串两版都在（`mcast route won seq=`、`REJECTED`、`startup context pid=`、
`vr.ko sys_exit tracepoint funcs zeroed`、`vr.ko tracepoint neutralize route failed` …）。

**决定性旁证**：`-DGL_VERBOSE` 构建出来的 `.so`
SHA-256 = `D02B240B64B70C02C497F5E9DE8EBFF73CECDA65E2AD58A30D5D0DC289D66DBD`，
与**加日志闸门之前**编出来的二进制**完全一致** —— 证明这一轮只改了日志输出，
没碰任何逻辑。

---

## 8. 用法

```bash
# 打包（PC 侧）
python tools/pack_offsets.py offsets.glt --salt 474c543100000001 \
    offsets/offsets-57+124+145-combined.json

# 调试构建
make ghostlock CFLAGS_EXTRA=-DGL_VERBOSE

# 离线等价性测试（任意 Android 用户态）
$CC -O1 -DGL_VERBOSE -Isrc/core -Isrc/kernels tools/glt_equiv_test.c \
    src/core/chacha20.c src/core/offsets_json.c src/core/offsets_bin.c -o glt_equiv_test
./glt_equiv_test --selftest
./glt_equiv_test <offsets.json> <offsets.glt> <release>...
```

`salt` 省略时随机；读取端从 header 取，所以任意值都能用，**固定它就能逐字节复现构建**。

---

## 9. 本轮**没有**做的（下一阶段）

1. **`main.c` 还没调用 `load_offsets_bin()`** —— 容器已就位、已验证，但尚未接进
   出货路径。接线要动 `try_external_offsets()`，属「已验证路径」，**必须真机 A/B**。
2. **内建明文表还在** `src/kernels/*/offsets.h`（泄漏点 1 的另一半）。
   删掉它要同步改 `buildSrc/GenerateSupportedKernelsTask.kt` 与
   `AndroidGhostlockRepository.kt`（app 目前没有 `assets/`，偏移靠内建表生成）。
3. **dex 侧键名**（泄漏点 3）：`KernelOffsets` 等模型类仍是明文键名。
4. **完整性校验**：见 §7.3 第 4 行，要等阶段② 的 Poly1305。

> **时序红线**：日志闸门减少了 race 步骤之间的 I/O 量，而本引擎是时序敏感的。
> release 构建**必须真机 A/B** 确认成功率没有下降，才能出货。
> `-DGL_VERBOSE` 可完整复现已验证版本的日志行为。
