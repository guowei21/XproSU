# 加固清单（对标企业级）

> 本文记录**每一项加固控制、它挡什么、怎么验证、以及哪些没做**。
> 构建/部署步骤见 [`build-and-deploy.md`](build-and-deploy.md)，协议见
> [`stage2-protocol.md`](stage2-protocol.md)。
>
> **一条硬规矩**：引擎靠 futex 竞速取胜，任何改变指令布局的加固都可能把
> 「稳定成功」变成「偶尔成功」——**这种退化不崩溃，只是成功率下降**。所以
> 引擎侧加固上线前必须在真机上跑 A/B（见 §2.3）。

---

## 1. 加固矩阵

| # | 层 | 控制 | 挡什么 | 状态 | 验证方式 |
|---|---|---|---|---|---|
| 1 | 引擎 | 阶段① 固定密钥 `GLT_KEY` 删除 | 拆包即得整表 | ✅ | `.so` 字节扫描 0 命中 |
| 2 | 引擎 | GLT2 按设备 AEAD（AAD=64B 头） | 拷到别的设备 | ✅ | MuMu 负向用例拒绝 |
| 3 | 引擎 | 头内 `card_tag` + 引擎独立比对 | 跳过登录直接喂密钥 | ✅ | MuMu 负向用例拒绝 |
| 4 | 引擎 | 只接受 `GLT2`，无内置表回退 | 用旧容器/伪造容器 | ✅ | 喂 GLT1/空文件均拒绝 |
| 5 | 引擎 | `-fstack-protector-strong` | 栈溢出 | ✅ | 编译产物 |
| 6 | 引擎 | `-fstack-clash-protection` | 大栈分配跳过 guard page | ✅ | 编译产物 |
| 7 | 引擎 | `-D_FORTIFY_SOURCE=2` | `memcpy/strcpy` 等越界 | ✅ | 编译产物 |
| 8 | 引擎 | `-ftrivial-auto-var-init=zero` | 未初始化栈变量被利用 | ✅ | 编译产物 |
| 9 | 引擎 | `-mbranch-protection=standard`（PAuth+BTI） | 返回地址改写 / 间接跳转劫持 | ✅ | 编译产物（ARMv8.3+） |
| 10 | 引擎 | `-fvisibility=hidden` | 动态符号表暴露内部结构 | ✅ | 编译产物 |
| 11 | 引擎 | `-Wl,-z,relro -Wl,-z,now` | GOT 改写 | ✅ | 原有 |
| 12 | 引擎 | `-Wl,-z,noexecstack`、`-Wl,-z,separate-code` | 栈执行 / 段刷写 | ✅ | 编译产物 |
| 13 | 引擎 | `-ffunction-sections` + `--gc-sections` | 不可达代码留在包里 | ✅ | 编译产物 |
| 14 | 引擎 | `-Wl,--icf=safe` | 抬高逆向成本 | ✅ | 编译产物 |
| 15 | 引擎 | `-s` strip | 符号名泄漏 | ✅ | 原有 |
| 16 | App | 载荷不进 APK（`assets/` 已删） | 拆包取表 | ✅ | Release APK `assets/` 0 条目 |
| 17 | App | 登录独立窗口 + 主界面守卫 | 未授权进主界面 | ✅ | `MainActivity exported=false` |
| 18 | App | 授权字段二进制化（`GlBlob`） | `strings` 读出协议字段名 | ✅ | dex 内 `device_fp`/`pubkey` 等 0 命中 |
| 19 | App | 本地凭据 Keystore AES-GCM | 改文件伪造授权 | ✅ | 原有 |
| 20 | App | 载荷密钥 ECIES 包裹（TEE 私钥） | 抓包拿 `Kd` | ✅ | 原有 |
| 21 | App | R8 `-repackageclasses` | 包结构线索 | ✅ | dex 内 `Lgl/` 2664 类 |
| 22 | App | R8 `-allowaccessmodification` | 可读的访问结构 | ✅ | 编译产物 |
| 23 | App | `-renamesourcefileattribute` | 堆栈里的源文件名 | ✅ | 编译产物 |
| 24 | App | `allowBackup=false` | adb backup 拉走凭据 | ✅ | manifest 核对 |
| 25 | App | 明文策略按主机收敛（network security config） | 全局明文放行 | ✅ | 生成物 + manifest 无 `usesCleartextTraffic` |
| 26 | App | Release 不显示明文日志 | 运行期信息泄漏 | ✅ | 资源表中日志字符串已消失 |
| 27 | 服务端 | `master_key` 只存服务器 | 主密钥随目录外泄 | ✅ | 全树扫描仅 `config.json` 命中 |
| 28 | 服务端 | `admin_key` 拒绝空/默认值 | 默认口令开管理端 | ✅ | 用默认值启动即报错退出 |
| 29 | 服务端 | `hmac.compare_digest` 比对 | 时序侧信道 | ✅ | 代码 + 实测 |
| 30 | 服务端 | 卡密绑定原子化（`claim_card`） | 一张卡并发激活多台 | ✅ | 并发实测只剩一个赢家 |
| 31 | 服务端 | 每 IP 激活限流 + 上游并发上限 | 打爆本进程/上游 | ✅ | 代码 + 429 路径 |
| 32 | 服务端 | 超长 body 关闭连接 | 请求走私/连接错位 | ✅ | 代码 |
| 33 | 服务端 | 500 不回显内部异常 | 路径/版本泄漏 | ✅ | 代码 |
| 34 | 服务端 | 卡密只存 SHA-256 | 库被读走即得卡密 | ✅ | schema 核对 |
| 35 | 服务端 | 文档不写明文凭据 | 文档外泄即凭据外泄 | ✅ | 全树扫描 |

---

## 2. 引擎加固细节

### 2.1 开关

```bash
make ghostlock                 # HARDEN=1（默认，全套加固）
make ghostlock HARDEN=0        # 对照引擎，用于真机 A/B
make ghostlock CFLAGS_EXTRA=-DGL_VERBOSE   # 调试版（含离线校验入口）
```

没有 `make` 时见 `build-and-deploy.md` §3.2 的 clang 直编写法，
脚本里对应 `-NoHarden` 开关。

### 2.2 实测：加固不改变行为

在 MuMu（aarch64）上对**加固版**跑了一遍完整离线校验：

| 检查 | 结果 |
|---|---|
| `--crypto-selftest`（ChaCha20 / Poly1305 / AEAD 的 RFC 向量） | 三项全 `0` |
| `--offsets-verify` 正例 | `verify.load=0`，`off_init_task=0x210fb40`、`task_cred=0x838`、`task_seccomp=0x900`、`compact_waiter=1`、`mm_struct_sz=0x400` —— 与未加固版**逐值相同** |
| `--offsets-verify` 负例（换卡密绑定值） | `REJECTED: card key does not match this payload` |

产物尺寸：未加固 78,424 B → 加固 86,696 B（canary / PAC-BTI / 零初始化带来的增量）。

### 2.3 仍未验证的：真机 A/B（**上线前必做**）

上面证明的是**解析与密码学路径**行为不变。真正没被覆盖的是**提权竞速路径**：
`-mbranch-protection` 会在每个函数入口/出口插 `paciasp/autiasp`，
`-ftrivial-auto-var-init=zero` 会插栈清零，两者都会改变指令条数与时序。

```
A：libghostlock.so（加固，86,696 B）
B：libghostlock.so（HARDEN=0，78,424 B）
```

同一台设备、同一开机周期各跑 N 次（N≥20），比较成功率。
**若 A 的成功率低于 B，就回退到 B**——加固的价值不值得用成功率换。

### 2.4 引擎发布版错误码

发布版引擎失败时 stderr **只输出一行不透明错误码**，形如 `EXX`（`0x01`→`E01`，
`0x0E`→`E0E`）。码表只存在于本文档，**不进二进制**——这样可以去掉
"bound to a different device" 这类既是设计说明书、又是逆向搜索锚点的描述文本。
调试版（`GL_VERBOSE`）保留完整英文原文。

| 码 | 含义 |
|---|---|
| `0x01` | 文件打不开 / 空 / 读不出 / 超出大小上限 |
| `0x02` | 容器太短或长度非法 |
| `0x03` | 魔数不符（GLT2 / GLT1 / GLP） |
| `0x04` | 版本不支持 |
| `0x05` | 未加封（flags 缺 AEAD） |
| `0x06` | 设备不符 |
| `0x07` | 卡密不符 |
| `0x08` | AEAD 认证失败 |
| `0x09` | entry_count 非法 |
| `0x0A` | 结构截断（entry header / field list） |
| `0x0B` | 没有该 release 的条目 |
| `0x0C` | 字段缺失或为 0 |
| `0x0D` | release 不匹配 / 无法解析 |
| `0x0E` | 试用窗口已过 |

---

## 3. App 加固细节

| 项 | 做法 | 说明 |
|---|---|---|
| R8 | `optimization.enable = true` + `proguard-rules.pro` | 已开；资源收缩会把 Debug-only 路径连字符串一起删掉 |
| 重打包 | `-repackageclasses 'gl'` | 实测 dex 内 `Lgl/` 2664 类，`Lcom/ghostlock/pro/` 只剩 5 处（组件入口） |
| 明文策略 | 构建期生成 `network_security_config.xml` | `base-config` 拒绝明文，只对 `LICENSE_BASE_URL` 的主机放行 |
| 备份 | `allowBackup="false"` | 否则 `adb backup` 能拉走 Keystore 加密的凭据 blob（虽解不开，但没必要给） |
| 日志 | Release 只显示百分比 + 阶段名 | R8 会把日志字符串一起删（实测 `console_title` 不在资源表里） |

### 3.1 一个**故意不做**的加固（重要）

`android:extractNativeLibs="false"`（即 `useLegacyPackaging = false`）看起来是标准加固项：
`.so` 不落盘、按页对齐映射、无法在解压目录里被替换。**但本项目不能开**：

```
引擎是以「文件」形式被 exec 的：
  AndroidGhostlockRepository.runExploit()
    → File(applicationInfo.nativeLibraryDir, "libghostlock.so")
不抽取到磁盘 → 该路径上没有文件 → require 失败 → 提权永远跑不起来。
```

所以 `packaging.jniLibs.useLegacyPackaging` **必须保持 `true`**，
manifest 里也刻意不写 `extractNativeLibs`（写了 AGP 会直接报错，见下）。

> 这是加固与产品设计冲突的一个真实例子：照抄"企业级清单"会把产品改坏。
> 想两全就得改引擎的调用方式（例如把 `.so` 当库 `dlopen` 而不是当程序 `exec`），
> 那属于引擎接口变更，必须走真机 A/B。

---

## 4. 服务端加固细节

| 项 | 做法 |
|---|---|
| 管理端鉴权 | 启动时拒绝空/默认 `admin_key`；`hmac.compare_digest` 比对；无 key 时恒不通过 |
| 一机一码 | `claim_card` 把"是否已绑别的设备"折进 `UPDATE ... WHERE`，靠 `rowcount` 判定；同一设备重激活仍幂等 |
| 限流 | 每 IP 60 秒 30 次激活；上游调用并发上限 8；限流表有上限并会回收 |
| 请求体 | 上限 64 KiB；超限回 413 **并关闭连接**（不排空 body 会让残留字节被当成下一个请求行） |
| 异常 | 对外固定文案，详情只进服务日志 |
| 上游异常 | 200 但缺 `code` 视为上游不可用（1004），不再误报成"卡密无效" |
| 凭据 | `config.json` / `payload.bin` / `cards.db` 写进 `.gitignore`；文档内不写明文凭据 |
| 运行身份 | 见 `build-and-deploy.md` §2.4 的 systemd 示例（`User=` 非 root） |

---

## 5. 明确没做的（不夸大）

| 项 | 为什么没做 |
|---|---|
| OLLVM / 控制流平坦化（计划 §6 阶段④） | 需要自建带混淆 pass 的 clang；且它**肯定**改变时序，必须真机 A/B 后才能上 |
| 引擎字符串加密（剩余 `GLT2`/`GLP1`/错误文案） | 收益低（这些是解析必需的魔数与诊断文本），成本高（要加运行时解密器，又改时序） |
| 定期联网强制下线（计划 §6 阶段⑤） | 现在是「激活时联网一次，之后离线可用」；`expire` 已在 AAD 内不可篡改，但引擎不强制 |
| Release 运行期冒烟 | 设备离线。R8 的重打包规则已刻意保守，但**Release 包至今没在真机上跑过一次** |
| 正式 release keystore | 待定，且换签名可能改 DRM ID |

**残余风险（诚实声明）**：买家自己 root + dump 内存仍能拿到明文表。
这是本地软件的根本上限；本清单挡的是「复制粘贴级别的盗版」「转卖 APK」「顺手拆包」，
不是专业逆向组织。

---

## 6. 复现全部验证

```powershell
# 引擎：加固 + 对照 + 调试
make ghostlock                       # 或 build-and-deploy.md §3.2 的 clang 写法
make ghostlock HARDEN=0

# App：双变体
.\gradlew.bat assembleDebug assembleRelease -x :buildGhostlockNative --no-daemon

# 服务端：四组自检
cd server\gl-license
python selftest.py      # 密码学 + 线路，10 项
python uverif_probe.py  # 实连上游握手
python smoke_test.py    # Kd → GLT2 → 解密回原文
python wire_smoke.py    # 二进制/JSON 双格式

# 引擎离线校验（需 aarch64 环境，例如 MuMu）
adb push ghostlock-verbose /data/local/tmp/glv && adb shell chmod 755 /data/local/tmp/glv
adb shell "/data/local/tmp/glv --crypto-selftest"
adb shell "GHOSTLOCK_RELEASE=<release> /data/local/tmp/glv --offsets-verify \
  /data/local/tmp/<blob> <kd_hex> <device_fp_hex> <card_tag_hex>"
```
