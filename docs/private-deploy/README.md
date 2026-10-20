# 私有化适配与部署（6.1.57 / 6.1.124 / 6.1.145）

> 来源：`ghostlock-57-124-145-project`（自用私有化分支）的**可公开部分**。
> 原始工程里与签名、成品 APK、提取二进制相关的内容**不在本目录**，见文末“未收录”。

本目录记录的是「拿到一台新机型 / 新内核之后，如何把引擎适配到它，并把它部署回设备」的完整链路：

```
设备取证 → 逐符号偏移提取 → BTF 结构对账 → 内建表烘焙 → 可复现构建 libghostlock.so
        → 重打包 APK → 同密钥重签 → 覆盖安装 → 真机核验（W1→VR→W2→W3→root→KernelSU）
```

## 目录

| 路径 | 内容 |
|---|---|
| `build.md` | 引擎构建（NDK/LLVM、可复现产物、哈希核验） |
| `packaging.md` | 重打包 + 重签 + 覆盖安装（含 INSTALL_FAILED 排错） |
| `r15-package-notes.md` | R15 线的按字节复现与产物校验 |
| `adapt-124-bootimg.md` | 从 boot.img 提取镜像、推导偏移（6.1.124 实例） |
| `compare-57-145-124.md` | 三个内核版本的偏移漂移分析（结论：不可用统一 delta） |
| `vr-ko-neutralize.md` | vivo `vr.ko` 中和（不做则 ksud/KernelSU 被杀） |
| `offsets/` | 三版本明文偏移 JSON（设备验证值）与字段说明 |
| `engine/` | R15 旧版 C 引擎参考源码：内建三版本表、`offsets_json` 合并加载、上游缺失的 `off_tp_sys_exit_*`（vr.ko）字段、mcast/tcp/pselect 路由 |
| `evidence/` | 真机全流程日志与装机核验记录 |
| `../../tools/private-deploy/` | `build.sh` / `build_r15.sh` / `lld_link.sh` / `repack_apk.py` |
| `../../scripts/private-deploy/` | 偏移提取、BTF、kallsyms、内建表生成脚本 |

## 适配矩阵

| `uname -r` | 设备 | 状态 |
|---|---|---|
| `6.1.57-android14-11-maybe-dirty` | vivo PD2324（早期固件） | 偏移逐符号 EXACT，与 6.1.124 同源交叉验证 |
| `6.1.124-android14-11-maybe-dirty` | vivo PD2324 / V2324A（MT6989） | boot.img 实测 + 真机全流程跑通 |
| `6.1.145-android14-11-maybe-dirty` | vivo V2324A（MT6989）/ V2339FA | 设备 kallsyms 提取，真机全流程跑通 |

## 关键结论（改代码前先读）

1. **跨版本没有统一 delta**：rodata/data/bss 三区漂移方向与幅度都不同（`boot_id` 甚至是负漂移），必须从目标内核自己的 kallsyms/BTF 逐符号重提。
2. **`off_slide_*` 三项只用于日志打印**，改错不影响功能，只会误导排障；设备验证值优先于事后用 kallsyms “修正”。
3. **同一开机周期内不要连跑第二次**：race 失败会留下悬空 PI 节点，继续跑容易崩；失败后重启设备再试。
4. **`mcast seq=1..15 errno=99、seq=16 成功`是正常现象**（EADDRNOTAVAIL），不是缺陷。
5. 偏移按 `uname -r` **全串**匹配；内核 OTA 后必须重新提取。
6. 覆盖安装必须使用**与设备现装版本相同的签名密钥**；该密钥不随本目录分发。

## 未收录（有意排除）

- `signing/`：签名密钥与口令说明；
- `dist/`、`evidence/*.so`、`evidence/AndroidManifest.xml`、`MANIFEST.MF`：成品 APK 与从原版 APK 提取的二进制；
- `tools/repack_apk.py` 之外的 APK 再分发产物；
- 上游文件的备份包。

原因是这些内容一旦公开，等于同时交出“可签同名更新包的密钥”和“可直接再分发的成品”。
