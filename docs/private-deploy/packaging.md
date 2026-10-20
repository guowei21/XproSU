# 打包 / 签名 / 部署指南

> 适用场景：替换 APK 里的 `lib/arm64-v8a/libghostlock.so`（引擎）、重新签名、在设备上覆盖安装、
> 以及（使用旧产物时）部署 `offsets.json`。主文档见根 `README.md` §5。

## 1. 原理

引擎（`libghostlock.so`）是 json 驱动、静态链接的原生库；APK 只是容器。**更新引擎不需要动 Java/Kotlin 层**，
流程固定为三步：重打包（换 so）→ 重签（同一密钥）→ 覆盖安装（保留数据）。

## 2. 准备模板 APK

- 从设备拉取当前安装版（推荐，可保留 Java 层一切改动）：
  `adb shell pm path com.ghostlock.app` → `adb pull <base.apk>`；
- 或使用仓库留档：`reference/gl-installed-original.apk`（设备原装版，**注意它是旧签名 DC:68:…**，
  只适合做模板重签，不能直接覆盖安装更新）与 `evidence/libghostlock.so`（其内引擎）。

## 3. 重打包（repack_apk.py）

```sh
python3 tools/repack_apk.py <模板base.apk> out-unsigned.apk <新的libghostlock.so>
```

脚本做三件事（每条都是 INSTALL_FAILED 换来的教训）：

1. **保留每个 entry 的压缩方式**：原 APK 里 STORED 的保持 STORED，DEFLATED 的重新压缩——不能一律重压；
2. **STORED 条目对齐**：`.so → 16384`、`resources.arsc → 4096`、其余 `4`（脚本输出 `mod16384=0` 等行可自查）；
3. **丢弃 `META-INF/`**：旧签名不清掉，新签名写不进去。

## 4. 签名（两条路径，任选）

> **必须用与设备现装版本相同的密钥**（`<your-keystore.jks>`，SHA-256 `<cert-sha256>`），
> 否则无法覆盖安装（见 §5 排错）。

**路径 A：apksigner（本机已实测可用）**

```sh
apksigner sign --ks <your-keystore.jks> --ks-key-alias <key-alias> \
    --ks-pass pass:<storepass> --key-pass pass:<keypass> \
    --out out-signed.apk out-unsigned.apk
```

**路径 B：uber-apk-signer（历史流程，命令留档；jar 未随本包分发）**

```sh
java -jar uber-apk-signer-1.3.0.jar \
     --apks out-unsigned.apk \
     --ks <your-keystore.jks> --ksAlias <key-alias> \
     --ksPass <storepass> --ksKeyPass <keypass> \
     --skipZipAlign --out ./
```

> `--skipZipAlign` 是必须的：repack 已做 16384/4096 对齐，再跑对齐反而会破坏。

**签名后自检**：

```sh
apksigner verify --print-certs out-signed.apk   # 应显示 SHA-256: <cert-sha256>（与 keystore 一致）
zipalign -c -P 16 -v 4 out-signed.apk           # 最后一行应为 Verification successful
```

## 5. 安装与覆盖升级

```sh
adb install -r out-signed.apk
# 或（有 Shizuku 时）
android-shizuku-cli exec pm install -r out-signed.apk
```

- 同签名 + versionCode 不低于现装版本 → **覆盖安装、保留应用数据**。
- 旧密钥（SHA-1 `DC:68:24:A1:…`，2026-10-01 的调试密钥，私钥已丢失）与现密钥互不兼容：
  用旧签名的包只能「卸载 → 安装」，会丢数据（历史数据备份在案）。

## 6. offsets.json 部署（旧产物必做；本树新产物可省）

**优先级**：`files/offsets.json`（外部）> `/data/local/tmp/offsets.json` > 内建表（`uname -r` 全串匹配）。

- **使用本树构建的 so（3 条内建）**：不需要部署任何 json；如需强制指定（例如临时切回旧表），外部文件依然生效。
- **使用交付 APK / 旧引擎（内建表不含 `-maybe-dirty` 型号）**：必须部署：

```sh
# 写进 app 私有目录（文件属主必须是 u0_a…，600 权限；root 属主 run-as 读不了）
adb shell 'run-as com.ghostlock.app sh -c "cat > files/offsets.json"' < offsets/offsets-6.1.124-v2.json

# 无 adb、有 Shizuku：
android-shizuku-cli exec sh -c 'cat <workspace>/....json > ...' # 或直接用 pm / run-as
```

- 部署后校验（md5）：`6.1.124 v2 = 86d068100cdb1a54f1ec5943f6cd35df`；
  `6.1.145 R15 表 = d939ddfa91c32b2bb70339453f14bfbb`。
- 简表（只包含 6.1.124）直接可用 v2；三版本可用 `offsets/offsets-57+124+145-combined.json`（引擎按 release 取对应条目）。

## 7. 验收清单（每次打包跑一遍）

1. `python3 tools/repack_apk.py …` 输出 `mod16384=0` / `mod4096=0`；
2. `apksigner verify --print-certs` → 证书 `<cert-sha256>`；
3. `zipalign -c -P 16 -v 4` → `Verification successful`；
4. `unzip -p out-signed.apk lib/arm64-v8a/libghostlock.so | sha256sum` → 与预期 so 指纹一致；
5. 安装后启动引擎，确认日志走完全流程（W1→VR→W2→W3→root→KernelSU ready），
   `ps -A | grep -i ksud` 应存活（vr.ko 中和成功的直接证据）。

## 8. 排错表

| 现象 | 原因 | 处理 |
|---|---|---|
| `INSTALL_FAILED_UPDATE_INCOMPATIBLE` | 签名与现装版本不同 / versionCode 更低 | 用同一把密钥；或卸载重装（丢数据） |
| `INSTALL_PARSE_FAILED_NO_CERTIFICATES` | 没签名或被破坏 | 重跑签名步骤并 verify |
| `INSTALL_FAILED_NO_MATCHING_ABIS` | APK 内没有 arm64 so | 检查模板 APK 与 repack 输出目录 `lib/arm64-v8a/` |
| 应用能装、引擎"没反应" | so 未替换成功 / offsets 缺失 / 内核未适配 | 校验 apk 内 so 指纹；看引擎日志（offsets 缺失会显式报错） |
| 提权后 ksud 被杀 | vr.ko 未中和 | 见 `docs/vr-ko-neutralize.md` |

## 9. 交付 APK 事实卡（dist/gl-r15-signed.apk）

| 项 | 值 |
|---|---|
| sha256 | `55350d0642874bc6d111c16946cd10dfdadca788a3e9b8b639c00acc6679fa88` |
| md5 | `ee3e8d3af69719117b848c3512532da3` |
| 大小 | 19,797,449 B |
| 签名 | v3 方案，证书 SHA-256 `<cert-sha256>`（= 本包 keystore） |
| 对齐 | zipalign 16K 通过 |
| 内含引擎 | `fb98636f…`（见根 README §3 指纹表） |
| 部署要求 | 需部署 `offsets/offsets-6.1.124-v2.json`（其内建表不含 maybe-dirty 型号） |
