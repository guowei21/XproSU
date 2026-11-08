# 第三方组件与许可

本仓库的 Android 壳使用下列开源组件。分发 APK 时请保留本文件与相应许可声明。

## libadb-android

- 项目：https://github.com/MuntashirAkon/libadb-android
- 用途：ADB 协议、TLS 会话、无线调试配对（`adb:` / `sync:` 服务）
- 许可：GPL-3.0-or-later OR Apache-2.0，本项目按 **Apache-2.0** 使用

## sun-security-android

- 项目：https://github.com/MuntashirAkon/sun-security-android
- 用途：提供 `android.sun.security.x509.*`，用于生成自签证书
- 许可：GPL-2.0 with Classpath Exception

## AdbShellTool

- 项目：https://github.com/pabloajoinglez/AdbShellTool
- 用途：`AdbPairingService` / `XprosuAdbKeyManager` 的移植来源（mDNS 配对流程、
  自签证书与密钥文件格式、通知内 RemoteInput 输入配对码）
- 许可：MIT，Copyright (c) 2026 Pablo Ajo

## HiddenApiBypass

- 项目：https://github.com/LSPosed/AndroidHiddenApiBypass
- 用途：解除隐藏 API 限制（`AbsAdbConnectionManager` 依赖反射访问 TLS 相关 API）
- 许可：Apache-2.0

## Conscrypt

- 项目：https://github.com/google/conscrypt
- 用途：TLSv1.3 Provider（`SslUtils` 的首选路径）
- 许可：Apache-2.0

## core/（原生提权载荷）

- 上游：https://github.com/kzktor/ic-timer-lpe（MIT, molanp）
- 许可：MIT
