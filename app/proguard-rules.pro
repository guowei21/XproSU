# 无线 ADB 客户端（移植自 AdbShellTool / libadb，MIT）
# 这类 conscrypt 适配器只在旧版本 Android 上通过反射使用，R8 不需要解析它们。
-dontwarn com.android.org.conscrypt.**
-dontwarn org.apache.harmony.xnet.provider.jsse.**
-dontwarn org.conscrypt.**
-dontwarn org.bouncycastle.**
-dontwarn io.github.muntashirakon.adb.**

# 保留客户端实现，避免反射/序列化点被裁剪。
-keep class io.github.muntashirakon.adb.** { *; }

# Compose / Kotlin 元数据由 AGP 默认规则处理。
