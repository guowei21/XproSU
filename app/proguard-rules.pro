# AIDL 用户服务由 Shizuku 反射实例化，名字不能被 R8 改掉
-keep class com.xprosu.IcService { *; }
-keep interface com.xprosu.IIcService { *; }
-keep class com.xprosu.IIcService$Stub { *; }

# Shizuku
-keep class rikka.shizuku.** { *; }
-keep class moe.shizuku.** { *; }
