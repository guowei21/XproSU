# ── R8 加固（只作用于 Release）──────────────────────────────────────────────
#
# 原则：只加"不会改变运行时语义"的项。Release 包至今没有在真机上跑过（设备离线），
# 所以这里刻意**不做**激进的属性剥离（-keepattributes 取反、-dontoptimize 之类的
# 组合），那类规则最容易在 Compose 的反射路径上炸在运行时，而那种崩溃只有真机
# 冒烟才能发现。等真机跑通一次 Release 之后再考虑加码。

# 把所有类重打包进一个扁平命名空间：打散包结构线索，也顺手缩短符号名。
-repackageclasses 'gl'

# 允许 R8 放宽访问修饰符，从而做更深的内联与合并（不改变可观察行为）。
-allowaccessmodification

# 堆栈里只留行号，不留源文件名。
-renamesourcefileattribute SourceFile

# 组件由系统按名字反射实例化，必须保留。
-keep public class * extends android.app.Activity
-keep public class * extends android.app.Application

# AndroidX / Compose 的注解类在编译期可见、运行期缺失，属已知无害告警。
-dontwarn org.jetbrains.annotations.**
