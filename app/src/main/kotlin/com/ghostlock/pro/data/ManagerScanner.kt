package com.ghostlock.pro.data

import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import java.io.File
import java.util.zip.ZipEntry
import java.util.zip.ZipFile

/**
 * 找出能提供 `ksud` 的管理器应用。
 *
 * 思路来自上游 ghostlock-app 的 ManagerScanner 与 dirtyfrag/DFRoot 的“管理器无关”做法：
 * 不信任包名白名单——任何非系统应用，只要自带 `libksud.so`，都可以在选择器里被手动选中；
 * 内置列表只决定“自动”模式的优先级顺序。
 *
 * `libksud.so` 有两种落地形态，两种都要认：
 * - `extractNativeLibs=true`（多数管理器）：解压到 `ApplicationInfo.nativeLibraryDir`；
 * - `extractNativeLibs=false`（例如部分分支的随机包名构建）：只在 APK 内的
 *   `lib/<abi>/libksud.so`，native 目录是空的，必须从 APK 里读。
 */
object ManagerScanner {
    /** 用户手动选中的管理器包名；null/空白 = 自动。 */
    const val PREF_KEY = "manager_package"

    private const val KSUD_LIB = "libksud.so"
    private const val LIB_PREFIX = "lib/"

    /** 内置候选，按自动模式的优先级排列。 */
    val BUILTIN = listOf(
        "me.weishu.kernelsu.pr",
        "me.weishu.kernelsu",
        "com.rifsxd.ksunext",
        "com.sukisu.ultra",
        "com.sukisu.ultra.pr",
        "com.resukisu.resukisu",
        "org.bakasu.bakasu",
        "me.yuki.fina.pr",
        "me.yuki.fina",
        "com.kowx712.supermanager",
    )

    data class Candidate(
        val packageName: String,
        val label: String,
        val hasKsud: Boolean,
        val builtin: Boolean,
    )

    /**
     * 列出全部第三方应用（依赖 `QUERY_ALL_PACKAGES`），带 libksud.so 的排前面。
     *
     * 系统应用在提权前不可读其 native 目录，也没有当管理器的先例，直接跳过。
     */
    fun scan(pm: PackageManager, selfPackage: String): List<Candidate> =
        pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(0))
            .asSequence()
            .filter { pi -> pi.packageName != selfPackage }
            .mapNotNull { pi ->
                val ai: ApplicationInfo = pi.applicationInfo ?: return@mapNotNull null
                if ((ai.flags and ApplicationInfo.FLAG_SYSTEM) != 0) return@mapNotNull null
                Candidate(
                    packageName = pi.packageName,
                    label = runCatching { ai.loadLabel(pm).toString() }
                        .getOrDefault(pi.packageName),
                    hasKsud = hasKsud(ai),
                    builtin = pi.packageName in BUILTIN,
                )
            }
            .sortedWith(compatibleFirst())
            .toList()

    /** 内置且带 libksud.so 的最前，其次带 libksud.so 的，同组按应用名。 */
    fun compatibleFirst(): Comparator<Candidate> =
        compareByDescending<Candidate> { it.builtin && it.hasKsud }
            .thenByDescending { it.hasKsud }
            .thenBy { it.label.lowercase() }

    /**
     * 解析 ksud 提供者的顺序：手动选择优先，其余内置按优先级兜底。
     *
     * 选择项失效（被卸载或缺少 libksud.so）时自动回退到内置列表，不会中断提权。
     */
    fun resolvePackages(chosen: String?): List<String> =
        if (chosen.isNullOrBlank()) BUILTIN
        else listOf(chosen) + BUILTIN.filter { it != chosen }

    /** 该应用是否自带 libksud.so：先看已解压的 native 目录，再看 APK 内。 */
    fun hasKsud(appInfo: ApplicationInfo): Boolean {
        if (nativeKsud(appInfo) != null) return true
        val sourceDir = appInfo.sourceDir ?: return false
        return runCatching { ZipFile(sourceDir).use { ksudEntry(it) != null } }
            .getOrDefault(false)
    }

    /**
     * 读出该应用的 libksud.so；native 目录优先，其次 APK 内的 `lib/<abi>/`。
     * 读不到返回 null。
     */
    fun readKsud(appInfo: ApplicationInfo): ByteArray? {
        nativeKsud(appInfo)?.let { file ->
            return runCatching { file.readBytes() }.getOrNull()
        }
        val sourceDir = appInfo.sourceDir ?: return null
        return runCatching {
            ZipFile(sourceDir).use { zip ->
                val entry = ksudEntry(zip) ?: return@use null
                zip.getInputStream(entry).use { it.readBytes() }
            }
        }.getOrNull()
    }

    private fun nativeKsud(appInfo: ApplicationInfo): File? {
        val dir = appInfo.nativeLibraryDir ?: return null
        val file = File(dir, KSUD_LIB)
        return file.takeIf { it.isFile }
    }

    /** APK 内的 libksud.so 条目；优先当前 ABI，其次任意 ABI。 */
    private fun ksudEntry(zip: ZipFile): ZipEntry? {
        val abi = android.os.Build.SUPPORTED_ABIS.firstOrNull() ?: "arm64-v8a"
        return zip.getEntry("lib/$abi/$KSUD_LIB")
            ?: zip.entries().asSequence()
                .firstOrNull { it.name.startsWith(LIB_PREFIX) && it.name.endsWith("/$KSUD_LIB") }
    }

    /**
     * `libksud.so` 在管理器自身目录里的真实路径（`extractNativeLibs=true`）。
     *
     * 引擎必须优先执行这个路径，而不是 App 复制出来的副本：SukiSU/KernelSU 的
     * ksud 靠自身路径（`/data/app/~~x/<pkg>-y/lib/arm64/libksud.so`）判断它归属
     * 哪个管理器，副本在私有目录里没有这层信息，late-load 之后管理器不认。
     *
     * `extractNativeLibs=false` 的管理器 native 目录是空的，返回 null，调用方
     * 退回 APK 内提取的副本。
     */
    fun nativeKsudPath(appInfo: ApplicationInfo): String? =
        nativeKsud(appInfo)?.absolutePath
}
