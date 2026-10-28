package com.ghostlock.pro.data

import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import java.io.File

/**
 * 找出能提供 `ksud` 的管理器应用。
 *
 * 思路来自上游 ghostlock-app 的 ManagerScanner 与 dirtyfrag/DFRoot 的“管理器无关”做法：
 * 不信任包名白名单——任何非系统应用，只要 `nativeLibraryDir/libksud.so` 存在，都可以在
 * 选择器里被手动选中；内置列表只决定“自动”模式的优先级顺序。
 */
object ManagerScanner {
    /** 用户手动选中的管理器包名；null/空白 = 自动。 */
    const val PREF_KEY = "manager_package"

    /** 内置候选，按自动模式的优先级排列。 */
    val BUILTIN = listOf(
        "me.weishu.kernelsu.pr",
        "me.weishu.kernelsu",
        "com.resukisu.resukisu",
        "org.bakasu.bakasu",
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
                val dir = ai.nativeLibraryDir
                Candidate(
                    packageName = pi.packageName,
                    label = runCatching { ai.loadLabel(pm).toString() }
                        .getOrDefault(pi.packageName),
                    hasKsud = dir != null && File(dir, "libksud.so").isFile,
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
}
