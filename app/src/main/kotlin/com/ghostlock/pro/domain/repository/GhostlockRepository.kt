package com.ghostlock.pro.domain.repository

import com.ghostlock.pro.data.ManagerScanner
import com.ghostlock.pro.domain.model.CpuPair
import com.ghostlock.pro.domain.model.KernelSnapshot

interface GhostlockRepository {
    suspend fun snapshot(): KernelSnapshot

    fun setSafeModeEnabled(enabled: Boolean)

    /** 手动选择的管理器包名（提供 ksud）；null = 自动。 */
    fun selectedManagerPackage(): String?

    /** 手动指定管理器；传 null 恢复自动（内置优先级）。 */
    fun setSelectedManagerPackage(pkg: String?)

    /** 已安装的第三方应用，带 libksud.so 的排前面；用于选择器展示。 */
    suspend fun installedManagers(): List<ManagerScanner.Candidate>

    /**
     * 提权后该打开哪个管理器。
     *
     * 必须是**真正接管了 root 的那个**：手动选中项被卸载或缺 libksud.so 时
     * [prepareKsud] 会回退到别的候选，此时跳回"用户选的那个"只会打开一个
     * 没被授权的应用，看起来就是"跳错了管理器"。
     */
    fun managerToOpen(): String?

    /** 本机可用核心对，按最高频簇优先排序；用于 UI 下拉选择。 */
    fun availableCpuPairs(): List<CpuPair>

    /** 与 availableCpuPairs() 一一对应的展示标签，例如 "4,5 · 3.35 GHz"。 */
    fun availableCpuPairLabels(): List<String>

    /** 当前选中的核心对（未手动指定时为自动优选结果）。 */
    fun selectedCpuPair(): CpuPair

    /** 手动指定核心对；传 null 恢复自动优选。 */
    fun selectCpuPair(pair: CpuPair?)

    /** W1 路由：true = socket(tcp) 路由，false = mcast 路由。 */
    fun tcpRouteEnabled(): Boolean

    fun setTcpRouteEnabled(enabled: Boolean)

    /** The CPU pair the exploit will race on. */
    fun bestCpuPair(): CpuPair


    /**
     * 执行提权。
     *
     * 偏移表由 AndroidGhostlockRepository 在运行前从 APK 资源解开，写成引擎认识的
     * `offsets.json`；这里不传任何密钥，也没有会话材料。
     */
    suspend fun runExploit(
        pair: CpuPair,
        onLog: (String) -> Unit,
    ): Int

    fun close()
}
