package com.ghostlock.pro.domain.repository

import com.ghostlock.pro.domain.model.CpuPair
import com.ghostlock.pro.domain.model.KernelSnapshot
import com.ghostlock.pro.domain.model.OffsetImportResult

interface GhostlockRepository {
    suspend fun snapshot(): KernelSnapshot

    fun setSafeModeEnabled(enabled: Boolean)

    /** 本机可用核心对，按最高频簇优先排序；用于 UI 下拉选择。 */
    fun availableCpuPairs(): List<CpuPair>

    /** 与 availableCpuPairs() 一一对应的展示标签，例如 "4,5 · 3.35 GHz"。 */
    fun availableCpuPairLabels(): List<String>

    /** 当前选中的核心对（未手动指定时为自动优选结果）。 */
    fun selectedCpuPair(): CpuPair

    /** 手动指定核心对；传 null 恢复自动优选。 */
    fun selectCpuPair(pair: CpuPair?)

    /** The CPU pair the exploit will race on. */
    fun bestCpuPair(): CpuPair


    /**
     * Install an offsets container after checking its header.
     *
     * Not user-facing: the packaged container is released automatically, so no
     * UI path calls this.  It is the seam stage 2 uses to write the per-device
     * container it receives for this handset.
     */
    suspend fun importOffsets(bytes: ByteArray): OffsetImportResult

    suspend fun runExploit(pair: CpuPair, onLog: (String) -> Unit): Int

    fun close()
}
