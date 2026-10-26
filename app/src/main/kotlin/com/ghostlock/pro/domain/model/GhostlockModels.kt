package com.ghostlock.pro.domain.model

data class CpuPair(val primary: Int, val consumer: Int) {
    override fun toString(): String = "$primary,$consumer"
}

data class KernelSnapshot(
    val deviceName: String,
    val kernelRelease: String,
    val socName: String = "",
    val kernelSupported: Boolean,
    /** The CPU pair the app races on, chosen automatically, e.g. "4,5 · 3.35 GHz". */
    val cpuPairLabel: String = "",
    val safeModeEnabled: Boolean,
)

enum class LogTone { Default, Error, Success, Warning, Progress }

data class LogEntry(val text: String, val tone: LogTone)
