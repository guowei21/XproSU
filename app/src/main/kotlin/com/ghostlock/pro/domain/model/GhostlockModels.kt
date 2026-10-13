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

/**
 * Outcome of installing an offsets package.
 *
 * There is no "requires overwrite" or "already present" case any more: a
 * package replaces the previous one outright, and the app cannot tell which
 * releases it carries -- the container stores a hash of the release string,
 * not the string.  Nothing here ever exposes a field name or an offset value,
 * because the app never parses the package.
 */
sealed interface OffsetImportResult {
    data object Imported : OffsetImportResult
    data class Failed(val reason: String) : OffsetImportResult
}
