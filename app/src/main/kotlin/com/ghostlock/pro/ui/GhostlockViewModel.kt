package com.ghostlock.pro.ui

import android.os.Build
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.ghostlock.pro.BuildConfig
import com.ghostlock.pro.R
import com.ghostlock.pro.data.DeviceLogStore
import com.ghostlock.pro.domain.model.KernelSnapshot
import com.ghostlock.pro.domain.model.LogTone
import com.ghostlock.pro.domain.repository.GhostlockRepository
import com.ghostlock.pro.domain.usecase.FormatLogUseCase
import com.ghostlock.pro.domain.usecase.LoadKernelSnapshotUseCase
import com.ghostlock.pro.domain.usecase.RunExploitUseCase
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

sealed interface GhostlockEffect {
    data class Toast(val resourceId: Int) : GhostlockEffect
    data class Message(val text: String) : GhostlockEffect
    data class Clipboard(val text: String) : GhostlockEffect
    data class KeepScreenAwake(val enabled: Boolean) : GhostlockEffect
}

/**
 * 公开版 ViewModel：没有授权、没有心跳、没有服务端。
 *
 * 运行路径只有三步——取本机内核快照、把随包的偏移表解到私有目录、执行引擎。
 * 日志面板常显，运行记录只落在本机。
 */
class GhostlockViewModel(
    private val repository: GhostlockRepository,
    private val deviceLog: DeviceLogStore,
) : ViewModel() {
    private val effectChannel = Channel<GhostlockEffect>(Channel.BUFFERED)
    private val mutableState = MutableStateFlow(
        GhostlockUiState(logsVisible = true),
    )
    private var initialized = false
    private var running = false
    private var progressJob: Job? = null
    private val loadKernelSnapshot = LoadKernelSnapshotUseCase(repository)
    private val runExploitUseCase = RunExploitUseCase(repository)
    private val formatLog = FormatLogUseCase()

    /** 每个进程只写一次设备头，后面的行都跟在它下面。 */
    private var logHeaderSent = false

    val state = mutableState.asStateFlow()
    val effects = effectChannel.receiveAsFlow()

    private var kernelSnapshot: KernelSnapshot? = null

    fun initialize() {
        if (initialized) return
        initialized = true
        val pairs = repository.availableCpuPairs()
        // 默认核心对 0,1：用户未手动选择时按 (0,1) 运行；手动选择仍然覆盖默认值。
        val defaultIdx = pairs.indexOfFirst { it.primary == 0 && it.consumer == 1 }
        val idx = if (defaultIdx >= 0) defaultIdx else 0
        repository.selectCpuPair(pairs.getOrNull(idx))
        mutableState.update {
            it.copy(
                cpuPairLabels = repository.availableCpuPairLabels(),
                cpuPairIndex = idx,
                tcpRouteEnabled = repository.tcpRouteEnabled(),
            )
        }
        viewModelScope.launch { refreshSnapshot() }

        // 启动即写一条本机标记：装上就能确认落盘链路可用，不必先跑一次提权。
        val bootLine = "[boot] ${Build.MODEL} / Android ${Build.VERSION.RELEASE} / " +
            "app ${BuildConfig.VERSION_NAME}(${BuildConfig.VERSION_CODE})"
        deviceLog.append(bootLine)
    }

    fun toggleSafeMode(enabled: Boolean) {
        repository.setSafeModeEnabled(enabled)
        mutableState.update { it.copy(safeModeEnabled = enabled) }
    }

    /** W1 路由开关：true = socket(tcp)，false = mcast。 */
    fun toggleTcpRoute(enabled: Boolean) {
        repository.setTcpRouteEnabled(enabled)
        mutableState.update { it.copy(tcpRouteEnabled = enabled) }
    }

    /** [index] 对应 [GhostlockUiState.cpuPairLabels] 的下标。 */
    fun onCpuPairSelected(index: Int) {
        val pairs = repository.availableCpuPairs()
        val pair = pairs.getOrNull(index) ?: return
        repository.selectCpuPair(pair)
        mutableState.update { it.copy(cpuPairIndex = index) }
    }

    fun onRun() {
        val snapshot = kernelSnapshot ?: return
        if (!snapshot.kernelSupported) {
            if (beginOperation()) {
                appendLog("result: exploit chain unsupported by this kernel")
                endOperation()
            }
            return
        }
        if (!beginOperation()) return
        mutableState.update { it.copy(lastRunFailed = false, progress = 0, progressLabelRes = 0) }
        send(GhostlockEffect.KeepScreenAwake(true))
        appendLog("==== start ====")
        appendLog("cpu pair: ${repository.selectedCpuPair()}")
        startProgressCreep()
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val code = runExploitUseCase(repository.selectedCpuPair(), ::appendLog)
                appendLog(if (code == 0) "result: exploit completed" else "result: exploit failed (exit code=$code)")
                appendLog("exit code=$code")
                mutableState.update {
                    it.copy(
                        lastRunFailed = code != 0,
                        progress = if (code == 0) 100 else it.progress,
                    )
                }
                if (code != 0) {
                    // 竞速窗口没跑到完成（典型：卡在 W1/锁核后的内核写入）：
                    // 这类失败用户无法自救，明确提示降级。
                    send(GhostlockEffect.Toast(R.string.run_unsupported_version))
                }
            } finally {
                endOperation()
                send(GhostlockEffect.KeepScreenAwake(false))
            }
        }
    }

    fun onCloseExecutionSheet() {
        if (running && !state.value.executionSheetDismissible) return
        mutableState.update { it.copy(executionSheetVisible = false) }
    }

    fun copyLogs() {
        val text = state.value.logLines.joinToString(separator = "") { it.text }
        send(GhostlockEffect.Clipboard(text))
        send(GhostlockEffect.Toast(R.string.copied))
    }

    fun clearLogs() = mutableState.update { it.copy(logLines = emptyList()) }

    /**
     * 导出本机日志。
     *
     * 典型的排障场景是运行卡死、机器被强制重启，App 里的滚动日志随之消失；
     * 这些行已经逐行落盘（[DeviceLogStore]），重启后仍然可以复制出来。
     */
    fun exportDiagnosticLogs() {
        viewModelScope.launch {
            val lines = withContext(Dispatchers.IO) { deviceLog.readTail(LOG_EXPORT_MAX_LINES) }
            if (lines.isEmpty()) {
                send(GhostlockEffect.Toast(R.string.diagnostics_log_empty))
                return@launch
            }
            send(GhostlockEffect.Clipboard(lines.joinToString(separator = "\n")))
            send(GhostlockEffect.Toast(R.string.diagnostics_log_copied))
        }
    }

    private suspend fun refreshSnapshot() {
        val snapshot = withContext(Dispatchers.IO) { loadKernelSnapshot() }
        kernelSnapshot = snapshot
        mutableState.update {
            it.copy(
                deviceName = snapshot.deviceName,
                kernelRelease = snapshot.kernelRelease,
                socName = snapshot.socName,
                kernelSupported = snapshot.kernelSupported,
                safeModeEnabled = snapshot.safeModeEnabled,
            )
        }
    }

    /** 记录一行引擎输出：进滚动日志，同时落盘。 */
    private fun appendLog(line: String) {
        val stage = stageProgress(line)
        val entry = formatLog(line)
        val uiLine = GhostlockLogLine(entry.text, toneColor(entry.tone))
        mutableState.update {
            val advanced = stage > it.progress
            it.copy(
                logLines = it.logLines + uiLine,
                progress = if (advanced) stage else it.progress,
                progressLabelRes = if (advanced) stageLabelRes(line) else it.progressLabelRes,
            )
        }
        if (!logHeaderSent) {
            logHeaderSent = true
            deviceLog.append(
                "[device] ${Build.MODEL} / Android ${Build.VERSION.RELEASE} / " +
                    "kernel ${state.value.kernelRelease} / app ${BuildConfig.VERSION_NAME}",
            )
        }
        deviceLog.append(line)
    }

    private fun startProgressCreep() {
        // 进度完全由引擎阶段行驱动（见 stageProgress），不做时间爬坡：
        // 没有阶段输出时进度停在上一阶段，避免「一口气冲到 95%」的假进度。
        progressJob?.cancel()
    }

    /** 把引擎日志映射成阶段百分比；未知行返回 -1（不改变进度）。
     *  百分比与 Release 引擎的实际输出行一一对应（common.h：阶段行不裁剪）。 */
    private fun stageProgress(line: String): Int {
        val l = line.lowercase()
        return when {
            l.contains("kernelsu ready") -> 100
            l.contains("enforcing restored") -> 90
            l.contains("waiting for selinux restore") -> 88
            l.contains("waiting for kernelsu module") -> 80
            l.contains("vr.ko") && (l.contains("tags cleared") || l.contains("funcs zeroed")) -> 72
            l.contains("seccomp") && (l.contains("bypassed") || l.contains("skipping")) -> 58
            l.contains("child is root") -> 42
            l.contains("selinux") && l.contains("permissive") -> 28
            l.contains("cpu pair") -> 14
            l.contains("==== start ====") -> 6
            else -> -1
        }
    }

    /** 与 [stageProgress] 对应的阶段名资源；0 表示沿用上一阶段。 */
    private fun stageLabelRes(line: String): Int {
        val l = line.lowercase()
        return when {
            l.contains("kernelsu ready") -> R.string.stage_done
            l.contains("enforcing restored") -> R.string.stage_race_won
            l.contains("waiting for selinux restore") -> R.string.stage_prepare
            l.contains("waiting for kernelsu module") -> R.string.stage_neutralize
            l.contains("vr.ko") && (l.contains("tags cleared") || l.contains("funcs zeroed")) -> R.string.stage_neutralize
            l.contains("seccomp") && (l.contains("bypassed") || l.contains("skipping")) -> R.string.stage_write_cred
            l.contains("child is root") -> R.string.stage_race_won
            l.contains("selinux") && l.contains("permissive") -> R.string.stage_prepare
            l.contains("cpu pair") -> R.string.stage_lock_cores
            else -> 0
        }
    }

    private fun beginOperation(): Boolean {
        if (running) return false
        running = true
        mutableState.update {
            it.copy(
                running = true,
                executionSheetVisible = it.logsVisible,
                executionSheetDismissible = false,
            )
        }
        return true
    }

    private fun endOperation() {
        running = false
        progressJob?.cancel()
        mutableState.update { it.copy(running = false, executionSheetDismissible = true) }
    }

    override fun onCleared() {
        progressJob?.cancel()
        repository.close()
        effectChannel.close()
        super.onCleared()
    }

    private fun send(effect: GhostlockEffect) {
        effectChannel.trySend(effect)
    }

    private fun toneColor(tone: LogTone): Int = when (tone) {
        LogTone.Error -> 0xFFFF6B6B.toInt()
        LogTone.Success -> 0xFF5FD68A.toInt()
        LogTone.Warning -> 0xFFFFC94D.toInt()
        LogTone.Progress -> 0xFF60A5FA.toInt()
        LogTone.Default -> 0xFFD1D5DB.toInt()
    }

    private companion object {
        /** 导出：本地最多取 800 行。 */
        const val LOG_EXPORT_MAX_LINES = 800
    }
}
