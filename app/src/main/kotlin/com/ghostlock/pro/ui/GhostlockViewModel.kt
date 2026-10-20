package com.ghostlock.pro.ui

import android.os.Build
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.ghostlock.pro.BuildConfig
import com.ghostlock.pro.R
import com.ghostlock.pro.domain.model.KernelSnapshot
import com.ghostlock.pro.domain.model.LogTone
import com.ghostlock.pro.domain.repository.GhostlockRepository
import com.ghostlock.pro.domain.usecase.FormatLogUseCase
import com.ghostlock.pro.domain.usecase.LoadKernelSnapshotUseCase
import com.ghostlock.pro.domain.usecase.RunExploitUseCase
import com.ghostlock.pro.license.ActivationResult
import com.ghostlock.pro.license.CardKey
import com.ghostlock.pro.license.LicenseRepository
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

sealed interface GhostlockEffect {
    data class Toast(val resourceId: Int) : GhostlockEffect

    /** 需要展示服务端原文（例如服务端返回的拒绝原因）。 */
    data class Message(val text: String) : GhostlockEffect
    data class Clipboard(val text: String) : GhostlockEffect
    data class KeepScreenAwake(val enabled: Boolean) : GhostlockEffect

    /** 授权已到期/被收回，需要退回登录窗口。 */
    data object LicenseExpired : GhostlockEffect
}

class GhostlockViewModel(
    private val repository: GhostlockRepository,
    private val license: LicenseRepository,
) : ViewModel() {
    private val effectChannel = Channel<GhostlockEffect>(Channel.BUFFERED)
    private val mutableState = MutableStateFlow(
        GhostlockUiState(
            deviceId = license.deviceId,
            licenseConfigured = license.configured,
            logsVisible = BuildConfig.DEBUG,
        ),
    )
    private var initialized = false
    private var running = false
    private var progressJob: Job? = null
    private val loadKernelSnapshot = LoadKernelSnapshotUseCase(repository)
    private val runExploitUseCase = RunExploitUseCase(repository)
    private val formatLog = FormatLogUseCase()

    /** 待上传的日志行；[logHeaderSent] 保证每个进程只带一次设备信息。 */
    private val logQueue = ArrayDeque<String>()
    private var logUploadJob: Job? = null
    private var logHeaderSent = false

    val state = mutableState.asStateFlow()
    val effects = effectChannel.receiveAsFlow()

    private var kernelSnapshot: KernelSnapshot? = null

    fun initialize() {
        if (initialized) return
        initialized = true
        val cached = license.cached()
        val pairs = repository.availableCpuPairs()
        // 默认核心对 0,1：用户未手动选择时按 (0,1) 运行；手动选择仍然覆盖默认值。
        val defaultIdx = pairs.indexOfFirst { it.primary == 0 && it.consumer == 1 }
        val idx = if (defaultIdx >= 0) defaultIdx else 0
        repository.selectCpuPair(pairs.getOrNull(idx))
        mutableState.update {
            it.copy(
                cpuPairLabels = repository.availableCpuPairLabels(),
                cpuPairIndex = idx,
                isLicensed = license.isActivated(),
                licenseExpiry = cached?.expiry.orEmpty(),
                // 永久卡：expireAt == 0（服务端 expire=0）。界面据此显示「永久授权」。
                licensePermanent = cached != null && cached.expireAt == 0L,
            )
        }
        viewModelScope.launch { refreshSnapshot() }
        viewModelScope.launch { licenseLoop() }
    }

    fun toggleSafeMode(enabled: Boolean) {
        repository.setSafeModeEnabled(enabled)
        mutableState.update { it.copy(safeModeEnabled = enabled) }
    }

    /** [index] 对应 [GhostlockUiState.cpuPairLabels] 的下标；无「自动」项。 */
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
                if (BuildConfig.DEBUG) appendLog("result: exploit chain unsupported by this kernel")
                endOperation()
            }
            return
        }
        if (!state.value.isLicensed) {
            // 未授权时直接引导到激活入口，而不是静默失败。
            openActivateDialog()
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
                if (!license.checkExpiry()) {
                    appendLog("result: license expired")
                    onLicenseRevoked()
                    return@launch
                }
                // 每次点击「立即获取 Root」都向服务端换一次解密材料：
                // 卡密被删/被封/过期 → 这里拿不到 Kd，直接中止，引擎根本不会被执行。
                val session = license.fetchSessionKey()
                if (session == null && !license.debugSessionAllowed()) {
                    appendLog("result: license check failed (network or server refused)")
                    onLicenseRevoked()
                    return@launch
                }
                val code = runExploitUseCase(repository.selectedCpuPair(), ::appendLog, session)
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

    // 识别码不再对外展示，复制动作随之移除；保留 action 空实现兼容动作层。

    /**
     * 到期检查入口：到期即收回并发出 [GhostlockEffect.LicenseExpired]。
     * 返回 false 表示已不再授权。
     */
    suspend fun checkLicenseNow(): Boolean {
        if (!license.checkExpiry()) {
            onLicenseRevoked()
            return false
        }
        return true
    }

    /** 授权被收回：同步 UI 到未激活态，并弹一次激活框。 */
    fun onLicenseRevoked() {
        mutableState.update {
            it.copy(isLicensed = false, licenseExpiry = "", licensePermanent = false)
        }
        openActivateDialog()
    }

    /** 本地凭据是否有效（不联网）。 */
    fun isActivated(): Boolean = license.isActivated()

    /**
     * 回前台时的在线核对：删卡/封卡/过期立刻生效。
     * 服务端明确拒绝或网络不可达 → 清凭据并回到未激活态。
     */
    suspend fun verifyOnResume() {
        if (license.hasCredentials() && !license.verifyOnline()) {
            license.clear()
            onLicenseRevoked()
        }
    }

    fun openActivateDialog() {
        if (state.value.activating) return
        mutableState.update {
            it.copy(
                dialogVisible = true,
                dialogType = DialogType.INPUT,
                dialogTitleRes = R.string.activate_dialog_title,
                dialogMessageRes = R.string.activate_dialog_hint,
                dialogInput = "",
            )
        }
    }

    fun onDialogInputChange(value: String) = mutableState.update { it.copy(dialogInput = value) }

    fun onDialogConfirm(value: String) {
        if (state.value.dialogType != DialogType.INPUT) return
        if (state.value.activating) return
        val key = CardKey.normalize(value)
        if (key.isEmpty()) {
            send(GhostlockEffect.Toast(R.string.license_card_empty))
            return
        }
        mutableState.update { it.copy(activating = true) }
        viewModelScope.launch {
            when (val result = license.activate(key)) {
                is ActivationResult.Ok -> {
                    mutableState.update {
                        it.copy(
                            activating = false,
                            isLicensed = true,
                            licenseExpiry = result.record.expiry,
                            licensePermanent = result.record.expireAt == 0L,
                        )
                    }
                    if (BuildConfig.DEBUG) appendLog("license activated on ${license.deviceId}")
                    send(GhostlockEffect.Toast(R.string.activate_success))
                    dismissDialog()
                }

                is ActivationResult.Rejected -> {
                    mutableState.update { it.copy(activating = false) }
                    send(GhostlockEffect.Message(result.message))
                }

                is ActivationResult.Unreachable -> {
                    mutableState.update { it.copy(activating = false) }
                    send(GhostlockEffect.Message(result.message))
                }
            }
        }
    }

    fun onDialogDismiss() = dismissDialog()

    fun onDialogDismissFinished() {
        if (!state.value.dialogVisible) {
            clearDialog()
        }
    }

    override fun onCleared() {
        progressJob?.cancel()
        repository.close()
        effectChannel.close()
        super.onCleared()
    }

    /**
     * 授权保活：定期 heartbeat + info 刷新，服务端明确拒绝或本地到期时收回授权。
     * 未配置服务或未激活时直接返回，不产生无谓请求。
     */
    private suspend fun licenseLoop() {
        if (!license.configured) return
        while (viewModelScope.isActive) {
            delay(HEARTBEAT_INTERVAL_MS)
            if (!license.isActivated()) continue
            val refreshed = license.refresh()
            if (refreshed == null) {
                // 服务端收回或离线时本地到期：clear 后立刻同步 UI 并退回登录。
                val activated = license.isActivated()
                mutableState.update {
                    it.copy(
                        isLicensed = activated,
                        licenseExpiry = if (activated) it.licenseExpiry else "",
                        licensePermanent = if (activated) it.licensePermanent else false,
                    )
                }
                if (!activated) {
                    mutableState.update { it.copy(licenseExpiry = "", licensePermanent = false) }
                    openActivateDialog()
                }
                continue
            }
            mutableState.update {
                it.copy(
                    isLicensed = license.isActivated(),
                    licenseExpiry = refreshed.expiry,
                    licensePermanent = refreshed.expireAt == 0L,
                )
            }
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

    private fun dismissDialog() {
        mutableState.update { it.copy(dialogVisible = false) }
    }

    private fun clearDialog() {
        mutableState.update {
            it.copy(
                dialogVisible = false,
                dialogType = DialogType.NONE,
                dialogTitleRes = 0,
                dialogMessageRes = 0,
                dialogInput = "",
                activating = false,
            )
        }
    }

    /**
     * 记录一行引擎输出。
     *
     * 交付版（[GhostlockUiState.logsVisible] 为 false）只推进进度，不留存明文日志。
     */
    private fun appendLog(line: String) {
        val stage = stageProgress(line)
        val uiLine = if (state.value.logsVisible) {
            val entry = formatLog(line)
            GhostlockLogLine(entry.text, toneColor(entry.tone))
        } else {
            null
        }
        mutableState.update {
            val advanced = stage > it.progress
            it.copy(
                logLines = if (uiLine != null) it.logLines + uiLine else it.logLines,
                progress = if (advanced) stage else it.progress,
                progressLabelRes = if (advanced) stageLabelRes(line) else it.progressLabelRes,
            )
        }
        enqueueLog(line)
    }

    /**
     * 把一行日志排进上传队列。
     *
     * 交付版界面不展示明文日志，但售后排障仍然需要它：批次每
     * [LOG_FLUSH_INTERVAL_MS] 发一次，队列有上限、上传失败静默丢弃——
     * 日志永远不能影响激活、心跳或提权本身。
     */
    private fun enqueueLog(line: String) {
        synchronized(logQueue) {
            if (!logHeaderSent) {
                logHeaderSent = true
                logQueue.addLast(
                    "[device] ${Build.MODEL} / Android ${Build.VERSION.RELEASE} / " +
                        "kernel ${state.value.kernelRelease} / app ${BuildConfig.VERSION_NAME}",
                )
            }
            while (logQueue.size >= LOG_QUEUE_MAX) logQueue.removeFirst()
            logQueue.addLast(line)
        }
        if (logUploadJob?.isActive != true) {
            logUploadJob = viewModelScope.launch {
                while (isActive) {
                    delay(LOG_FLUSH_INTERVAL_MS)
                    val batch = synchronized(logQueue) {
                        if (logQueue.isEmpty()) {
                            emptyList<String>()
                        } else {
                            val out = ArrayList<String>(minOf(logQueue.size, LOG_BATCH_MAX))
                            while (out.size < LOG_BATCH_MAX && logQueue.isNotEmpty()) {
                                out.add(logQueue.removeFirst())
                            }
                            out
                        }
                    }
                    if (batch.isNotEmpty()) license.uploadLogs(batch)
                }
            }
        }
    }

    private fun startProgressCreep() {
        // 交付版进度完全由引擎阶段行驱动（见 stageProgress），不做时间爬坡：
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
        /** 尚未手动选择核心对。 */
        const val NO_PAIR_INDEX = -1
        const val HEARTBEAT_INTERVAL_MS = 60 * 1000L

        /** 日志上传：8 秒一批、每批最多 60 行、进程内最多排队 600 行。 */
        const val LOG_FLUSH_INTERVAL_MS = 8 * 1000L
        const val LOG_BATCH_MAX = 60
        const val LOG_QUEUE_MAX = 600
    }
}
