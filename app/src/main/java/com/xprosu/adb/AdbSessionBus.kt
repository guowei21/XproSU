package com.xprosu.adb

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * 无线调试配对/连接状态的进程内单一来源。
 *
 * 配对服务（AdbPairingService）是前台 Service，生命周期与 Activity 解耦，
 * 所以状态不能放在 ViewModel 里；上游 AdbShellTool 用广播回传，这里换成 StateFlow，
 * Compose 侧直接 collect。
 */
object AdbSessionBus {

    /** 状态迁移统一落 logcat（标签 XproSU），连不上时能直接看出卡在哪一步。 */
    private fun log(phase: Phase, message: String?) {
        android.util.Log.i("XproSU", "link " + phase + (message?.let { " | " + it } ?: ""))
    }

    enum class Phase {
        IDLE,          // 未开始
        SCANNING,      // 正在等用户在设置里发起配对
        CODE_REQUIRED, // 已发现配对端口，等用户输入 6 位码
        PAIRING,       // 配对中
        PAIRED,        // 配对成功，等待会话端口
        CONNECTING,    // 正在连接会话端口
        CONNECTED,     // 已连接，可以开流
        NEEDS_PAIRING, // adbd 不认这把密钥：必须先配对一次
        ERROR
    }

    data class State(
        val phase: Phase = Phase.IDLE,
        val port: Int = -1,
        val message: String? = null
    )

    private val _state = MutableStateFlow(State())
    val state: StateFlow<State> = _state.asStateFlow()

    @JvmStatic
    fun scanning() {
        _state.value = State(Phase.SCANNING, -1, "等待系统广播配对端口")
        log(Phase.SCANNING, _state.value.message)
    }

    @JvmStatic
    fun codeRequired(port: Int) {
        _state.value = State(Phase.CODE_REQUIRED, port, "已发现配对端口 $port")
        log(Phase.CODE_REQUIRED, _state.value.message)
    }

    @JvmStatic
    fun pairing(port: Int) {
        _state.value = State(Phase.PAIRING, port, "正在配对")
        log(Phase.PAIRING, _state.value.message)
    }

    @JvmStatic
    fun paired() {
        _state.value = State(Phase.PAIRED, _state.value.port, "配对成功，等待会话端口")
        log(Phase.PAIRED, _state.value.message)
    }

    @JvmStatic
    fun connecting(port: Int) {
        _state.value = State(Phase.CONNECTING, port, "正在连接 $port")
        log(Phase.CONNECTING, _state.value.message)
    }

    @JvmStatic
    fun connected(port: Int) {
        _state.value = State(Phase.CONNECTED, port, "已连接，端口 $port")
        log(Phase.CONNECTED, _state.value.message)
    }

    /** adbd 回了 "ADB pairing is required"：密钥没被授信，必须走一次配对。 */
    @JvmStatic
    fun needsPairing(message: String?) {
        _state.value = State(
            Phase.NEEDS_PAIRING,
            -1,
            message ?: "adbd 还不认本机密钥，需要配对一次"
        )
        log(Phase.NEEDS_PAIRING, _state.value.message)
    }

    @JvmStatic
    fun error(message: String?) {
        _state.value = State(Phase.ERROR, _state.value.port, message ?: "未知错误")
        android.util.Log.w("XproSU", "link ERROR | " + (_state.value.message ?: ""))
    }

    @JvmStatic
    fun reset() {
        _state.value = State()
        log(Phase.IDLE, null)
    }
}
