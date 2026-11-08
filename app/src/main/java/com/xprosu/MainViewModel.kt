package com.xprosu

import android.app.Application
import android.net.Uri
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.xprosu.adb.AdbBridge
import com.xprosu.adb.AdbPairingService
import com.xprosu.adb.AdbSessionBus
import com.xprosu.adb.AdbTransport
import com.xprosu.core.STAGES
import com.xprosu.core.StagePhase
import com.xprosu.core.StageStatus
import com.xprosu.core.StageTracker
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import java.io.File
import java.io.InputStream

data class AppState(
    val link: AdbSessionBus.State = AdbSessionBus.State(),
    val connected: Boolean = false,
    val pairing: Boolean = false,
    val identity: String = "",
    val device: String = "",
    val running: Boolean = false,
    val stages: List<StageStatus> = STAGES.map { StageStatus(it.title, StagePhase.PENDING) },
    val log: String = "",
    val ksuIndex: Int = 0,
    val detectedManager: String = "",
    val safeMode: Boolean = false,
    val toast: String? = null,
)

val KSU_NAMES = listOf(
    "自动检测", "KernelSU", "KernelSU-Next", "SukiSU Ultra",
    "BakaSU", "ReSukiSU (旧包名)", "SakiSU", "FinaSU",
    "7kimisu", "7kimisu (备用包名)", "vivoKSU",
)

// 与 ksu_handoff.sh 的 KNOWN 列表保持一致；脚本优先，应用只做检测和传参。
val KSU_PACKAGES = listOf(
    "", "me.weishu.kernelsu", "com.rifsxd.ksunext", "com.sukisu.ultra",
    "org.bakasu.bakasu", "com.resukisu.resukisu",
    "com.sakisu.sakisu", "me.yuki.fina", "com.sevenk.core",
    "com.sevenkimimasy.love", "me.inkdye.vivoksu",
)

private const val TMP = "/data/local/tmp/"
private const val ATTEMPTS = 16
private const val RUN_TIMEOUT_MS = 20 * 60 * 1000L
private const val DEFAULT_CMD = "id; cat /proc/self/attr/current; getenforce; echo LPE-PROOF"
private const val LOG_LIMIT = 400_000
/** 运行期间界面刷新的最小间隔：刷新太勤会和载荷抢页面分配器。 */
private const val UI_FLUSH_MS = 900L
private const val PREFS = "adb_prefs"
private const val PREF_PORT = "connection_port"

class MainViewModel(app: Application) : AndroidViewModel(app) {

    private val _state = MutableStateFlow(AppState())
    val state: StateFlow<AppState> = _state.asStateFlow()

    @Volatile private var activeManager: String? = null
    @Volatile private var logPath: String? = null
    @Volatile private var exitAtMs = 0L
    private var tailJob: Job? = null

    private val logLock = Any()
    private val logBuilder = StringBuilder()
    private val lineBuffer = StringBuilder()
    private val tracker = StageTracker()
    private var exitSeen: Int? = null
    /**
     * 终态挂起：core 的 park_forever 打出 "reboot before rerun"，进程停在 pause() 不退出。
     * 注意 plant burst miss、reap 非 SIGKILL 时也会打 "holding zombie"，但那只是过程日志，
     * 载荷随后会继续重试（core/timer98260.c:1985、:2039 对 :1033）。
     */
    private var zombieHeld = false
    /** 载荷打出 "failure condition"：有 plant 没被回收。本轮可能仍提到 root，但建议重启。 */
    private var plantMissed = false

/** 日志流提前收尾的内部信号（不是错误）。 */
private class RunStreamDone : Exception()

    /** 节流中的界面刷新任务；关键事件会 cancel 它并立刻刷新。 */
    private var flushJob: Job? = null
    /** 已经看到 [core] exit，等下一次刷新时把 running 置回 false。 */
    @Volatile private var pendingExit: Int? = null

    init {
        viewModelScope.launch(Dispatchers.Main.immediate) {
            AdbSessionBus.state.collect { link ->
                _state.update {
                    it.copy(
                        link = link,
                        pairing = link.phase != AdbSessionBus.Phase.IDLE &&
                            link.phase != AdbSessionBus.Phase.CONNECTED &&
                            link.phase != AdbSessionBus.Phase.ERROR,
                    )
                }
                if (link.phase == AdbSessionBus.Phase.CONNECTED) {
                    withContext(Dispatchers.IO) { loadIdentity() }
                }
            }
        }
    }

    // ---------------------------------------------------------------- 连接

    /** 点"连接"：先试已保存的会话端口，失败再去发现当前无线调试端口（不要求重新配对）。 */
    fun connect() {
        android.util.Log.i(
            "XproSU",
            "connect() phase=" + _state.value.link.phase + " connected=" + isConnected()
        )
        if (_state.value.link.phase == AdbSessionBus.Phase.NEEDS_PAIRING) {
            // 配对发现已经在跑了，再连一次只会再被拒
            toast("去设置 › 无线调试 › 使用配对码配对设备，再从通知栏输入 6 位码")
            return
        }
        if (isConnected()) {
            viewModelScope.launch(Dispatchers.IO) { loadIdentity() }
            return
        }
        val saved = getApplication<Application>()
            .getSharedPreferences(PREFS, Application.MODE_PRIVATE)
            .getInt(PREF_PORT, -1)
        android.util.Log.i("XproSU", "connect() savedPort=" + saved)
        if (saved > 0) {
            viewModelScope.launch(Dispatchers.IO) {
                val ok = runCatching { AdbBridge.get(getApplication()).connect(saved) }
                    .onFailure { android.util.Log.w("XproSU", "connect(saved) 异常", it) }
                    .getOrDefault(false)
                android.util.Log.i("XproSU", "connect(saved=" + saved + ") -> " + ok)
                if (ok) {
                    AdbSessionBus.connected(saved)
                    loadIdentity()
                } else {
                    discoverAndConnect()
                }
            }
        } else {
            discoverAndConnect()
        }
    }

    /**
     * 只发现不配对：重启后无线调试端口会变，但 adbd 仍记着我们的公钥，
     * 所以直接按 mDNS 广播的会话端口连就行，用户不用再要一次配对码。
     */
    fun discoverAndConnect() {
        android.util.Log.i("XproSU", "discoverAndConnect() 走 mDNS 发现会话端口")
        AdbSessionBus.scanning()
        val intent = android.content.Intent(
            getApplication(), AdbPairingService::class.java
        ).setAction(AdbPairingService.ACTION_CONNECT)
        runCatching {
            getApplication<Application>().startForegroundService(intent)
        }.onFailure {
            AdbSessionBus.error("无法启动连接服务：" + it.message)
        }
    }

    /** 拉起前台配对服务，等系统广播配对端口。 */
    fun startPairing() {
        android.util.Log.i("XproSU", "startPairing() 走 mDNS 发现配对端口")
        AdbSessionBus.scanning()
        val intent = android.content.Intent(
            getApplication(), AdbPairingService::class.java
        ).setAction(AdbPairingService.ACTION_START)
        runCatching {
            getApplication<Application>().startForegroundService(intent)
        }.onFailure {
            AdbSessionBus.error("无法启动配对服务：" + it.message)
        }
    }

    /** 应用内对话框提交 6 位配对码。 */
    fun submitPairingCode(code: String) {
        val port = _state.value.link.port
        if (port <= 0) {
            toast("还没发现配对端口，先让系统广播一次")
            return
        }
        if (code.length != 6 || code.any { !it.isDigit() }) {
            toast("配对码是 6 位数字")
            return
        }
        val intent = android.content.Intent(
            getApplication(), AdbPairingService::class.java
        ).setAction(AdbPairingService.ACTION_REPLY)
            .putExtra(AdbPairingService.REMOTE_INPUT_KEY, port)
            .putExtra(AdbPairingService.EXTRA_PAIRING_CODE, code)
        runCatching {
            getApplication<Application>().startForegroundService(intent)
        }.onFailure {
            AdbSessionBus.error("提交配对码失败：" + it.message)
        }
    }

    fun cancelPairing() {
        val intent = android.content.Intent(
            getApplication(), AdbPairingService::class.java
        ).setAction(AdbPairingService.ACTION_STOP)
        runCatching { getApplication<Application>().startService(intent) }
        AdbSessionBus.reset()
    }

    /** 打开系统的无线调试页面，配对端口只在那里出现。 */
    fun openWirelessDebugging() {
        val app = getApplication<Application>()
        val intents = listOf(
            android.content.Intent("android.settings.APPLICATION_DEVELOPMENT_SETTINGS"),
            android.content.Intent(android.provider.Settings.ACTION_SETTINGS),
        )
        for (intent in intents) {
            intent.addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK)
            if (runCatching { app.startActivity(intent) }.isSuccess) return
        }
        toast("请手动打开 设置 › 开发者选项 › 无线调试")
    }

    fun isConnected(): Boolean = runCatching {
        AdbBridge.get(getApplication()).isConnected()
    }.getOrDefault(false)

    private suspend fun loadIdentity() {
        try {
            val out = AdbTransport.exec("id; cat /proc/self/attr/current")
            android.util.Log.i("XproSU", "identity rc=" + out.code + " out=" + out.output.trim())
            if (out.code < 0) throw IllegalStateException("身份命令未返回哨兵：" + out.output.trim())
            val dev = AdbTransport.exec(
                "getprop ro.product.model; getprop ro.build.display.id; uname -r"
            ).output
            _state.update { it.copy(identity = out.output.trim(), device = dev.trim()) }
            appendLog("[adb] " + out.output.trim())
            if (dev.isNotBlank()) appendLog("[设备]\n" + dev.trim())
        } catch (t: Throwable) {
            android.util.Log.w("XproSU", "读取身份失败", t)
            _state.update {
                it.copy(connected = false, toast = "读取身份失败：" + (t.message ?: t.toString()))
            }
            return
        }
        _state.update { it.copy(connected = true) }
    }

    // ---------------------------------------------------------------- 运行

    fun run() {
        android.util.Log.i("XproSU", "run() enter running=" + _state.value.running + " connected=" + isConnected())
        if (_state.value.running) return
        if (!isConnected()) return toast("ADB 未连接：先完成无线调试配对")
        val st = _state.value
        val selectedPkg = KSU_PACKAGES[st.ksuIndex]
        val safe = st.safeMode

        // 每次运行用新副本：截断仍在执行的 ELF 会让停驻的 attempt SIGBUS。
        val stamp = (System.currentTimeMillis() / 1000).toString()
        val bin = TMP + "ic-timer-a" + stamp
        val script = TMP + "ic-lpe-a" + stamp + ".sh"
        val logFile = TMP + "ic-app-a" + stamp + ".log"
        // 与上游一致：handoff 恒存在，空包名由脚本自己识别管理器。
        val handoff: String = TMP + "ksu-h" + stamp + ".sh"

        synchronized(logLock) {
            tracker.reset()
            exitSeen = null
            zombieHeld = false
            plantMissed = false
            pendingExit = null
            exitAtMs = 0L
        }
        activeManager = null
        _state.update {
            it.copy(
                running = true,
                detectedManager = "",
                stages = STAGES.map { spec -> StageStatus(spec.title, StagePhase.PENDING) },
            )
        }

        viewModelScope.launch(Dispatchers.IO) {
            try {
                val id0 = AdbTransport.exec("id; cat /proc/self/attr/current").output
                if (!id0.contains("uid=2000") || !id0.contains("u:r:shell")) {
                    appendLog(
                        "[run] 拒绝执行：ADB shell 身份不是 shell\n" + id0 +
                            "\n无线调试的连接必须来自本机 adbd（不要用 root 重启 adbd）。"
                    )
                    finish(failed = true)
                    return@launch
                }

                // 自动检测：pm list packages 里按已知优先级取第一个装了的。
                val managerPkg = if (selectedPkg.isEmpty()) detectManager() else selectedPkg
                activeManager = managerPkg
                if (managerPkg.isNotEmpty()) {
                    _state.update { it.copy(detectedManager = managerPkg) }
                    appendLog("[app] 管理器: " + managerName(managerPkg) + " (" + managerPkg + ")")
                } else {
                    appendLog("[app] 未检测到已安装的 KSU 管理器，只做提权")
                }

                val payload = "sh " + handoff + " '" + managerPkg + "' '' '" +
                    (if (safe) "1" else "0") + "' ; " + DEFAULT_CMD

                pushAsset("run_core.sh", script)
                pushAsset("ic-timer", bin)
                pushAsset("ksu_handoff.sh", handoff)

                val env = LinkedHashMap<String, String>()
                env["PATH"] = "/sbin:/system/bin:/system/xbin"
                env["IC_BIN"] = bin
                env["ATTEMPTS"] = ATTEMPTS.toString()
                env["IC_APP_LOG"] = logFile
                env["PAYLOAD_CMD"] = payload
                env["IC_SYMS_FILE"] = "/data/local/tmp/ic-syms.txt"
                if (safe) env["IC_SAFE_MODE"] = "1"
                env["IC_KSU"] = "1"
                // 空检测结果传 "-"：让 core 跳过写死的 am start 并不再报错，
                // 管理器由应用侧退出后再找。
                env["IC_KSU_PKG"] = managerPkg.ifEmpty { "-" }

                // 载荷 stdout/stderr 直接落盘（不经 tee：tee 会在进程被杀时把缓冲区
                // 里的最后 ~2 KB 一起丢掉），同一个 shell 流里再 tail -f 这份文件。
                // 流不关，adbd 就不会收掉这个进程组——这本身就是保活机制。
                // 载荷内部用 setsid 脱离进程组，所以即便流断了它也继续跑。
                AdbTransport.execOrThrow(": > " + quote(logFile))
                logPath = logFile

                val envPart = env.entries.joinToString(" ") { it.key + "=" + quote(it.value) }
                val runCmd = "cd " + quote(TMP) + " && ( env " + envPart +
                    " setsid /system/bin/sh " + quote(script) +
                    " >> " + quote(logFile) + " 2>&1 < /dev/null & ) ; " +
                    "exec tail -n +1 -f " + quote(logFile)

                val label = if (selectedPkg.isEmpty()) {
                    "自动检测 → " + managerName(managerPkg)
                } else {
                    KSU_NAMES[st.ksuIndex]
                }
                appendLog(
                    "[run] 启动 方案: run_core.sh  KSU: " + label +
                        "\n[run] 载荷输出直写日志，同一条流里 tail -f 实时回显" +
                        "\n[run] bin=" + bin + "\n[run] log=" + logFile
                )
                attachRunStream(runCmd)
                // 流结束（tail 读完）后按退出码收尾。这里不依赖 running 标志，只看
                // [core] exit / 终态挂起 / 流提前断掉三种情况。
                val seen = exitSeen
                when {
                    seen != null -> {
                        appendLog("[adb] 运行流已结束（[core] exit=" + seen + "）")
                        finish(failed = seen != 0)
                    }
                    zombieHeld -> {
                        appendLog("[adb] 运行流已结束（载荷已挂起，需重启后再试）")
                        if (_state.value.running) finish(failed = true)
                    }
                    else -> {
                        appendLog("[adb] 运行流已结束（没等到 [core] exit）")
                        if (_state.value.running) finish(failed = true)
                    }
                }
                // 失败轮次也要清临时文件：挂起的载荷还持有自己的 inode，unlink 不会
                // 让它 SIGBUS，只是把目录项抹掉。成功路径由 handleCoreExit 收尾时清理。
                if (seen != 0) runCatching { autoCleanup() }
            } catch (t: Throwable) {
                android.util.Log.w("XproSU", "run() 失败", t)
                appendLog("[run] 失败: " + t)
                finish(failed = true)
                runCatching { autoCleanup() }
            }
        }
    }

    /**
     * 把一条长命令跑在自己的 shell 流里，边跑边把输出喂给界面。
     *
     * 流一直开到脚本退出为止：这就是保活机制本身，不需要 setsid/nohup。
     */
    private suspend fun attachRunStream(cmd: String) {
        tailJob?.cancel()
        val ready = CompletableDeferred<Unit>()
        tailJob = viewModelScope.launch(Dispatchers.IO) {
            try {
                withTimeoutOrNull(RUN_TIMEOUT_MS) {
                    AdbTransport.stream(cmd).collect { chunk ->
                        if (chunk.isEmpty()) {
                            ready.complete(Unit)
                        } else {
                            appendLog(String(chunk, Charsets.UTF_8))
                            // tail -f 不会自己结束：看到收尾标记就主动断流。
                            if (exitSeen != null) throw RunStreamDone()
                            if (zombieHeld) {
                                delay(1200) // 让「holding zombie」那句和栈尾写完
                                throw RunStreamDone()
                            }
                        }
                    }
                }
                if (zombieHeld && _state.value.running) {
                    appendLog(
                        "[adb] 载荷已挂起（holding zombie）：内核里留着没回收的 timer 节点，" +
                            "必须重启设备后再试一轮。"
                    )
                    finish(failed = true)
                }
            } catch (done: RunStreamDone) {
                if (zombieHeld && _state.value.running) {
                    appendLog(
                        "[adb] 载荷已挂起（holding zombie）：内核里留着没回收的 timer 节点，" +
                            "必须重启设备后再试一轮。"
                    )
                    finish(failed = true)
                }
            } catch (t: Throwable) {
                if (!ready.isCompleted) ready.completeExceptionally(t)
                if (_state.value.running) {
                    appendLog("[adb] 日志流中断: " + t.message)
                }
            }
        }
        val ok = withTimeoutOrNull(15_000) { ready.await() }
        if (ok == null) throw IllegalStateException("日志流打开超时")
        // 关键：ready 只代表 shell 流已建立，不代表载荷跑完。必须等收集协程真正结束
        // （脚本退出 → tail 读完日志 → EOF），否则 run() 会立刻按 exitSeen==null 判失败，
        // 而流仍在后台收日志，造成"秒失败、稍后却成功"。
        val ended = withTimeoutOrNull(RUN_TIMEOUT_MS) { tailJob?.join() }
        if (ended == null) {
            appendLog("[adb] 等待运行流结束超时（" + RUN_TIMEOUT_MS / 60000 + " 分钟）")
        }
    }

    /**
     * 先按已知包名匹配；没有命中就按关键字扫描，并用 resolve-activity
     * 确认它真的有 launcher（有些 fork 会换包名或带随机别名）。
     */
    private suspend fun detectManager(): String {
        val out = runCatching { AdbTransport.exec("pm list packages").output }.getOrDefault("")
        val known = KSU_PACKAGES
            .filter { it.isNotEmpty() }
            .firstOrNull { out.contains("package:" + it) }
        if (known != null) return known

        val keys = listOf("kernelsu", "sukisu", "resukisu", "bakasu", "sakisu", "vivoksu", "ksu")
        val candidates = out.lineSequence()
            .map { it.removePrefix("package:").trim() }
            .filter { p -> p.isNotEmpty() && keys.any { p.contains(it, ignoreCase = true) } }
            .take(6)
            .toList()
        return candidates.firstOrNull { p ->
            runCatching {
                AdbTransport.exec("cmd package resolve-activity --brief " + p + " 2>/dev/null | tail -1").output
            }.getOrDefault("").contains("/")
        }.orEmpty()
    }

    private fun managerName(pkg: String): String {
        val i = KSU_PACKAGES.indexOf(pkg)
        return if (i >= 0) KSU_NAMES[i] else pkg
    }

    /**
     * core 最后一步把 am start 的包名写死成 me.weishu.kernelsu，SukiSU 等管理器
     * 必然失败并让 core 以 1 退出。模块已 resident 时由应用侧收尾：
     * 已在前台就什么都不做，否则用 resolve-activity 冷启动一次。
     * 不 force-stop —— 用户可能正用着管理器，杀掉再拉会丢状态。
     */
    private suspend fun handleCoreExit(code: Int, manager: String) {
        // 给脚本自己的收尾留时间，避免两边同时拉起
        delay(2500)
        val live = runCatching {
            AdbTransport.exec("grep -q '^kernelsu ' /proc/modules && echo LIVE || echo NOLIVE").output
        }.getOrDefault("")
        if (!live.contains("LIVE")) {
            appendLog("[app] KSU 模块不在 /proc/modules，跳过管理器启动")
            autoCleanup()
            return
        }

        // 运行时没检测到就再扫一次：用户可能刚装好管理器，或者包名不在清单里
        val target = manager.ifEmpty { detectManager() }
        if (target.isEmpty()) {
            appendLog("[app] 未识别到 KSU 管理器，请手动打开管理器完成激活")
            autoCleanup()
            markHandoffDone("提权完成；未识别到管理器，请手动打开")
            return
        }

        val top = runCatching {
            AdbTransport.exec("dumpsys activity activities 2>/dev/null | grep -m1 topResumedActivity").output
        }.getOrDefault("")
        if (top.contains(target)) {
            appendLog("[app] 管理器已在前台，跳过启动")
        } else {
            // 不 force-stop：管理器可能正被用户使用，杀掉再拉会丢状态。
            val comp = runCatching {
                AdbTransport.exec("cmd package resolve-activity --brief " + target + " 2>/dev/null | tail -1").output
            }.getOrDefault("").trim()
            val out = if (comp.contains("/")) {
                runCatching {
                    AdbTransport.exec("am start -W -n " + comp + " 2>&1 | grep -E 'Status|LaunchState|Error' | tr '\\n' ' '").output
                }.getOrDefault("")
            } else {
                runCatching {
                    AdbTransport.exec("monkey -p " + target + " -c android.intent.category.LAUNCHER 1 2>&1 | tail -2 | tr '\\n' ' '").output
                }.getOrDefault("")
            }
            appendLog("[app] 启动管理器 " + target + " (" + comp + "): " + out.trim())
        }

        autoCleanup()
        markHandoffDone("提权完成：KSU 模块已加载，管理器已拉起")
    }

    private fun markHandoffDone(msg: String) {
        synchronized(logLock) { tracker.feed("ROOT_SHELL_OK") }
        _state.update {
            it.copy(
                running = false,
                stages = synchronized(logLock) { tracker.snapshot() },
                toast = msg,
            )
        }
    }

    fun diag() {
        if (!isConnected()) return toast("ADB 未连接：先完成无线调试配对")
        if (_state.value.running) return toast("运行期间不做诊断，避免额外分配内核对象")
        viewModelScope.launch(Dispatchers.IO) {
            val out = try {
                AdbTransport.exec(
                    "id; cat /proc/self/attr/current; getenforce; echo ---; uname -r; " +
                        "getprop ro.product.device; getprop ro.product.model; echo ---; " +
                        "ls -l /data/local/tmp/ | head -20; echo ---; " +
                        "head -n 2 /data/local/tmp/ic-syms.txt 2>/dev/null; " +
                        "ls -d /data/adb/ksu 2>/dev/null; echo ---; " +
                        "pm list packages 2>/dev/null | grep -Ei 'kernelsu|sukisu|resukisu|bakasu|sakisu|sevenk|ksunext|fina'",
                    timeoutMs = 30_000,
                ).output
            } catch (t: Throwable) {
                "诊断失败: " + t
            }
            appendLog("[诊断]\n" + out)
        }
    }

    fun parseOffsets(uri: Uri) {
        if (!isConnected()) return toast("ADB 未连接：先完成无线调试配对")
        if (_state.value.running) return toast("运行期间不解析偏移")
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val stamp = (System.currentTimeMillis() / 1000).toString()
                val bin = TMP + "ic-syms-a" + stamp
                val img = TMP + "ic-boot-a" + stamp + ".img"
                val syms = "/data/local/tmp/ic-syms.txt"
                pushAsset("ic-timer", bin)

                // 先把镜像落到缓存目录拿到长度，SEND 头里必须写准确的文件大小
                val cache = File(getApplication<Application>().cacheDir, "boot-$stamp.img")
                var size = 0L
                getApplication<Application>().contentResolver.openInputStream(uri)?.use { input ->
                    cache.outputStream().use { out -> size = input.copyTo(out) }
                } ?: throw IllegalStateException("openInputStream 返回 null")
                try {
                    cache.inputStream().use { input ->
                        AdbTransport.pushStream(input, size, img, 0x1a4)
                    }
                } finally {
                    cache.delete()
                }

                val out = AdbTransport.exec(
                    "ls -l " + img + " 2>&1; " + bin + " syms " + img + " " + syms +
                        " 2>&1; echo parse_rc=" + "\$?" + "; sed -n '1,3p' " + syms +
                        " 2>/dev/null; rm -f " + img,
                    timeoutMs = 120_000,
                ).output
                appendLog("[解析偏移] 已选择: " + (uri.lastPathSegment ?: "") + " (" + size + " bytes)\n" + out)
            } catch (t: Throwable) {
                appendLog("[解析偏移] 失败: " + t)
            }
        }
    }

    private suspend fun cleanupTemp(): Int {
        val stamp = (System.currentTimeMillis() / 1000).toString()
        val script = TMP + "ic-clean-a" + stamp + ".sh"
        pushAsset("cleanup_tmp.sh", script)
        val out = AdbTransport.exec("sh " + script + " 2>&1", timeoutMs = 60_000).output
        val procs = Regex("procs=(\\d+)").find(out)?.groupValues?.get(1)?.toIntOrNull() ?: 0
        if (procs > 0) {
            appendLog("[app] 仍有 " + procs + " 个载荷进程驻留（挂起态，故意不回收），只能重启清除")
        }
        return Regex("cleaned=(\\d+)").find(out)?.groupValues?.get(1)?.toIntOrNull() ?: 0
    }

    /** 运行结束后自动清理；等日志流收尾再删，避免日志读一半。 */
    private suspend fun autoCleanup() {
        runCatching { tailJob?.cancel() }
        runCatching { cleanupTemp() }.onSuccess { n ->
            appendLog("[app] 已自动清理 " + n + " 项临时文件")
        }
    }

    fun setKsuIndex(index: Int) = _state.update { it.copy(ksuIndex = index) }

    fun setSafeMode(on: Boolean) = _state.update { it.copy(safeMode = on) }

    fun clearLog() {
        synchronized(logLock) {
            logBuilder.setLength(0)
            lineBuffer.setLength(0)
            tracker.reset()
        }
        _state.update {
            it.copy(log = "", stages = STAGES.map { spec -> StageStatus(spec.title, StagePhase.PENDING) })
        }
    }

    fun consumeToast() = _state.update { it.copy(toast = null) }

    private fun toast(msg: String) = _state.update { it.copy(toast = msg) }

    private fun finish(failed: Boolean) {
        android.util.Log.i(
            "XproSU",
            "finish failed=" + failed + " running=" + _state.value.running +
                " exitSeen=" + exitSeen + " zombieHeld=" + zombieHeld +
                " tail=" + synchronized(logLock) { logBuilder.toString().takeLast(150).replace("\n", " | ") }
        )
        if (!failed) {
            synchronized(logLock) { tracker.feed("ROOT_SHELL_OK") }
        }
        flushUi(force = true) // 结束前把节流中没推出去的日志补齐
        _state.update {
            it.copy(
                running = false,
                stages = synchronized(logLock) { tracker.snapshot() },
                toast = if (failed) "运行结束（失败），见日志" else it.toast,
            )
        }
    }

    /**
     * 单引号包裹的 shell 字面量；内部单引号按 POSIX 规则转义。
     * 命令体整体放进 OPEN 包，不经过数据帧。
     */
    private fun quote(s: String): String = "'" + s.replace("'", "'\\''") + "'"

    private suspend fun pushAsset(asset: String, dst: String) {
        val bytes = getApplication<Application>().assets.open(asset).use { it.readBytes() }
        AdbTransport.pushFile(bytes, dst, 0x1ed) // 0755
    }

    /**
     * 日志线程安全地追加；按行喂给阶段解析器。
     *
     * 界面刷新必须节流：每来一段日志就重建整串日志（最多 400 KB）并触发 Compose
     * 重组，会让界面线程与载荷争抢同一个页面分配器。实测前台实时刷新时 plant 命中
     * 耗时 4–139ms、约一成直接空等 15 秒后 holding zombie；同一份载荷息屏跑则稳定
     * 5–18ms 全中。所以这里只把文本追加进缓冲，界面最多每 [UI_FLUSH_MS] 毫秒取一次
     * 快照；退出、挂起这类关键事件才强制立刻刷新。
     */
    private fun appendLog(text: String) {
        var exited: Int? = null
        synchronized(logLock) {
            logBuilder.append(text)
            if (logBuilder.length > LOG_LIMIT) {
                logBuilder.delete(0, logBuilder.length - LOG_LIMIT)
            }
            lineBuffer.append(text)
            while (true) {
                val idx = lineBuffer.indexOf("\n")
                if (idx < 0) break
                val line = lineBuffer.substring(0, idx)
                lineBuffer.delete(0, idx + 1)
                tracker.feed(line)
                // 只有 park_forever 的结句才是终态（core/timer98260.c:1033）。
                if (line.contains("reboot before rerun")) zombieHeld = true
                // 这两个是 core 跑完后的自评（core/timer98260.c:3547、:3549）。
                if (line.contains("failure condition:")) plantMissed = true
                if (line.contains("success condition met")) plantMissed = false
                if (line.contains("[core] exit=")) {
                    exited = line.substringAfter("[core] exit=").trim().toIntOrNull()
                    exitSeen = exited
                    exitAtMs = System.currentTimeMillis()
                    // core 正常退出但没打 ROOT_SHELL_OK 时，仍把「完成」标掉
                    if (exited == 0) tracker.feed("ROOT_SHELL_OK")
                }
            }
        }
        val code = exited
        if (code == null) {
            flushUi(force = false)
            return
        }
        pendingExit = code
        val snapshot = flushUi(force = true)
        viewModelScope.launch(Dispatchers.IO) {
            runCatching { handleCoreExit(code, activeManager.orEmpty()) }
        }
        val failHint = when {
            code == 0 -> null
            snapshot.contains("fake cred retry exhausted") ->
                "伪造 cred 8 次未命中：内核状态可能被上次运行污染，重启后再试"
            snapshot.contains("start failed") -> null
            else -> "运行结束（exit=" + code + "），见日志"
        }
        if (failHint != null) _state.update { it.copy(toast = failHint) }
        if (code == 0 && plantMissed) {
            appendLog(
                "[adb] 警告：载荷报告 failure condition（有 plant 没被回收）。本轮确实提到了 root，" +
                    "但内核里可能还留着 timer 节点，建议用完重启一次再跑。"
            )
            _state.update { it.copy(toast = "提权完成，但建议重启后再用（有 plant 未回收）") }
        }
    }

    /**
     * 把缓冲里的日志推给界面。force=false 时按 [UI_FLUSH_MS] 合并，避免每行都重组；
     * 返回本次推送的日志快照（节流未刷新时返回空串）。
     */
    private fun flushUi(force: Boolean): String {
        if (!force) {
            if (flushJob?.isActive != true) {
                flushJob = viewModelScope.launch(Dispatchers.Default) {
                    delay(UI_FLUSH_MS)
                    flushUi(force = true)
                }
            }
            return ""
        }
        flushJob?.cancel()
        flushJob = null
        val snapshot: String
        val stages: List<StageStatus>
        synchronized(logLock) {
            snapshot = logBuilder.toString()
            stages = tracker.snapshot()
        }
        val ex = pendingExit
        _state.update {
            it.copy(
                log = snapshot,
                stages = stages,
                running = if (ex != null) false else it.running,
            )
        }
        return snapshot
    }

    override fun onCleared() {
        tailJob?.cancel()
        super.onCleared()
    }
}
