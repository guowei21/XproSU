package com.xprosu

import android.app.Application
import android.content.ComponentName
import android.content.ServiceConnection
import android.content.pm.PackageManager
import android.net.Uri
import android.os.IBinder
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.xprosu.core.STAGES
import com.xprosu.core.StagePhase
import com.xprosu.core.StageStatus
import com.xprosu.core.StageTracker
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
import rikka.shizuku.Shizuku
import java.io.InputStream

enum class ShizukuState { UNKNOWN, NOT_RUNNING, NO_PERMISSION, READY }

data class AppState(
    val shizuku: ShizukuState = ShizukuState.UNKNOWN,
    val serviceReady: Boolean = false,
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

private const val REQ_SHIZUKU = 1001
private const val TMP = "/data/local/tmp/"
private const val CHUNK = 128 * 1024
private const val ATTEMPTS = 16
private const val DEFAULT_CMD = "id; cat /proc/self/attr/current; getenforce; echo LPE-PROOF"
private const val LOG_LIMIT = 400_000

class MainViewModel(app: Application) : AndroidViewModel(app) {

    private val _state = MutableStateFlow(AppState())
    val state: StateFlow<AppState> = _state.asStateFlow()

    @Volatile private var svc: IIcService? = null
    private var args: Shizuku.UserServiceArgs? = null
    @Volatile private var activeManager: String? = null
    @Volatile private var logPath: String? = null
    @Volatile private var logOffset = 0
    @Volatile private var exitAtMs = 0L
    private var pollJob: Job? = null

    private val logLock = Any()
    private val logBuilder = StringBuilder()
    private val lineBuffer = StringBuilder()
    private val tracker = StageTracker()
    private var exitSeen: Int? = null

    private val onPermission = Shizuku.OnRequestPermissionResultListener { _, grant ->
        _state.update {
            it.copy(
                toast = if (grant == PackageManager.PERMISSION_GRANTED) {
                    "Shizuku 权限已允许"
                } else {
                    "Shizuku 权限被拒绝($grant)"
                },
            )
        }
        if (grant == PackageManager.PERMISSION_GRANTED) bindService()
        refreshShizuku()
    }

    private val onBinderReceived = Shizuku.OnBinderReceivedListener { refreshShizuku() }

    private val onBinderDead = Shizuku.OnBinderDeadListener {
        svc = null
        _state.update { it.copy(serviceReady = false) }
        refreshShizuku()
    }

    private val conn = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName?, binder: IBinder?) {
            val s = binder?.let { IIcService.Stub.asInterface(it) }
            svc = s
            _state.update { it.copy(serviceReady = s != null) }
            if (s == null) return
            viewModelScope.launch(Dispatchers.IO) {
                val id = runCatching { s.identity() }.getOrElse { "读取身份失败: $it" }
                val dev = runCatching {
                    s.runCmd("getprop ro.product.model; getprop ro.build.display.id; uname -r")
                }.getOrNull().orEmpty()
                withContext(Dispatchers.Main) {
                    _state.update { it.copy(identity = id, device = dev.trim()) }
                    appendLog("[service] $id")
                    if (dev.isNotBlank()) appendLog("[设备]\n${dev.trim()}")
                }
            }
        }

        override fun onServiceDisconnected(name: ComponentName?) {
            svc = null
            _state.update { it.copy(serviceReady = false) }
        }
    }

    init {
        Shizuku.addBinderReceivedListenerSticky(onBinderReceived)
        Shizuku.addBinderDeadListener(onBinderDead)
        Shizuku.addRequestPermissionResultListener(onPermission)
        refreshShizuku()
    }

    fun refreshShizuku() {
        val running = runCatching { Shizuku.pingBinder() }.getOrDefault(false)
        val granted = running && runCatching {
            Shizuku.checkSelfPermission() == PackageManager.PERMISSION_GRANTED
        }.getOrDefault(false)
        _state.update {
            it.copy(
                shizuku = when {
                    !running -> ShizukuState.NOT_RUNNING
                    !granted -> ShizukuState.NO_PERMISSION
                    else -> ShizukuState.READY
                },
            )
        }
    }

    fun connect() {
        if (!runCatching { Shizuku.pingBinder() }.getOrDefault(false)) {
            _state.update { it.copy(toast = "Shizuku 未运行：请先用无线调试 / ADB 启动 Shizuku") }
            refreshShizuku()
            return
        }
        if (runCatching { Shizuku.checkSelfPermission() }.getOrDefault(-1) !=
            PackageManager.PERMISSION_GRANTED
        ) {
            _state.update { it.copy(toast = "已弹出 Shizuku 授权请求，请允许") }
            runCatching { Shizuku.requestPermission(REQ_SHIZUKU) }
            return
        }
        bindService()
    }

    private fun bindService() {
        if (svc != null) return
        try {
            val cn = ComponentName(getApplication(), IcService::class.java)
            val a = Shizuku.UserServiceArgs(cn)
                .daemon(true)
                .debuggable(false)
                .version(1)
                .tag("ic-lpe")
                .processNameSuffix(":icsvc")
            args = a
            Shizuku.bindUserService(a, conn)
            appendLog("正在绑定 shell 用户服务…")
        } catch (t: Throwable) {
            _state.update { it.copy(toast = "绑定失败: $t") }
        }
    }

    fun run() {
        val s = svc ?: return toast("服务未连接：先点“连接 Shizuku”")
        if (_state.value.running) return
        val st = _state.value
        val selectedPkg = KSU_PACKAGES[st.ksuIndex]
        val safe = st.safeMode

        // 每次运行用新副本：截断仍在执行的 ELF 会让停驻的 attempt SIGBUS。
        val stamp = (System.currentTimeMillis() / 1000).toString()
        val bin = TMP + "ic-timer-a$stamp"
        val script = TMP + "ic-lpe-a$stamp.sh"
        val logFile = TMP + "ic-app-a$stamp.log"
        // 与上游一致：handoff 恒存在，空包名由脚本自己识别管理器。
        val handoff: String? = TMP + "ksu-h$stamp.sh"
        val safeScript = if (safe && handoff == null) TMP + "ic-safe-h$stamp.sh" else null

        synchronized(logLock) {
            tracker.reset()
            exitSeen = null
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
                // 自动检测：pm list packages 里按已知优先级取第一个装了的。
                val managerPkg = if (selectedPkg.isEmpty()) detectManager(s) else selectedPkg
                activeManager = managerPkg
                if (managerPkg.isNotEmpty()) {
                    _state.update { it.copy(detectedManager = managerPkg) }
                    appendLog("[app] 管理器: ${managerName(managerPkg)} ($managerPkg)")
                } else {
                    appendLog("[app] 未检测到已安装的 KSU 管理器，只做提权")
                }

                val payload = when {
                    handoff != null ->
                        "sh $handoff '$managerPkg' '' '${if (safe) "1" else "0"}' ; $DEFAULT_CMD"
                    safeScript != null -> "sh $safeScript ; $DEFAULT_CMD"
                    else -> DEFAULT_CMD
                }
                val extraEnv = buildString {
                    append("IC_SYMS_FILE=/data/local/tmp/ic-syms.txt")
                    if (safe) append("\nIC_SAFE_MODE=1")
                    if (handoff != null) append("\nIC_KSU=1")
                    if (handoff != null) {
                        // 空检测结果传 "-"：让 core 跳过写死的 am start 并不再报错，
                        // 管理器由应用侧退出后再找。
                        append("\nIC_KSU_PKG=${managerPkg.ifEmpty { "-" }}")
                    }
                }

                val id0 = s.identity()
                if (!id0.startsWith("uid=2000 ") || !id0.contains("ctx=u:r:shell")) {
                    appendLog(
                        "[run] 拒绝执行：用户服务身份不是 shell\n$id0\n" +
                            "请用 ADB / 无线调试启动 Shizuku（不要用 root 启动），再点“连接 Shizuku”。",
                    )
                    finish(failed = true)
                    return@launch
                }
                s.truncate(script)
                pushAsset(s, "run_core.sh", script)
                s.makeExec(script)

                s.truncate(bin)
                pushAsset(s, "ic-timer", bin)
                s.makeExec(bin)

                if (handoff != null) {
                    s.truncate(handoff)
                    pushAsset(s, "ksu_handoff.sh", handoff)
                    s.makeExec(handoff)
                }
                if (safeScript != null) {
                    s.truncate(safeScript)
                    pushAsset(s, "safemode.sh", safeScript)
                    s.makeExec(safeScript)
                }

                s.truncate(logFile)
                val r = s.start(script, bin, logFile, ATTEMPTS, payload, extraEnv)
                val label = if (selectedPkg.isEmpty()) {
                    "自动检测 → ${managerName(managerPkg)}"
                } else {
                    KSU_NAMES[st.ksuIndex]
                }
                appendLog("[run] 方案: run_core.sh  KSU: $label\n$r")
                logPath = logFile
                logOffset = 0
                startPolling()
            } catch (t: Throwable) {
                appendLog("[run] 失败: $t")
                finish(failed = true)
            }
        }
    }

    /**
     * 先按已知包名匹配；没有命中就按关键字扫描，并用 resolve-activity
     * 确认它真的有 launcher（有些 fork 会换包名或带随机别名）。
     */
    private fun detectManager(s: IIcService): String {
        val out = runCatching { s.runCmd("pm list packages") }.getOrNull().orEmpty()
        val known = KSU_PACKAGES
            .filter { it.isNotEmpty() }
            .firstOrNull { out.contains("package:$it") }
        if (known != null) return known

        val keys = listOf("kernelsu", "sukisu", "resukisu", "bakasu", "sakisu", "vivoksu", "ksu")
        val candidates = out.lineSequence()
            .map { it.removePrefix("package:").trim() }
            .filter { p -> p.isNotEmpty() && keys.any { p.contains(it, ignoreCase = true) } }
            .take(6)
            .toList()
        return candidates.firstOrNull { p ->
            runCatching {
                s.runCmd("cmd package resolve-activity --brief $p 2>/dev/null | tail -1")
            }.getOrNull().orEmpty().contains("/")
        }.orEmpty()
    }

    private fun managerName(pkg: String): String {
        val i = KSU_PACKAGES.indexOf(pkg)
        return if (i >= 0) KSU_NAMES[i] else pkg
    }

    private fun startPolling() {
        pollJob?.cancel()
        pollJob = viewModelScope.launch(Dispatchers.IO) {
            val started = System.currentTimeMillis()
            while (isActive) {
                if (System.currentTimeMillis() - started > 20 * 60 * 1000L) {
                    _state.update { it.copy(running = false, toast = "运行超时（20 分钟），见日志") }
                    break
                }
                val s = svc ?: break
                val p = logPath ?: break
                try {
                    val len = s.length(p)
                    if (len > logOffset) {
                        var off = logOffset
                        while (off < len && isActive) {
                            val want = minOf(64 * 1024, len - off)
                            val bytes = s.read(p, off, want)
                            if (bytes == null || bytes.isEmpty()) break
                            off += bytes.size
                            appendLog(String(bytes, Charsets.UTF_8))
                        }
                        logOffset = off
                    }
                } catch (_: Throwable) {
                    // 服务端日志文件可能尚未创建，下一轮再试
                }
                val stopped = !_state.value.running
                if (stopped && exitAtMs > 0 && System.currentTimeMillis() - exitAtMs > 15_000) break
                delay(700)
            }
        }
    }

    /**
     * core 最后一步把 am start 的包名写死成 me.weishu.kernelsu，SukiSU 等管理器
     * 必然失败并让 core 以 1 退出。模块已 resident 时由应用侧收尾：
     * 已在前台就什么都不做，否则用 resolve-activity 冷启动一次。
     * 不 force-stop —— 用户可能正用着管理器，杀掉再拉会丢状态。
     */
    private fun handleCoreExit(code: Int, manager: String) {
        viewModelScope.launch(Dispatchers.IO) {
            val s = svc ?: return@launch
            // 给脚本自己的收尾留时间，避免两边同时拉起
            delay(2500)
            val live = runCatching {
                s.runCmd("grep -q '^kernelsu ' /proc/modules && echo LIVE || echo NOLIVE")
            }.getOrNull().orEmpty()
            if (!live.contains("LIVE")) {
                appendLog("[app] KSU 模块不在 /proc/modules，跳过管理器启动")
                autoCleanup(s)
                return@launch
            }

            // 运行时没检测到就再扫一次：用户可能刚装好管理器，或者包名不在清单里
            val target = manager.ifEmpty { detectManager(s) }
            if (target.isEmpty()) {
                appendLog("[app] 未识别到 KSU 管理器，请手动打开管理器完成激活")
                autoCleanup(s)
                markHandoffDone("提权完成；未识别到管理器，请手动打开")
                return@launch
            }

            val top = runCatching {
                s.runCmd("dumpsys activity activities 2>/dev/null | grep -m1 topResumedActivity")
            }.getOrNull().orEmpty()
            if (top.contains(target)) {
                appendLog("[app] 管理器已在前台，跳过启动")
            } else {
                // 不 force-stop：管理器可能正被用户使用，杀掉再拉会丢状态。
                val comp = runCatching {
                    s.runCmd("cmd package resolve-activity --brief $target 2>/dev/null | tail -1")
                }.getOrNull().orEmpty().trim()
                val out = if (comp.contains("/")) {
                    runCatching {
                        s.runCmd("am start -W -n $comp 2>&1 | grep -E 'Status|LaunchState|Error' | tr '\\n' ' '")
                    }.getOrNull().orEmpty()
                } else {
                    runCatching {
                        s.runCmd("monkey -p $target -c android.intent.category.LAUNCHER 1 2>&1 | tail -2 | tr '\\n' ' '")
                    }.getOrNull().orEmpty()
                }
                appendLog("[app] 启动管理器 $target ($comp): ${out.trim()}")
            }

            autoCleanup(s)
            markHandoffDone("提权完成：KSU 模块已加载，管理器已拉起")
        }
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
        val s = svc ?: return toast("服务未连接：先点“连接 Shizuku”")
        viewModelScope.launch(Dispatchers.IO) {
            val out = try {
                s.runCmd(
                    "id; cat /proc/self/attr/current; getenforce; echo ---; uname -r; " +
                        "getprop ro.product.device; getprop ro.product.model; echo ---; " +
                        "ls -l /data/local/tmp/ | head -20; echo ---; " +
                        "head -n 2 /data/local/tmp/ic-syms.txt 2>/dev/null; " +
                        "ls -d /data/adb/ksu 2>/dev/null; echo ---; " +
                        "pm list packages 2>/dev/null | grep -Ei 'kernelsu|sukisu|resukisu|bakasu|sakisu|sevenk|ksunext|fina'",
                )
            } catch (t: Throwable) {
                "诊断失败: $t"
            }
            appendLog("[诊断]\n$out")
        }
    }

    fun parseOffsets(uri: Uri) {
        val s = svc ?: return toast("服务未连接：先点“连接 Shizuku”")
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val stamp = (System.currentTimeMillis() / 1000).toString()
                val bin = TMP + "ic-syms-a$stamp"
                val img = TMP + "ic-boot-a$stamp.img"
                val syms = "/data/local/tmp/ic-syms.txt"
                s.truncate(bin)
                pushAsset(s, "ic-timer", bin)
                s.makeExec(bin)

                s.truncate(img)
                var off = 0
                val input: InputStream = getApplication<Application>().contentResolver
                    .openInputStream(uri)
                    ?: throw IllegalStateException("openInputStream 返回 null")
                input.use {
                    val buf = ByteArray(CHUNK)
                    while (true) {
                        val n = it.read(buf)
                        if (n <= 0) break
                        val chunk = if (n == buf.size) buf else buf.copyOf(n)
                        s.put(img, off, chunk)
                        off += n
                    }
                }
                val out = s.runCmd(
                    "ls -l $img 2>&1; $bin syms $img $syms 2>&1; echo parse_rc=$?; " +
                        "sed -n '1,3p' $syms 2>/dev/null; rm -f $img",
                )
                appendLog("[解析偏移] 已选择: ${uri.lastPathSegment.orEmpty()} ($off bytes)\n$out")
            } catch (t: Throwable) {
                appendLog("[解析偏移] 失败: $t")
            }
        }
    }

    private suspend fun cleanupTemp(s: IIcService): Int {
        val stamp = (System.currentTimeMillis() / 1000).toString()
        val script = TMP + "ic-clean-a$stamp.sh"
        s.truncate(script)
        pushAsset(s, "cleanup_tmp.sh", script)
        s.makeExec(script)
        val out = s.runCmd("sh $script 2>&1")
        return Regex("cleaned=(\\d+)").find(out)?.groupValues?.get(1)?.toIntOrNull() ?: 0
    }

    /** 运行结束后自动清理；等日志轮询收尾再删，避免日志读一半。 */
    private suspend fun autoCleanup(s: IIcService) {
        runCatching { pollJob?.join() }
        runCatching { cleanupTemp(s) }.onSuccess { n ->
            appendLog("[app] 已自动清理 $n 项临时文件")
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
        if (!failed) {
            synchronized(logLock) { tracker.feed("ROOT_SHELL_OK") }
        }
        _state.update {
            it.copy(
                running = false,
                stages = synchronized(logLock) { tracker.snapshot() },
                toast = if (failed) "运行结束（失败），见日志" else it.toast,
            )
        }
    }

    private fun pushAsset(s: IIcService, asset: String, dst: String) {
        getApplication<Application>().assets.open(asset).use { input ->
            val buf = ByteArray(CHUNK)
            var off = 0
            while (true) {
                val n = input.read(buf)
                if (n <= 0) break
                val chunk = if (n == buf.size) buf else buf.copyOf(n)
                s.put(dst, off, chunk)
                off += n
            }
        }
    }

    /** 日志线程安全地追加；按行喂给阶段解析器。 */
    private fun appendLog(text: String) {
        var snapshot: String
        var stages: List<StageStatus>
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
                if (line.contains("[core] exit=")) {
                    exited = line.substringAfter("[core] exit=").trim().toIntOrNull()
                    exitAtMs = System.currentTimeMillis()
                    // core 正常退出但没打 ROOT_SHELL_OK 时，仍把「完成」标掉
                    if (exited == 0) tracker.feed("ROOT_SHELL_OK")
                }
            }
            snapshot = logBuilder.toString()
            stages = tracker.snapshot()
        }
        exited?.let { code -> runCatching { handleCoreExit(code, activeManager.orEmpty()) } }
        val failHint = when {
            exited == null || exited == 0 -> null
            snapshot.contains("fake cred retry exhausted") ->
                "伪造 cred 8 次未命中：内核状态可能被上次运行污染，重启后再试"
            snapshot.contains("start failed") -> null
            else -> "运行结束（exit=$exited），见日志"
        }
        _state.update {
            it.copy(
                log = snapshot,
                stages = stages,
                running = if (exited != null) false else it.running,
                toast = failHint ?: it.toast,
            )
        }
    }

    override fun onCleared() {
        pollJob?.cancel()
        runCatching { Shizuku.removeRequestPermissionResultListener(onPermission) }
        runCatching { Shizuku.removeBinderDeadListener(onBinderDead) }
        runCatching { Shizuku.removeBinderReceivedListener(onBinderReceived) }
        val a = args
        if (a != null) runCatching { Shizuku.unbindUserService(a, conn, false) }
        svc = null
        super.onCleared()
    }
}
