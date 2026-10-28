package com.ghostlock.pro.data

import android.annotation.SuppressLint
import android.content.Context
import android.os.Build
import android.system.Os
import com.ghostlock.pro.domain.model.CpuPair
import com.ghostlock.pro.domain.model.KernelSnapshot
import com.ghostlock.pro.domain.model.SupportedKernels
import com.ghostlock.pro.domain.repository.GhostlockRepository
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runInterruptible
import kotlinx.coroutines.withContext
import java.io.File
import java.io.IOException
import java.io.RandomAccessFile
import java.nio.charset.StandardCharsets
import java.util.Locale
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicLong

/**
 * Android implementation of the domain repository. All platform I/O lives here.
 *
 * 偏移表随 APK 分发：`assets/offsets.enc` 由 [LocalOffsets] 在运行前解开，写成
 * 引擎认识的 `offsets.json`。没有卡密、没有会话密钥、没有网络请求。
 */
class AndroidGhostlockRepository(
    context: Context,
) : GhostlockRepository {
    private companion object {
        /** 引擎从 `$GHOSTLOCK_HOME/offsets.json` 导入偏移表。 */
        const val OffsetsFileName = "offsets.json"
        /** AES-256-GCM 密封的同一张表，见 tools/pack_offsets_local.py。 */
        const val OffsetsAsset = "offsets.enc"
        const val KsuLogName = ".ghostlock_ksu.log"

        const val KEY_TCP_ROUTE = "tcp_route"
    }

    private val appContext = context.applicationContext
    private val filesDir: File = appContext.filesDir
    private val offsetsFile get() = File(filesDir, OffsetsFileName)
    private val cpuPairs = mutableListOf<CpuPair>()
    private var selectedPair: CpuPair? = null
    private var safeModeEnabled = false
    private val prefs = appContext.getSharedPreferences("ghostlock_settings", Context.MODE_PRIVATE)

    init {
        buildCpuPairs()
    }

    override fun bestCpuPair(): CpuPair = selectedCpuPair()

    override fun availableCpuPairs(): List<CpuPair> = cpuPairs.toList()

    override fun availableCpuPairLabels(): List<String> = cpuPairs.map(::labelOf)

    override fun selectedCpuPair(): CpuPair = selectedPair ?: cpuPairs.first()

    override fun selectCpuPair(pair: CpuPair?) {
        selectedPair = pair
    }

    override fun tcpRouteEnabled(): Boolean = prefs.getBoolean(KEY_TCP_ROUTE, false)

    override fun setTcpRouteEnabled(enabled: Boolean) {
        prefs.edit().putBoolean(KEY_TCP_ROUTE, enabled).apply()
    }

    override fun selectedManagerPackage(): String? =
        prefs.getString(ManagerScanner.PREF_KEY, null)?.takeIf { it.isNotBlank() }

    override fun setSelectedManagerPackage(pkg: String?) {
        prefs.edit().putString(ManagerScanner.PREF_KEY, pkg).apply()
    }

    override suspend fun installedManagers(): List<ManagerScanner.Candidate> =
        withContext(Dispatchers.IO) {
            runCatching { ManagerScanner.scan(appContext.packageManager, appContext.packageName) }
                .getOrDefault(emptyList())
        }

    override suspend fun snapshot(): KernelSnapshot = KernelSnapshot(
        deviceName = resolveDeviceName(),
        kernelRelease = System.getProperty("os.version", "unknown").orEmpty(),
        socName = resolveSocName(),
        kernelSupported = isKernelSupported(),
        cpuPairLabel = bestCpuPairLabel(),
        safeModeEnabled = safeModeEnabled,
    )

    override fun setSafeModeEnabled(enabled: Boolean) {
        safeModeEnabled = enabled
    }


    /**
     * 把随包的偏移表解到 `<files>/offsets.json`。
     *
     * 每次运行前都重写一份：解出来的表只有 5 KB，解密成本远低于「缓存被截断后
     * 引擎静默退回内建表」的风险。解不开就直接返回 false，由调用方中止本次运行——
     * 读到半张表比没有表更危险。
     */
    private fun ensureLocalOffsets(onLog: (String) -> Unit): Boolean {
        return try {
            val sealed = appContext.assets.open(OffsetsAsset).use { it.readBytes() }
            offsetsFile.writeBytes(LocalOffsets.decrypt(sealed))
            true
        } catch (error: Exception) {
            onLog("error: offsets decrypt failed: " + (error.message ?: error::class.simpleName))
            false
        }
    }


    /**
     * 运行一次提权。
     *
     * 顺序是固定的：解开随包的偏移表 → 执行引擎。表解不开就不跑——引擎在找不到
     * 导入表时会退回编译期内建的那一份，而那份未必与随包的版本一致，静默跑一张
     * 旧表比直接失败更难查。
     */
    override suspend fun runExploit(
        pair: CpuPair,
        onLog: (String) -> Unit,
    ): Int {
        val workDir = filesDir
        return try {
            val binary = File(appContext.applicationInfo.nativeLibraryDir, "libghostlock.so")
            require(binary.isFile) { "missing native binary: " + binary.absolutePath }
            if (!ensureLocalOffsets(onLog)) return 1
            runExploitInner(pair, onLog, workDir, binary)
        } catch (error: CancellationException) {
            throw error
        } catch (error: Exception) {
            onLog("error: " + (error::class.simpleName ?: "?") + ": " + error.message)
            1
        }
    }

    private suspend fun runExploitInner(
        pair: CpuPair,
        onLog: (String) -> Unit,
        workDir: File,
        binary: File,
    ): Int {
        if (prepareKsud(workDir, onLog) != null) onLog("ksud ready") else onLog("warning: ksud not found")
        // the root script creates its log as root, so one name per run
        // keeps the last run's lines out of this run's log
        val ksuLog = File(workDir, "$KsuLogName.${System.currentTimeMillis()}")
        val nativeLog = File(workDir, ".ghostlock_native.log")
        nativeLog.writeText("")
        val ksuOffset = AtomicLong()
        val nativeOffset = AtomicLong()
        // tag root-script lines so they cannot be read as the native stages'
        val ksuSink: (String) -> Unit = { onLog("[ksu] $it") }
        val tailer = Thread {
            try {
                while (!Thread.currentThread().isInterrupted) {
                    tailKsuLog(nativeLog, nativeOffset, onLog)
                    tailKsuLog(ksuLog, ksuOffset, ksuSink)
                    Thread.sleep(200)
                }
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
            }
        }.apply {
            name = "ksu-log-tailer"
            isDaemon = true
            start()
        }
        val command = ProcessBuilder(binary.absolutePath)
            .directory(workDir)
            .redirectErrorStream(true)
            .redirectOutput(nativeLog)
            .apply {
                environment()["GHOSTLOCK_HOME"] = workDir.absolutePath
                environment()["TMPDIR"] = workDir.absolutePath
                environment()["HOME"] = workDir.absolutePath
                environment()["GHOSTLOCK_KSU_LOG"] = ksuLog.absolutePath
                environment()["GHOSTLOCK_CORE"] = pair.primary.toString()
                environment()["GHOSTLOCK_CONSUMER_CORE"] = pair.consumer.toString()
                environment()["GHOSTLOCK_ROUTE"] = if (tcpRouteEnabled()) "tcp" else "mcast"
                if (safeModeEnabled) environment()["GHOSTLOCK_DISABLE_MODULES"] = "1"
            }
        return try {
            runProcess(command, onLog = {}, captureOutput = false)
        } finally {
            withContext(Dispatchers.IO) {
                tailer.interrupt()
                tailer.join(1000)
                tailKsuLog(nativeLog, nativeOffset, onLog)
                tailKsuLog(ksuLog, ksuOffset, ksuSink)
                // 引擎日志是一次性排错产物，运行结束即删，不留明文残留。
                runCatching { nativeLog.delete() }
                runCatching { ksuLog.delete() }
            }
        }
    }

    override fun close() {
        synchronized(processes) {
            processes.forEach(Process::destroyForcibly)
            processes.clear()
        }
    }

    private fun isKernelSupported(): Boolean {
        val version = System.getProperty("os.version", "").orEmpty()
        // 只做粗筛：真正的判定在引擎里（内建表 / 导入表都要过同一套 gate）。
        // 这里列的是本仓库验证过的 release，命中即视为“值得一试”。
        return version in SupportedKernels.UNAMES
    }

    /**
     * Pick the CPU pair the exploit races on, automatically.
     *
     * The race window only opens when the writer and the consumer run on the
     * same high-frequency cluster: split across clusters, or parked on a slow
     * cluster, the consumer wakes too late and the route misses.  That makes
     * the choice a measured parameter, not a preference, so nothing here is
     * user-facing -- the app takes the highest-frequency pair from
     * /sys/devices/system/cpu and always sets it.
     *
     * The engine still honours GHOSTLOCK_CORE / GHOSTLOCK_CONSUMER_CORE, so a
     * manual override over adb keeps working.
     */
    private fun buildCpuPairs() {
        cpuPairs.clear()
        val online = parseCpuList(readSysFile("/sys/devices/system/cpu/online"))
        online.groupBy { readMaxFreq(it) }
            .filterKeys { it > 0 }
            .toSortedMap(compareByDescending { it })
            .forEach { (_, cluster) ->
                cluster.sorted().chunked(2).filter { it.size == 2 }.forEach { pair ->
                    cpuPairs += CpuPair(pair[0], pair[1])
                }
            }
        if (cpuPairs.isEmpty()) cpuPairs += CpuPair(0, 1)
    }

    /** Label of the pair the app will use, for the device card. */
    /** Label of the pair the app will use, for the device card. */
    private fun bestCpuPairLabel(): String = labelOf(selectedCpuPair())

    private fun labelOf(pair: CpuPair): String {
        val freq = readMaxFreq(pair.primary)
        return "${pair.primary},${pair.consumer}" + if (freq > 0) " · ${formatFreq(freq)}" else ""
    }


    private fun parseCpuList(value: String): List<Int> = value.split(',').flatMap { part ->
        val range = part.trim().split('-').mapNotNull { it.toIntOrNull() }
        when (range.size) {
            1 -> range
            2 -> (range[0]..range[1]).toList()
            else -> emptyList()
        }
    }

    private fun readMaxFreq(cpu: Int): Long = readSysFile("/sys/devices/system/cpu/cpu$cpu/cpufreq/cpuinfo_max_freq").toLongOrNull() ?: -1L

    private fun formatFreq(khz: Long): String =
        if (khz >= 1_000_000L) "%.2f GHz".format(Locale.ROOT, khz / 1_000_000.0) else "%.0f MHz".format(Locale.ROOT, khz / 1000.0)

    private fun readSysFile(path: String): String = File(path).takeIf { it.isFile }?.useLines { it.firstOrNull()?.trim().orEmpty() } ?: ""

    @SuppressLint("PrivateApi")
    private fun systemProperty(key: String): String = try {
        val properties = Class.forName("android.os.SystemProperties")
        properties.getMethod("get", String::class.java).invoke(null, key) as? String ?: ""
    } catch (_: Throwable) {
        ""
    }

    private fun validDeviceName(value: String?): String? =
        value?.trim()?.takeIf { it.isNotEmpty() && !it.contains("unknown", true) && !it.contains("null", true) }

    private fun resolveDeviceName(): String {
        val manufacturer = Build.MANUFACTURER.orEmpty()
        val marketName = when (manufacturer.lowercase(Locale.ROOT)) {
            "xiaomi" -> firstValidProperty("ro.product.marketname")
            "oppo", "oneplus", "realme", "oplus" -> {
                val cn = Locale.getDefault().country.equals("CN", true)
                firstValidProperty(
                    *(if (cn) arrayOf(
                        "ro.vendor.oplus.market.name",
                        "ro.vendor.oplus.market.enname"
                    ) else arrayOf("ro.vendor.oplus.market.enname", "ro.vendor.oplus.market.name"))
                )
            }

            "vivo" -> firstValidProperty("ro.vivo.market.name")
            "honor", "huawei" -> firstValidProperty("ro.config.marketing_name")
            "zte", "nubia" -> firstValidProperty("ro.vendor.product.ztename")
            else -> null
        }
        return marketName ?: listOfNotNull(
            manufacturer,
            Build.BRAND.orEmpty().takeIf { !it.equals(manufacturer, true) },
            Build.MODEL.orEmpty()
        )
            .filter { it.isNotBlank() }
            .joinToString(" ")
    }

    private fun resolveSocName(): String = listOf(
        systemProperty("ro.soc.manufacturer"),
        systemProperty("ro.soc.model"),
    )
        .mapNotNull(::validDeviceName)
        .joinToString(" ")
        .ifBlank { "unknown" }

    private fun firstValidProperty(vararg keys: String): String? =
        keys.asSequence().firstNotNullOfOrNull { validDeviceName(systemProperty(it)) }

    /**
     * 找出提供 ksud 的管理器并复制成 `files/ksud`。
     *
     * 顺序 = 手动选择优先 + 内置列表兜底（见 [ManagerScanner.resolvePackages]）：
     * 选择项被卸载或缺 libksud.so 时自动回退，不会让提权整体失败。
     */
    private fun prepareKsud(workDir: File, onLog: (String) -> Unit): File? {
        val chosen = selectedManagerPackage()
        val packages = ManagerScanner.resolvePackages(chosen)
        var installed = false
        for (packageName in packages) {
            val appInfo = runCatching {
                appContext.packageManager.getApplicationInfo(packageName, 0)
            }.getOrNull() ?: continue
            installed = true
            val source = File(appInfo.nativeLibraryDir, "libksud.so")
            if (!source.isFile) continue
            val output = File(workDir, "ksud")
            runCatching {
                source.inputStream().use { input -> output.outputStream().use { input.copyTo(it) } }
                runCatching { Os.chmod(output.absolutePath, 448) }
                onLog("ksud source: $packageName")
                return output
            }.onFailure { onLog("copy ksud failed: ${it.message}") }
        }
        when {
            !installed && chosen.isNullOrBlank() ->
                onLog("KernelSU/ReSukiSU/BakaSU/KowSU app not installed")
            !installed ->
                onLog("selected manager $chosen is not installed; no fallback found")
            else ->
                onLog("manager app(s) found but none provides libksud.so")
        }
        return null
    }

    private suspend fun runProcess(
        builder: ProcessBuilder,
        onLog: (String) -> Unit = {},
        timeoutSeconds: Long = 300,
        captureOutput: Boolean = true,
    ): Int = runInterruptible {
        val process = builder.start()
        synchronized(processes) { processes += process }
        val reader = if (captureOutput) Thread {
            try {
                process.inputStream.bufferedReader(StandardCharsets.UTF_8).useLines { lines -> lines.forEach(onLog) }
            } catch (_: IOException) { }
        }.apply {
            name = "process-output-reader"
            isDaemon = true
        } else null
        try {
            reader?.start()
            val finished = process.waitFor(timeoutSeconds, TimeUnit.SECONDS)
            if (!finished) {
                process.destroy()
                if (!process.waitFor(5, TimeUnit.SECONDS)) process.destroyForcibly()
            }
            reader?.let(::joinReader)
            if (finished) process.exitValue() else -1
        } finally {
            if (process.isAlive) process.destroyForcibly()
            reader?.interrupt()
            runCatching { process.inputStream.close() }
            reader?.let(::joinReader)
            synchronized(processes) { processes -= process }
        }
    }

    private fun joinReader(reader: Thread) {
        try {
            reader.join(3000)
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
        }
    }

    private fun tailKsuLog(logFile: File, offset: AtomicLong, onLog: (String) -> Unit) {
        if (!logFile.isFile) return
        synchronized(offset) {
            runCatching {
                RandomAccessFile(logFile, "r").use { file ->
                    val position = offset.get().takeIf { it <= file.length() } ?: 0L
                    file.seek(position)
                    var lastComplete = position
                    val pending = StringBuilder()
                    while (true) {
                        val byte = file.read()
                        if (byte == -1) break
                        if (byte == '\n'.code) {
                            if (pending.isNotEmpty()) onLog(pending.toString())
                            pending.clear()
                            lastComplete = file.filePointer
                        } else {
                            pending.append(byte.toChar())
                        }
                    }
                    offset.set(lastComplete)
                }
            }
        }
    }

    private val processes = mutableSetOf<Process>()

}
