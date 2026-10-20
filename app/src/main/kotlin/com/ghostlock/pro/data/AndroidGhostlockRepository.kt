package com.ghostlock.pro.data

import android.annotation.SuppressLint
import android.content.Context
import android.os.Build
import android.system.Os
import com.ghostlock.pro.BuildConfig
import com.ghostlock.pro.domain.model.CpuPair
import com.ghostlock.pro.domain.model.KernelSnapshot
import com.ghostlock.pro.domain.model.OffsetImportResult
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
 * The three licence values are injected as providers rather than reached for
 * directly, so this layer stays independent of the licence package: the engine
 * needs them, but it does not need to know where they came from.
 */
class AndroidGhostlockRepository(
    context: Context,
    /** 32-byte per-device payload key `Kd`; null while the device is not activated. */
    private val payloadKey: () -> ByteArray?,
    /** This handset's 32-byte fingerprint, hex. */
    private val deviceFpHex: () -> String,
    /** First 16 bytes of SHA-256(card key), hex. The engine checks it against the container. */
    private val cardTagHex: () -> String?,
) : GhostlockRepository {
    private companion object {
        const val OffsetsFileName = "offsets.glt"
        const val KsuLogName = ".ghostlock_ksu.log"

        // Stage-2 container: 64-byte header, AEAD payload, no fixed key anywhere.
        // See docs/stage2-protocol.md section 5.
        const val GltVersion = 2
        const val GltFlagAead = 0x02
        const val GltHeaderSize = 64
        const val GltMaxSize = 1 shl 20
        val GltMagic = byteArrayOf(0x47, 0x4C, 0x54, 0x32) // "GLT2"
        val Glt1Magic = byteArrayOf(0x47, 0x4C, 0x54, 0x31) // "GLT1"
        const val OFFLINE_ASSET = "offsets.glt"
        const val OFFLINE_MODE = true
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
     * Make sure `<files>/offsets.glt` holds a usable container, releasing the
     * packaged one out of the APK when it does not.
     *
     * The packaged container is the authoritative copy -- there is no install
     * step, the engine simply decrypts whatever lands here.  A cached file is
     * reused only while its header still checks out, so a truncated or foreign
     * file cannot wedge the run path: it is replaced on the next attempt.
     *
     * The app never parses the payload.  It used to write a plaintext
     * offsets.json here, so the whole table sat in the app's private directory
     * in a form anyone with a file browser could read and forward
     * (ENCRYPTION-PLAN.md section 1, leaks 2 and 7).  The container is opaque:
     * the copy is useless without the engine's decode step.
     */
    /**
     * The container now arrives from the licence server, not from `assets/`.
     *
     * Stage 1 shipped a copy of the table inside the APK; stage 2 ships nothing,
     * so this only validates whatever the activation flow already wrote.  A
     * missing or malformed file is a hard stop: the engine has no fallback table
     * and must not grow one.
     */
    private fun ensureOffsetsBlob(): Boolean = hasValidBlobHeader(offsetsFile)

    /**
     * 离线分支：把 APK 内置的 GLT1 容器释放到 filesDir。
     *
     * GLT1 由编译进引擎的固定 key 做混淆，不带设备绑定，也不需要服务端下发；
     * 随包分发意味着任何拿到 APK 的人都能解出偏移表——这是离线版的取舍。
     */
    private fun ensureOfflineContainer(): Boolean {
        return try {
            val bytes = appContext.assets.open(OFFLINE_ASSET).use { it.readBytes() }
            if (bytes.size < 16 || !bytes.copyOfRange(0, 4).contentEquals(Glt1Magic)) {
                false
            } else {
                offsetsFile.writeBytes(bytes)
                true
            }
        } catch (_: Exception) {
            false
        }
    }

    /**
     * Header-only check: does this file look like a container for *this* card?
     *
     * The app cannot verify the payload -- it holds no key -- and does not need
     * to: the engine re-checks the whole table against its gate set before it
     * uses a single address.  What it can do cheaply is refuse a container that
     * belongs to another device or another card, so the failure surfaces here
     * rather than as a decryption error.
     */
    private fun hasValidBlobHeader(file: File): Boolean {
        if (file.length() < GltHeaderSize) return false
        val head = try {
            file.inputStream().use { it.readBytes() }
        } catch (_: IOException) {
            return false
        }
        return validateBlob(head) is OffsetImportResult.Imported
    }

    /** Structural check of a container header; no key involved. */
    private fun validateBlob(bytes: ByteArray): OffsetImportResult {
        if (bytes.size < GltHeaderSize) {
            return OffsetImportResult.Failed("payload is too short")
        }
        if (!bytes.copyOfRange(0, 4).contentEquals(GltMagic)) {
            return OffsetImportResult.Failed("payload has a foreign magic")
        }
        if (bytes[4].toInt() != GltVersion) {
            return OffsetImportResult.Failed("unsupported payload version ${bytes[4]}")
        }
        if (bytes[5].toInt() and GltFlagAead == 0) {
            return OffsetImportResult.Failed("payload is not sealed")
        }
        if (bytes.size > GltMaxSize) {
            return OffsetImportResult.Failed("payload is too large")
        }

        // fail-closed：长度不对或 hex 非法都必须直接拒绝，不能把校验跳过。
        val fpBytes = decodeHex(deviceFpHex())
            ?: return OffsetImportResult.Failed("invalid device fingerprint")
        if (fpBytes.size != 32) {
            return OffsetImportResult.Failed("invalid device fingerprint length")
        }
        if (!bytes.copyOfRange(16, 48).contentEquals(fpBytes)) {
            return OffsetImportResult.Failed("payload is bound to another device")
        }
        val tag = decodeHex(cardTagHex() ?: return OffsetImportResult.Failed("missing card key"))
            ?: return OffsetImportResult.Failed("invalid card key digest")
        if (tag.size != 16) {
            return OffsetImportResult.Failed("invalid card key digest length")
        }
        if (!bytes.copyOfRange(48, 64).contentEquals(tag)) {
            return OffsetImportResult.Failed("payload is bound to another card key")
        }
        return OffsetImportResult.Imported
    }

    private fun decodeHex(hex: String): ByteArray? {
        if (hex.length % 2 != 0) return null
        val out = ByteArray(hex.length / 2)
        for (i in out.indices) {
            val hi = Character.digit(hex[i * 2], 16)
            val lo = Character.digit(hex[i * 2 + 1], 16)
            if (hi < 0 || lo < 0) return null
            out[i] = ((hi shl 4) or lo).toByte()
        }
        return out
    }

    override suspend fun importOffsets(bytes: ByteArray): OffsetImportResult = withContext(Dispatchers.IO) {
        val result = validateBlob(bytes)
        if (result !is OffsetImportResult.Imported) return@withContext result
        try {
            offsetsFile.writeBytes(bytes)
            result
        } catch (error: CancellationException) {
            throw error
        } catch (error: Exception) {
            OffsetImportResult.Failed(error.message ?: "cannot write offsets package")
        }
    }


    /**
     * 会话模式：session 由 ViewModel 在运行前现场向服务端取得（Kd + 容器），
     * 投喂给引擎后立即删除临时文件。传 null 时（Debug 旁路）走旧路径。
     */
    override suspend fun runExploit(
        pair: CpuPair,
        onLog: (String) -> Unit,
        session: com.ghostlock.pro.license.SessionKey?,
    ): Int {
        val workDir = filesDir
        return try {
            val binary = File(appContext.applicationInfo.nativeLibraryDir, "libghostlock.so")
            require(binary.isFile) { "missing native binary: " + binary.absolutePath }
            var sessionKd: ByteArray? = null
            if (session != null) {
                offsetsFile.writeBytes(session.blob)
                sessionKd = session.kd
            } else if (OFFLINE_MODE) {
                // 离线分支：释放随包 GLT1 容器，不需要服务端与会话密钥。
                if (!ensureOfflineContainer()) {
                    onLog("error: missing bundled offsets (" + OFFLINE_ASSET + ")")
                    return 1
                }
                sessionKd = ByteArray(0)
            } else {
                val kd0 = payloadKey()
                if (kd0 == null) {
                    if (BuildConfig.DEBUG) onLog("error: no license")
                    return 1
                }
                sessionKd = kd0
                if (!ensureOffsetsBlob()) {
                    if (BuildConfig.DEBUG) onLog("error: missing activation payload (" + OffsetsFileName + ")")
                    return 1
                }
            }
            val kd = sessionKd!!
            try {
                return runExploitInner(pair, onLog, kd, workDir, binary)
            } finally {
                if (session != null) {
                    // 容器与密钥都是一次性材料：用完立刻从磁盘与内存清掉。
                    runCatching { offsetsFile.delete() }
                    kd.fill(0)
                    session.kd.fill(0)
                }
            }
        } catch (error: CancellationException) {
            throw error
        } catch (error: Exception) {
            if (BuildConfig.DEBUG) onLog("error: " + (error::class.simpleName ?: "?") + ": " + error.message)
            1
        }
    }

    private suspend fun runExploitInner(
        pair: CpuPair,
        onLog: (String) -> Unit,
        kd: ByteArray,
        workDir: File,
        binary: File,
    ): Int {
        val keyHex = kd.joinToString("") { "%02x".format(it) }
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
                    // Stage 2: the container is sealed with a key that only this
                    // handset's licence can produce, so the engine needs both the
                    // key and this device's fingerprint to open it.
                    environment()["GHOSTLOCK_KEY"] = keyHex
                    environment()["GHOSTLOCK_DEVICE_FP"] = deviceFpHex()
                    // The card binding: the engine refuses the container unless this
                    // matches the AAD-covered header, so a build with the login
                    // screen patched out still cannot decrypt anything.
                    cardTagHex()?.let { environment()["GHOSTLOCK_CARD"] = it }
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
        // A packaged entry always counts: the engine validates it far more
        // strictly than the app could, and reports the reason if it refuses.
        // 会话模式下容器是临时文件（用完即删），不能用它判断内核是否支持。
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

    private fun prepareKsud(workDir: File, onLog: (String) -> Unit): File? {
        val packages = listOf("me.weishu.kernelsu.pr", "me.weishu.kernelsu", "com.resukisu.resukisu", "com.kowx712.supermanager")
        var installed = false
        for (packageName in packages) {
            val appInfo = runCatching { appContext.packageManager.getApplicationInfo(packageName, 0) }.getOrNull() ?: continue
            installed = true
            val source = File(appInfo.nativeLibraryDir, "libksud.so")
            if (!source.isFile) continue
            val output = File(workDir, "ksud")
            runCatching {
                source.inputStream().use { input -> output.outputStream().use { input.copyTo(it) } }
                runCatching { Os.chmod(output.absolutePath, 448) }
                return output
            }.onFailure { onLog("copy ksud failed: ${it.message}") }
        }
        if (!installed) onLog("KernelSU/ReSukiSU/KowSU app not installed")
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
