package com.xprosu.adb

import android.content.Context
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.callbackFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.util.UUID

/**
 * 在 ADB 之上拼出 exploit 需要的四种 I/O：一次性命令、后台启动、长驻日志跟随、文件上传。
 *
 * libadb-android 只提供原始 "shell:" / "sync:" 流，没有 exit code、没有 sync 封装，
 * 这里逐个补上。日志不再按 1Hz 反复打开文件，
 * 而是 exploit 启动前就打开一个 tail 流一直读，这在 timer-slab 释放窗口里很重要。
 *
 * 所有阻塞 I/O 都放在 Dispatchers.IO。
 */
object AdbTransport {

    data class ExecResult(
        val code: Int,
        val output: String,
        val timedOut: Boolean = false
    )

    private const val DEFAULT_TIMEOUT_MS = 20_000L
    private const val DEFAULT_LIMIT = 256 * 1024

    @Volatile
    private var appContext: Context? = null

    fun attach(context: Context) {
        appContext = context.applicationContext
    }

    private fun bridge(): AdbBridge {
        val ctx = appContext ?: throw IllegalStateException("AdbTransport 未初始化")
        return AdbBridge.get(ctx)
    }

    // ------------------------------------------------------------ 一次性命令

    /**
     * 执行命令并取回退出码。shell: 流本身不返回 exit code，
     * 所以在命令末尾打一个哨兵，从输出里把码切出来。
     */
    suspend fun exec(
        cmd: String,
        timeoutMs: Long = DEFAULT_TIMEOUT_MS,
        limit: Int = DEFAULT_LIMIT,
        lingerMs: Long = 0
    ): ExecResult = withContext(Dispatchers.IO) {
        val marker = "__XPROSU_RC_" + UUID.randomUUID().toString().replace("-", "") + "__"
        // 子 shell 包一层：cd/env 不污染，且拿到的是整条命令的退出码
        val wrapped = "(" + cmd + ") 2>&1; echo; echo " + marker + "\$?"

        android.util.Log.i("XproSU", "exec open: " + cmd.take(48))
        val stream = bridge().openStream("shell:" + wrapped)
        android.util.Log.i("XproSU", "exec opened: " + cmd.take(24))
        val input: InputStream = stream.openInputStream()
        val buffer = ByteArrayOutputStream()
        val buf = ByteArray(8192)
        var timedOut = false

        val watchdog: Job = CoroutineScope(Dispatchers.IO).launch {
            delay(timeoutMs)
            timedOut = true
            runCatching { stream.close() }
        }

        try {
            while (buffer.size() < limit) {
                val n = input.read(buf)
                if (n <= 0) break
                buffer.write(buf, 0, n)
                if (buffer.toString("UTF-8").contains(marker + "0")) break
            }
        } catch (e: Exception) {
            if (!timedOut) throw e
        } finally {
            watchdog.cancel()
            // 后台启动时不要在流上立刻发 CLSE：adbd 收到关闭会顺手收掉这个 shell 的
            // 进程组，而 setsid 还没来得及把子进程挪进新会话（真机上表现为日志 0 字节、
            // 进程凭空消失）。先按住一段时间，等子进程完成 setsid。
            if (lingerMs > 0) delay(lingerMs)
            runCatching { stream.close() }
        }

        android.util.Log.i("XproSU", "exec eof: " + cmd.take(24) + " bytes=" + buffer.size())
        val text = buffer.toString("UTF-8").replace("\r\n", "\n")
        val idx = text.lastIndexOf(marker)
        if (idx < 0) {
            android.util.Log.w("XproSU", "exec 无哨兵 timedOut=" + timedOut + " out=" + text.take(400))
            ExecResult(-2, text.trimEnd('\n'), timedOut)
        } else {
            val code = text.substring(idx + marker.length).trim().toIntOrNull() ?: -1
            val body = text.substring(0, idx).trimEnd('\n')
            ExecResult(code, body, timedOut)
        }
    }

    /** 失败即抛异常，用于关键步骤。 */
    suspend fun execOrThrow(cmd: String, timeoutMs: Long = DEFAULT_TIMEOUT_MS): String {
        val result = exec(cmd, timeoutMs)
        if (result.timedOut) throw IllegalStateException("命令超时：" + cmd)
        if (result.code != 0) {
            throw IllegalStateException("命令失败(" + result.code + ")：" + cmd + "\n" + result.output)
        }
        return result.output
    }

    // -------------------------------------------------------------- 后台启动

    /**
     * 后台拉起脚本，返回 pid。脚本 stdout/stderr 全部重定向到 [logPath]，
     * stdin 接 /dev/null —— 否则 adbd 的 pty 会被后台进程占着，读流永远等不到 EOF。
     */
    suspend fun startDetached(
        script: String,
        logPath: String,
        env: Map<String, String> = emptyMap(),
        workDir: String = "/data/local/tmp"
    ): Int {
        val envPart = env.entries.joinToString(" ") { it.key + "=" + shellQuote(it.value) }
        // 日志文件由调用方预先创建（空文件），tail 流先打开再启动，见 MainViewModel.run()
        val cmd = "cd " + shellQuote(workDir) + " && " +
            "nohup env " + (if (envPart.isEmpty()) "" else envPart + " ") +
            "setsid /system/bin/sh " + shellQuote(script) +
            " >> " + shellQuote(logPath) + " 2>&1 < /dev/null & " +
            "echo __PID__\$!"
        // linger：命令里的 & 只是把这个 sh 放进后台，setsid 生效前进程仍属于 adbd 的
        // shell 会话；客户端一关流 adbd 会连带清掉进程组，脚本连第一行都写不出来。
        val result = exec(cmd, timeoutMs = 20_000, lingerMs = 1_500)
        val pid = Regex("__PID__(\\d+)").find(result.output)?.groupValues?.get(1)?.toIntOrNull()
        return pid ?: -1
    }

    // ------------------------------------------------------------ 日志跟随

    /**
     * 从 [offset] 字节起持续读取 [path]。返回的 Flow 在取消时关闭底层流，
     * 也就顺带杀掉 tail 进程。
     *
     * 注意：返回的流必须在 exploit 启动之前打开并保持，中途不要关掉重开——
     * 重新打开只会再分配一个 struct file。
     */
    fun tail(path: String, offset: Long = 0): Flow<ByteArray> =
        stream("exec tail -c +" + (offset + 1) + " -f " + shellQuote(path) + " 2>&1")

    /**
     * 在当前 shell 流里前台跑一条长命令，边跑边读输出。返回的 Flow 取消时关流，
     * adbd 随之收掉进程组。
     *
     * 这是唯一可靠的启动方式：把脚本丢后台（nohup/setsid/&）在无线调试下会随
     * 流关闭被 adbd 连带清掉，脚本连第一行都写不出来。
     */
    fun stream(cmd: String): Flow<ByteArray> = callbackFlow {
        android.util.Log.i("XproSU", "stream open: " + cmd.take(60))
        val stream = bridge().openStream("shell:" + cmd)
        val input = stream.openInputStream()
        android.util.Log.i("XproSU", "stream opened")
        // 空包表示"流已建立"：调用方据此在启动 exploit 之前确认 tail 已经在读
        trySend(ByteArray(0))

        val job = CoroutineScope(Dispatchers.IO).launch {
            val buf = ByteArray(8192)
            try {
                while (isActive) {
                    val n = input.read(buf)
                    if (n <= 0) break
                    android.util.Log.i("XproSU", "stream chunk=" + n)
                    if (!trySend(buf.copyOf(n)).isSuccess) {
                        android.util.Log.w("XproSU", "stream 通道满，主动断流")
                        break
                    }
                }
                android.util.Log.i("XproSU", "stream eof")
            } catch (e: Exception) {
                // 流被正常关闭时会抛 "Stream closed."，不算错误
                android.util.Log.i("XproSU", "stream 读取结束: " + e.message)
            } finally {
                close()
            }
        }

        awaitClose {
            job.cancel()
            runCatching { stream.close() }
        }
    }

    // -------------------------------------------------------------- 文件上传

    /**
     * 上传文件。
     *
     * 不走 sync: SEND —— libadb 的写路径在无线调试下会永久阻塞：每次 write 只拿到
     * 一个 OKAY 令牌，adbd 之后不再回 OKAY，第二个数据帧就卡死在 mWriteReady 上。
     * 改用 shell 侧 base64 追加：命令体放在 OPEN 包里，全程不写数据帧。
     */
    suspend fun pushFile(
        bytes: ByteArray,
        remotePath: String,
        mode: Int = 0x1a4 // 0644
    ) {
        pushViaShell(bytes, remotePath, mode)
    }

    /** 兼容旧调用：把流读全，再走 shell 上传。 */
    suspend fun pushStream(
        source: InputStream,
        size: Long,
        remotePath: String,
        mode: Int = 0x1a4 // 0644
    ) {
        val bytes = source.readBytes()
        require(bytes.size.toLong() == size) {
            "上传长度不符：声明 " + size + "，实际 " + bytes.size
        }
        pushViaShell(bytes, remotePath, mode)
    }

    private suspend fun pushViaShell(bytes: ByteArray, remotePath: String, mode: Int) {
        execOrThrow(": > " + shellQuote(remotePath))
        val b64 = android.util.Base64.encodeToString(bytes, android.util.Base64.NO_WRAP)
        var at = 0
        while (at < b64.length) {
            val end = minOf(at + 48 * 1024, b64.length)
            execOrThrow("printf '%s' '" + b64.substring(at, end) + "' | base64 -d >> " + shellQuote(remotePath))
            at = end
        }
        execOrThrow("chmod " + Integer.toOctalString(mode) + " " + shellQuote(remotePath))
        val got = execOrThrow("stat -c %s " + shellQuote(remotePath)).trim().toLongOrNull() ?: -1L
        if (got != bytes.size.toLong()) {
            throw IllegalStateException(
                "上传校验失败：" + remotePath + " 期望 " + bytes.size + " 实际 " + got
            )
        }
        android.util.Log.i("XproSU", "push ok: " + remotePath + " bytes=" + got)
    }

    private fun concat(vararg parts: ByteArray): ByteArray {
        var total = 0
        for (p in parts) total += p.size
        val out = ByteArray(total)
        var at = 0
        for (p in parts) {
            System.arraycopy(p, 0, out, at, p.size)
            at += p.size
        }
        return out
    }

    private fun readSyncStatus(input: InputStream, stage: String) {
        val head = ByteArray(4)
        var read = 0
        while (read < 4) {
            val n = input.read(head, read, 4 - read)
            if (n <= 0) throw IllegalStateException("sync " + stage + " 读取失败")
            read += n
        }
        val id = String(head, Charsets.US_ASCII)
        if (id == "OKAY") return
        if (id == "FAIL") {
            val lenBuf = ByteArray(4)
            var got = 0
            while (got < 4) {
                val n = input.read(lenBuf, got, 4 - got)
                if (n <= 0) break
                got += n
            }
            val len = le32ToInt(lenBuf)
            val message = if (len > 0 && len < 4096) {
                val msg = ByteArray(len)
                var m = 0
                while (m < len) {
                    val n = input.read(msg, m, len - m)
                    if (n <= 0) break
                    m += n
                }
                String(msg, Charsets.UTF_8)
            } else "未知原因"
            throw IllegalStateException("sync " + stage + " 失败：" + message)
        }
        throw IllegalStateException("sync " + stage + " 响应异常：" + id)
    }

    private fun le32(value: Int): ByteArray = byteArrayOf(
        (value and 0xff).toByte(),
        ((value ushr 8) and 0xff).toByte(),
        ((value ushr 16) and 0xff).toByte(),
        ((value ushr 24) and 0xff).toByte()
    )

    private fun le32ToInt(bytes: ByteArray): Int {
        if (bytes.size < 4) return 0
        return (bytes[0].toInt() and 0xff) or
            ((bytes[1].toInt() and 0xff) shl 8) or
            ((bytes[2].toInt() and 0xff) shl 16) or
            ((bytes[3].toInt() and 0xff) shl 24)
    }

    // ---------------------------------------------------------------- 工具

    fun shellQuote(value: String): String = "'" + value.replace("'", "'\\''") + "'"
}
