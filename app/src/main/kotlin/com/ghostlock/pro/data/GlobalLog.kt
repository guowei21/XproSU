package com.ghostlock.pro.data

import android.content.Context
import java.io.File
import java.io.RandomAccessFile
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * 全局日志：跨运行、跨组件的一份流水。
 *
 * 与 [DeviceLogStore] 的区别：device.log 只收运行日志，用来在卡死后补交；
 * 这里还收 WebUI 的控制台输出、每个失败的 HTTP 接口、以及 App 自己的错误，
 * 用来查「页面能打开但功能没有」这类问题——这种情况在单次运行日志里看不到。
 *
 * 单文件 2 MB，超过滚成 `.1`；每行 fsync，崩溃重启后仍可读。
 */
class GlobalLog private constructor(context: Context) {

    private val file = File(context.filesDir, FILE_NAME)
    private val rotated = File(context.filesDir, "$FILE_NAME.1")
    private val lock = Any()
    private val stamp = SimpleDateFormat("MM-dd HH:mm:ss.SSS", Locale.US)

    fun append(tag: String, message: String) {
        val text = message.replace("\r", "").replace("\n", "\\n")
        val line = "${stamp.format(Date())} [$tag] $text\n"
        synchronized(lock) {
            try {
                if (file.length() > MAX_BYTES) {
                    rotated.delete()
                    if (!file.renameTo(rotated)) file.delete()
                }
                RandomAccessFile(file, "rw").use { raf ->
                    raf.seek(raf.length())
                    raf.write(line.toByteArray(Charsets.UTF_8))
                    raf.fd.sync()
                }
            } catch (_: Exception) {
                // 日志失败不能影响主流程
            }
        }
    }

    fun tail(maxLines: Int): List<String> {
        synchronized(lock) {
            if (!file.isFile) return emptyList()
            return try {
                file.readLines()
                    .filter { it.isNotBlank() }
                    .takeLast(maxLines)
            } catch (_: Exception) {
                emptyList()
            }
        }
    }

    fun clear() {
        synchronized(lock) {
            runCatching { file.delete() }
            runCatching { rotated.delete() }
        }
    }

    fun fileSize(): Long = runCatching { file.length() }.getOrDefault(0L)

    companion object {
        private const val FILE_NAME = "global.log"
        private const val MAX_BYTES = 2L * 1024 * 1024

        @Volatile
        private var instance: GlobalLog? = null

        fun get(context: Context): GlobalLog =
            instance ?: synchronized(this) {
                instance ?: GlobalLog(context.applicationContext).also { instance = it }
            }
    }
}
