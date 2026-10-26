package com.ghostlock.pro.data

import android.content.Context
import java.io.File
import java.io.RandomAccessFile
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * 本机运行日志落盘。
 *
 * 「跑到 14% 卡死、强制重启」这一类故障发生时，App 进程随时可能被杀掉——还留在
 * 内存里的行就永远消失了。所以每一行在展示的同时写一份到这里，重启后仍能取出来
 * 复制给开发者。
 *
 * 只服务排障，不做审计：单文件上限 512 KiB，超过就滚成 `.1` 重新开始，从不无限增长。
 * 公开版没有服务端，日志只留在本机。
 */
class DeviceLogStore(context: Context) {

    private val file = File(context.filesDir, FILE_NAME)
    private val rotated = File(context.filesDir, "$FILE_NAME.1")
    private val lock = Any()
    private val stamp = SimpleDateFormat("MM-dd HH:mm:ss", Locale.US)

    /** 追加一行；任何 IO 失败都被吞掉——日志不能拖累运行路径。 */
    fun append(line: String) {
        val bytes = "${stamp.format(Date())} $line\n".toByteArray(Charsets.UTF_8)
        synchronized(lock) {
            try {
                if (file.length() > MAX_BYTES) {
                    rotated.delete()
                    if (!file.renameTo(rotated)) file.delete()
                }
                RandomAccessFile(file, "rw").use { raf ->
                    raf.seek(raf.length())
                    raf.write(bytes)
                    // f2fs 崩溃回滚会保留文件长度却把未落盘的数据变成 0。卡死重启
                    // 正是我们要救的场景，所以每行都 fsync，别指望 page cache。
                    raf.fd.sync()
                }
            } catch (_: Exception) {
                // 磁盘满 / 无权限：放弃这一行，不影响提权
            }
        }
    }

    /** 读取最近 [maxLines] 行，用于导出。空行和 NUL 填充都丢掉。 */
    fun readTail(maxLines: Int = 800): List<String> {
        synchronized(lock) {
            if (!file.isFile) return emptyList()
            return try {
                file.readLines()
                    .asSequence()
                    .filter { it.replace("\u0000", "").isNotBlank() }
                    .toList()
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

    private companion object {
        const val FILE_NAME = "device.log"
        const val MAX_BYTES = 512 * 1024L
    }
}
