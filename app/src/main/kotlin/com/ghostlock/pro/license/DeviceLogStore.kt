package com.ghostlock.pro.license

import android.content.Context
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * 本机运行日志落盘。
 *
 * 服务端只保留 24 小时；而「跑到 14% 卡死、强制重启」这一类故障发生时，App 进程
 * 随时可能被杀掉——还留在内存队列里没发出去的行就永远消失了。所以每一行在入队的
 * 同时写一份到这里，重启后由用户点「立即上传」补交。
 *
 * 只服务排障，不做审计：单文件上限 512 KiB，超过就滚成 `.1` 重新开始，从不无限增长。
 */
class DeviceLogStore(context: Context) {

    private val file = File(context.filesDir, FILE_NAME)
    private val rotated = File(context.filesDir, "$FILE_NAME.1")
    private val lock = Any()
    private val stamp = SimpleDateFormat("MM-dd HH:mm:ss", Locale.US)

    /** 追加一行；任何 IO 失败都被吞掉——日志不能拖累运行路径。 */
    fun append(line: String) {
        synchronized(lock) {
            try {
                if (file.length() > MAX_BYTES) {
                    rotated.delete()
                    if (!file.renameTo(rotated)) file.delete()
                }
                file.appendText("${stamp.format(Date())} $line\n")
            } catch (_: Exception) {
                // 磁盘满 / 无权限：放弃这一行，不影响激活和提权
            }
        }
    }

    /** 读取最近 [maxLines] 行，用于手动上传。 */
    fun readTail(maxLines: Int = 800): List<String> {
        synchronized(lock) {
            if (!file.isFile) return emptyList()
            return try {
                file.readLines().takeLast(maxLines)
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
