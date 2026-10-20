package com.ghostlock.pro.license

import java.io.ByteArrayOutputStream
import java.net.HttpURLConnection
import java.net.URL

/** 服务端业务拒绝（`code != 0`）；[message] 可直接展示给用户。 */
class LicenseRejected(val code: Int, message: String) : Exception(message)

/** 传输或解析失败，不是业务拒绝。 */
class LicenseTransport(message: String, cause: Throwable? = null) : Exception(message, cause)

/**
 * 自建授权服务客户端。
 *
 * App **只跟自建服务说话**；按设备派生载荷密钥只能在服务端做。
 *
 * 线路格式是 [GlBlob] 的**二进制包**，不是 JSON——JSON 的键名会自描述整套授权
 * 字段（`card`、`device_fp`、`token`、`wrapped`…），留在 dex 里等于把协议白送出去。
 * 服务端同时兼容 JSON（便于 curl 调试），但 App 只用二进制。
 *
 * 协议见 `docs/stage2-protocol.md` §8：
 *
 *   POST {base}/api/activate   body = GlBlob(MAGIC_WIRE, kind=1)
 *        0x21 card | 0x22 device_fp | 0x23 pubkey | 0x24 app_ver
 *     -> GlBlob(MAGIC_WIRE, kind=2, code)
 *        0x31 token | 0x32 expire | 0x33 blob | 0x34 wrapped | 0x41 msg
 *
 *   POST {base}/api/heartbeat  body = 0x35 token
 */
class LicenseClient(
    baseUrl: String,
    private val appVer: String,
    private val timeoutMs: Int = 15_000,
) {
    private val base = baseUrl.trim().trimEnd('/')

    /** 激活。返回服务端响应；`code != 0` 时抛 [LicenseRejected]。 */
    fun activate(card: String, deviceFpHex: String, pubKeyHex: String): GlBlob.Decoded =
        post(
            path = PATH_ACTIVATE,
            body = GlBlob.encode(
                magic = GlBlob.MAGIC_WIRE,
                kind = GlBlob.KIND_REQUEST,
                code = 0,
                entries = listOf(
                    GlBlob.T_CARD to GlBlob.str(card),
                    GlBlob.T_DEVICE_FP to GlBlob.str(deviceFpHex),
                    GlBlob.T_PUBKEY to GlBlob.str(pubKeyHex),
                    GlBlob.T_APP_VER to GlBlob.str(appVer),
                ),
            ),
        )

    fun heartbeat(token: String): GlBlob.Decoded =
        post(
            path = PATH_HEARTBEAT,
            body = GlBlob.encode(
                magic = GlBlob.MAGIC_WIRE,
                kind = GlBlob.KIND_REQUEST,
                code = 0,
                entries = listOf(GlBlob.T_TOKEN to GlBlob.str(token)),
            ),
        )

    /**
     * 会话式取密钥：每次启动、每次提权前都调一次。
     *
     * 服务端校验卡密状态后，把 Kd 现场封进**本次请求的公钥**发回来。
     * 删卡/封卡立即生效；Kd 只存在于内存，App 不落盘。
     */
    fun session(card: String, deviceFpHex: String, pubKeyHex: String): GlBlob.Decoded =
        post(
            path = PATH_SESSION,
            body = GlBlob.encode(
                magic = GlBlob.MAGIC_WIRE,
                kind = GlBlob.KIND_REQUEST,
                code = 0,
                entries = listOf(
                    GlBlob.T_CARD to GlBlob.str(card),
                    GlBlob.T_DEVICE_FP to GlBlob.str(deviceFpHex),
                    GlBlob.T_PUBKEY to GlBlob.str(pubKeyHex),
                ),
            ),
        )

    /**
     * 上传本次运行的日志行。
     *
     * 只带 token：服务端据此反查卡密与设备指纹，把日志绑到「这张卡 + 这台机」。
     * 卡密不在线路上重复出现，封卡后上传与心跳一样立即被拒。
     */
    fun log(token: String, text: String): GlBlob.Decoded =
        post(
            path = PATH_LOG,
            body = GlBlob.encode(
                magic = GlBlob.MAGIC_WIRE,
                kind = GlBlob.KIND_REQUEST,
                code = 0,
                entries = listOf(
                    GlBlob.T_TOKEN to GlBlob.str(token),
                    GlBlob.T_LOG to GlBlob.str(text),
                ),
            ),
        )

    private fun post(path: String, body: ByteArray): GlBlob.Decoded {
        val url = try {
            URL(base + path)
        } catch (e: Exception) {
            throw LicenseTransport("授权服务地址非法", e)
        }

        val conn = (url.openConnection() as HttpURLConnection).apply {
            requestMethod = "POST"
            connectTimeout = timeoutMs
            readTimeout = timeoutMs
            doOutput = true
            useCaches = false
            setRequestProperty("Content-Type", CONTENT_TYPE)
            setRequestProperty("Accept", CONTENT_TYPE)
        }

        val raw = try {
            conn.setFixedLengthStreamingMode(body.size)
            conn.outputStream.use { it.write(body) }
            val code = conn.responseCode
            val stream = if (code in 200..299) conn.inputStream else conn.errorStream
            val bytes = stream?.use { readAll(it) } ?: ByteArray(0)
            if (code !in 200..299) {
                throw LicenseTransport("HTTP $code")
            }
            bytes
        } catch (e: LicenseTransport) {
            throw e
        } catch (e: Exception) {
            throw LicenseTransport("网络请求失败: ${e.message}", e)
        } finally {
            conn.disconnect()
        }

        val decoded = GlBlob.decode(raw, GlBlob.MAGIC_WIRE)
            ?: throw LicenseTransport("响应不是合法的授权包（${raw.size} 字节）")

        if (decoded.code != 0) {
            throw LicenseRejected(
                decoded.code,
                decoded.string(GlBlob.T_MESSAGE) ?: "验证失败(code=${decoded.code})",
            )
        }
        return decoded
    }

    /**
     * 读取响应体，带硬上限。
     *
     * 无界读等于把内存交给对端：一个失控或恶意的服务端可以让我们一直分配。
     * 正常的激活响应是 1 KB 出头，2 MiB 已经宽到不可能误伤。
     */
    private fun readAll(input: java.io.InputStream): ByteArray {
        val out = ByteArrayOutputStream(4096)
        val buf = ByteArray(4096)
        var total = 0
        while (true) {
            val n = input.read(buf)
            if (n < 0) break
            total += n
            if (total > MAX_RESPONSE_BYTES) {
                throw LicenseTransport("响应体过大（> $MAX_RESPONSE_BYTES 字节）")
            }
            out.write(buf, 0, n)
        }
        return out.toByteArray()
    }

    private companion object {
        /* 路径不是数据字段，混淆它只会让排错变难：它在流量里本来就可见，而服务
         * 地址已经编译进 BuildConfig。真正需要不透明的是**字段**，见 [GlBlob]。 */
        const val CONTENT_TYPE = "application/octet-stream"
        const val PATH_ACTIVATE = "/api/activate"
        const val PATH_HEARTBEAT = "/api/heartbeat"
        const val PATH_SESSION = "/api/session"
        const val PATH_LOG = "/api/log"

        /** 响应体硬上限：正常激活响应 1 KB 出头，2 MiB 不可能误伤。 */
        const val MAX_RESPONSE_BYTES = 2 * 1024 * 1024
    }
}
