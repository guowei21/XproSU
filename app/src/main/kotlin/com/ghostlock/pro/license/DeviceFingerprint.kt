package com.ghostlock.pro.license

import android.content.Context
import android.media.MediaDrm
import android.util.Log
import java.util.UUID

/**
 * 本机身份。**只认硬件级 Widevine 设备 ID，没有退化路径。**
 *
 * 为什么不留退化方案：退化的 `SHA-256(ANDROID_ID | BRAND | MODEL | ...)` 里，
 * ANDROID_ID 在 Android 8+ 是**按签名 + 按用户**算的 —— 换一次签名重装就"变成
 * 一台新机器"，等于给「一机一号」「一机一次试用」开了个后门；顺带还会让
 * 同一个人的两台设备算出同一个身份。宁可在没有 Widevine 的机器上（模拟器、
 * 云手机）直接拒绝运行，也不要一个能被换签名刷掉的假身份。
 *
 * 两个值，用途严格分开：
 *
 *  - [raw]：**32 字节二进制**，唯一的密码学身份。它作为 HKDF 的 `info` 参与派生
 *    每台设备专属的载荷密钥，并且写进 GLT2 容器的头部。换设备 → 密钥不同 → 解不开。
 *  - [display]：给人看的 64 位大写 hex（与 [raw] 完全一致，也与服务端
 *    `device_fp`、管理端显示一致），只用于界面展示与人工核对，**不参与**
 *    任何密码学计算（密码学直接用 [raw] 二进制）。
 *
 * 两者取不到时都返回 `null`，调用方必须按「本机不支持」处理（fail-closed）。
 */
object DeviceFingerprint {

    private val WIDEVINE_UUID: UUID = UUID(-0x121074568629b532L, -0x5c37d8232ae2de13L)

    private const val TAG = "DeviceFingerprint"

    /** 本机 32 字节身份；取不到 Widevine 时为 null。 */
    fun raw(context: Context): ByteArray? = widevineRaw(context)

    /**
     * 供界面展示的本机标识：真实 Widevine ID 的 64 位大写 hex。
     *
     * 这是设备级身份（跨卸载重装/清数据/恢复出厂不变），客服据此对单。
     */
    fun display(context: Context): String? =
        raw(context)?.let { hex(it).uppercase() }

    /** 旧名字，等价于 [display]。 */
    fun of(context: Context): String? = display(context)

    /** 本机是否具备硬件级设备身份。整个授权链路的前置条件。 */
    fun supported(context: Context): Boolean = raw(context) != null

    fun hex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it) }

    fun fromHex(hex: String): ByteArray? {
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

    /** 原始 DRM ID 本身，32 字节。取不到返回 null，并在 Logcat 输出明确警告。 */
    private fun widevineRaw(context: Context): ByteArray? {
        if (!MediaDrm.isCryptoSchemeSupported(WIDEVINE_UUID)) {
            Log.w(TAG, "Widevine crypto scheme not supported on this device")
            return null
        }
        var drm: MediaDrm? = null
        return try {
            drm = MediaDrm(WIDEVINE_UUID)
            val id = drm.getPropertyByteArray(MediaDrm.PROPERTY_DEVICE_UNIQUE_ID)
            if (id == null || id.size != 32) {
                Log.w(TAG, "Widevine deviceUniqueId is null or size mismatch (got ${id?.size} bytes)")
                null
            } else {
                id
            }
        } catch (t: Throwable) {
            Log.w(TAG, "Failed to read Widevine deviceUniqueId for ${context.packageName}: ${t.message}", t)
            null
        } finally {
            drm?.let {
                runCatching { it.close() }
            }
        }
    }
}
