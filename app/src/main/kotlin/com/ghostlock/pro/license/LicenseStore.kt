package com.ghostlock.pro.license

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * 本地授权凭据存储。
 *
 * 落盘内容用 Android Keystore 里的 AES-GCM 密钥加密后再写入 SharedPreferences：
 * 密钥不出 TEE/StrongBox，明文授权信息不落盘，改文件也无法伪造授权。
 *
 * 明文形态是 [GlBlob] 的二进制记录（定长头 + 不透明标签），**不是 JSON**——
 * 字段名留在 dex 里等于把数据结构白送出去。
 *
 * 存的是「本机专属凭据」：卡密 + 本机标识 + 服务端 token + 到期信息。
 * 换机器后本机标识不匹配，凭据直接作废，配合服务端校验实现一机一码。
 */
class LicenseStore(context: Context) {

    private val prefs = context.applicationContext
        .getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    fun save(record: LicenseRecord) {
        prefs.edit().putString(KEY_BLOB, encrypt(record.toBlob())).apply()
    }

    fun load(): LicenseRecord? {
        val blob = prefs.getString(KEY_BLOB, null) ?: return null
        return try {
            LicenseRecord.fromBlob(decrypt(blob))
        } catch (_: Exception) {
            // 密钥失效（清数据/换机）或内容被改动 —— 一律视为未授权。
            clear()
            null
        }
    }

    fun clear() {
        // Kd 不再落盘；清理 `p` 只是为了让从旧版本升级上来的设备不残留旧密钥。
        prefs.edit().remove(KEY_BLOB).remove(KEY_PAYLOAD).apply()
    }

    private fun encrypt(plain: ByteArray): String {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, secretKey())
        val iv = cipher.iv
        val ct = cipher.doFinal(plain)
        return Base64.encodeToString(iv + ct, Base64.NO_WRAP)
    }

    private fun decrypt(blob: String): ByteArray {
        val all = Base64.decode(blob, Base64.NO_WRAP)
        val iv = all.copyOfRange(0, IV_LEN)
        val ct = all.copyOfRange(IV_LEN, all.size)
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, secretKey(), GCMParameterSpec(TAG_BITS, iv))
        return cipher.doFinal(ct)
    }

    private fun secretKey(): SecretKey {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        (keyStore.getEntry(KEY_ALIAS, null) as? KeyStore.SecretKeyEntry)?.let { return it.secretKey }

        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        generator.init(
            KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build(),
        )
        return generator.generateKey()
    }

    private companion object {
        const val ANDROID_KEYSTORE = "AndroidKeyStore"

        // Keystore 别名与 SharedPreferences 文件名同样不外露用途：直接用摘要当名字，
        // 字面量本身不出现在 dex 里。
        val KEY_ALIAS: String = "gla_" + Integer.toHexString(0x5F3A2C71)
        val PREFS_NAME: String = "gls_" + Integer.toHexString(0x1D9E4B02)

        const val TRANSFORMATION = "AES/GCM/NoPadding"
        const val IV_LEN = 12
        const val TAG_BITS = 128
        const val KEY_BLOB = "b"
        const val KEY_PAYLOAD = "p"
    }
}

const val STATE_DISABLED = 0
const val STATE_ENABLED = 1
const val STATE_TRIAL = 2

private fun formatExpireSeconds(seconds: Long): String {
    if (seconds <= 0L) return ""
    return java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss", java.util.Locale.US)
        .format(java.util.Date(seconds * 1000))
}

/**
 * 本机授权凭据。字段全部来自服务端返回，本地不做信任推导。
 *
 * [state] 现在是 u8：`1` = 付费激活，`2` = 试用中，`0` = 已停用；
 * [expireAt] 是 unix 秒（u64），`0` = 永久。二者不再以展示字符串落盘。
 */
data class LicenseRecord(
    val deviceId: String,
    val cardKey: String,
    val token: String,
    val state: Int,
    val expireAt: Long,
    val activatedAt: Long,
) {
    /** 供 UI 展示的到期时间；永久授权为空字符串。 */
    val expiry: String get() = formatExpireSeconds(expireAt)

    val trial: Boolean get() = state == STATE_TRIAL

    /**
     * 脱敏：`data class` 默认实现会把卡密与 token 原样打出来。
     *
     * 现在没有任何调用点会打印它，但日志是后来最容易加上去的东西 —— 与其指望
     * 以后没人手滑，不如让这个对象天生打不出秘密。
     */
    override fun toString(): String =
        "LicenseRecord(deviceId=$deviceId, cardKey=***, token=***, state=$state, " +
                "expireAt=$expireAt, activatedAt=$activatedAt)"

    /** 序列化为 [GlBlob] 二进制记录（标签不透明，无字段名）。 */
    fun toBlob(): ByteArray = GlBlob.encode(
        magic = GlBlob.MAGIC_RECORD,
        kind = GlBlob.KIND_RESPONSE,
        code = 0,
        entries = listOf(
            GlBlob.R_DEVICE_ID to GlBlob.str(deviceId),
            GlBlob.R_CARD_KEY to GlBlob.str(cardKey),
            GlBlob.R_TOKEN to GlBlob.str(token),
            GlBlob.R_STATE to GlBlob.u8(state),
            GlBlob.R_EXPIRY to GlBlob.u64(expireAt),
            GlBlob.R_ACTIVATED_AT to GlBlob.u64(activatedAt),
        ),
    )

    companion object {
        fun fromBlob(bytes: ByteArray): LicenseRecord? {
            val decoded = GlBlob.decode(bytes, GlBlob.MAGIC_RECORD) ?: return null

            // 0x55 由字符串改为 u64、0x54 由字符串改为 u8（不兼容变更）：
            // 旧记录的 state/expire 无法解析成合法值，这里一律当作未授权。
            val state = decoded.u8(GlBlob.R_STATE)
                ?.takeIf { it == STATE_DISABLED || it == STATE_ENABLED || it == STATE_TRIAL }
                ?: return null
            val expireAt = decoded.long(GlBlob.R_EXPIRY) ?: return null
            val activatedAt = decoded.long(GlBlob.R_ACTIVATED_AT) ?: return null
            return LicenseRecord(
                deviceId = decoded.string(GlBlob.R_DEVICE_ID).orEmpty(),
                cardKey = decoded.string(GlBlob.R_CARD_KEY).orEmpty(),
                token = decoded.string(GlBlob.R_TOKEN).orEmpty(),
                state = state,
                expireAt = expireAt,
                activatedAt = activatedAt,
            )
        }
    }
}
