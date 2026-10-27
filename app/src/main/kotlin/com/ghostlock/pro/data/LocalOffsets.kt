package com.ghostlock.pro.data

import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * 本地偏移解密。
 *
 * 公开版没有授权服务，偏移表只能随 APK 走。它不以明文存放：`assets/offsets.enc`
 * 是 AES-256-GCM 密封的 offsets JSON，运行时在设备上解开，写成引擎认识的
 * `<files>/offsets.json`，由引擎的 `offsets.json` 导入路径读入。
 *
 * 这是混淆，不是保密：密钥推导就在 App 里，反编译可以复现。要「APK 里拿不到表」
 * 就必须有服务端持有密钥，而这正是本版去掉的东西。
 */
internal object LocalOffsets {

    /** 文件头；同时作为 GCM 的 AAD，改头就会解不开。 */
    private val Magic = "XSO1".toByteArray(Charsets.US_ASCII)
    private const val NonceSize = 12
    private const val TagBits = 128

    private val key: ByteArray by lazy {
        MessageDigest.getInstance("SHA-256")
            .digest("XproSU/local-offsets/v1".toByteArray(Charsets.UTF_8))
    }

    /**
     * 解开 `assets/offsets.enc`。
     *
     * 失败一律抛异常：读到一半的表比没有表更危险，调用方必须把这次运行中止，
     * 而不是退回某个猜测值。
     */
    fun decrypt(blob: ByteArray): ByteArray {
        val header = Magic.size + NonceSize
        require(blob.size > header + TagBits / 8) { "offsets asset is truncated" }
        require(blob.copyOfRange(0, Magic.size).contentEquals(Magic)) {
            "offsets asset has a foreign magic"
        }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(
            Cipher.DECRYPT_MODE,
            SecretKeySpec(key, "AES"),
            GCMParameterSpec(TagBits, blob, Magic.size, NonceSize),
        )
        cipher.updateAAD(Magic)
        return cipher.doFinal(blob, header, blob.size - header)
    }
}
