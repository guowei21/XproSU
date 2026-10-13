package com.ghostlock.pro.license

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * 设备侧 P-256 密钥对，私钥不可导出。
 *
 * 用途：把服务端下发的载荷密钥 `Kd` 包在只有本机能解的 ECIES 里。
 * 服务端拿本机公钥做一次性 ECDH，客户端在 TEE 内解出 `Kd`。
 *
 * 为什么不能直接收明文 `Kd`：自建授权服务多为 `http://`，明文密钥在线路上可被嗅探。
 * 包一层 ECDH 之后，即使流量被完整抓走，也只有持有本机私钥的设备能解出 `Kd`。
 *
 * 协议见 `docs/stage2-protocol.md` §6。
 */
class DeviceKey {

    /** 未压缩点 `0x04‖X(32)‖Y(32)`，65 字节。随激活请求上传。 */
    fun publicKey(): ByteArray {
        val pub = keyPair().public as ECPublicKey
        return byteArrayOf(0x04) +
                pad32(pub.w.affineX) +
                pad32(pub.w.affineY)
    }

    /**
     * 解开服务端包裹的 `Kd`。
     *
     * `wrapped = eph_pub(65) ‖ nonce(12) ‖ ct(32) ‖ tag(16)`，
     * `kek = HKDF-SHA256(ECDH_x, salt=SHA-256(cardKey), info="GL-KDW1", L=32)`，
     * `AAD = eph_pub`。
     *
     * 失败（换机、卡密不符、被篡改）时抛异常，调用方一律按"未授权"处理。
     */
    fun unwrap(wrapped: ByteArray, cardKey: String): ByteArray {
        require(wrapped.size == WRAPPED_SIZE) {
            "bad envelope length ${wrapped.size}"
        }
        val ephPub = wrapped.copyOfRange(0, 65)
        val nonce = wrapped.copyOfRange(65, 77)
        val ctAndTag = wrapped.copyOfRange(77, WRAPPED_SIZE)

        val shared = ecdh(ephPub)
        val kek = hkdfSha256(
            ikm = shared,
            salt = sha256(cardKey.toByteArray(Charsets.UTF_8)),
            info = "GL-KDW1".toByteArray(Charsets.US_ASCII),
            length = 32,
        )

        val cipher = Cipher.getInstance("ChaCha20/Poly1305/NoPadding")
        cipher.init(
            Cipher.DECRYPT_MODE,
            SecretKeySpec(kek, "ChaCha20"),
            IvParameterSpec(nonce),
        )
        cipher.updateAAD(ephPub)
        val kd = cipher.doFinal(ctAndTag)
        require(kd.size == 32) { "unwrapped Kd must be 32 bytes, got ${kd.size}" }
        return kd
    }
    private fun keyPair(): KeyPair {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        (keyStore.getEntry(ALIAS, null) as? KeyStore.PrivateKeyEntry)?.let {
            return KeyPair(it.certificate.publicKey, it.privateKey)
        }

        val generator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC,
            ANDROID_KEYSTORE,
        )
        return try {
            // 优先落 StrongBox；不支持/不可用时回退到普通 Keystore，而不是失败。
            generator.initialize(
                KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_AGREE_KEY)
                    .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                    .setIsStrongBoxBacked(true)
                    .build(),
            )
            generator.generateKeyPair()
        } catch (_: StrongBoxUnavailableException) {
            generateFallbackKeyPair(generator)
        } catch (_: Exception) {
            generateFallbackKeyPair(generator)
        }
    }

    private fun generateFallbackKeyPair(generator: KeyPairGenerator): KeyPair {
        generator.initialize(
            KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_AGREE_KEY)
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                .build(),
        )
        return generator.generateKeyPair()
    }

    private fun ecdh(peerUncompressed: ByteArray): ByteArray {
        val peer = decodePublic(peerUncompressed)
        val agreement = KeyAgreement.getInstance("ECDH")
        agreement.init(keyPair().private)
        agreement.doPhase(peer, true)
        // generateSecret() 会去掉前导零字节，所以必须左侧补齐到 32 字节，
        // 否则与服务端按定长 X 坐标算出的 kek 不一致（约 1/256 的概率踩中）。
        return pad32(BigInteger(1, agreement.generateSecret()))
    }

    private fun decodePublic(uncompressed: ByteArray): ECPublicKey {
        require(uncompressed.size == 65 && uncompressed[0] == 0x04.toByte()) {
            "public key must be an uncompressed P-256 point"
        }
        val x = BigInteger(1, uncompressed.copyOfRange(1, 33))
        val y = BigInteger(1, uncompressed.copyOfRange(33, 65))
        val params = AlgorithmParameters.getInstance("EC").apply {
            init(ECGenParameterSpec("secp256r1"))
        }.getParameterSpec(ECParameterSpec::class.java)
        val point = ECPoint(x, y)
        // fail-closed：临时公钥必须落在 secp256r1 上，否则不解包。
        val field = params.curve.field as? java.security.spec.ECFieldFp
        require(field != null) { "unexpected EC field" }
        val p = field.p
        val lhs = y.modPow(BigInteger.valueOf(2), p)
        val rhs = x.modPow(BigInteger.valueOf(3), p)
            .add(params.curve.a.multiply(x))
            .add(params.curve.b)
            .mod(p)
        require(lhs == rhs) { "public key point is not on secp256r1" }
        return KeyFactory.getInstance("EC")
            .generatePublic(ECPublicKeySpec(point, params)) as ECPublicKey
    }

    private companion object {
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val ALIAS = "ghostlock_device_key_v1"
        const val WRAPPED_SIZE = 125

        fun pad32(value: BigInteger): ByteArray {
            val raw = value.toByteArray()
            val out = ByteArray(32)
            val start = if (raw.size > 32) raw.size - 32 else 0
            val n = minOf(raw.size, 32)
            System.arraycopy(raw, start, out, 32 - n, n)
            return out
        }

        fun sha256(data: ByteArray): ByteArray =
            java.security.MessageDigest.getInstance("SHA-256").digest(data)

        /** RFC 5869 HKDF-SHA256；与 `server/gl-license/crypto.py` 逐字节一致。 */
        fun hkdfSha256(ikm: ByteArray, salt: ByteArray, info: ByteArray, length: Int): ByteArray {
            val mac = Mac.getInstance("HmacSHA256")
            mac.init(SecretKeySpec(if (salt.isEmpty()) ByteArray(32) else salt, "HmacSHA256"))
            val prk = mac.doFinal(ikm)
            mac.init(SecretKeySpec(prk, "HmacSHA256"))

            val out = ByteArray(length)
            var block = ByteArray(0)
            var pos = 0
            var counter = 1
            while (pos < length) {
                mac.reset()
                mac.update(block)
                mac.update(info)
                mac.update(counter.toByte())
                block = mac.doFinal()
                val n = minOf(block.size, length - pos)
                System.arraycopy(block, 0, out, pos, n)
                pos += n
                counter++
            }
            return out
        }
    }
}
