package com.ghostlock.pro.license

import android.content.Context
import com.ghostlock.pro.BuildConfig
import com.ghostlock.pro.R
import java.io.IOException
import java.security.MessageDigest
import java.security.SecureRandom
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File

private fun nowSeconds(): Long = System.currentTimeMillis() / 1000L

/** 激活结果。 */
sealed interface ActivationResult {
    data class Ok(val record: LicenseRecord) : ActivationResult

    /** 服务端明确拒绝（卡密错、已绑定他机、已过期…），[message] 可直接展示。 */
    data class Rejected(val code: Int, val message: String) : ActivationResult

    /** 连不上服务端或响应异常。 */
    data class Unreachable(val message: String) : ActivationResult
}

/**
 * 授权仓库：卡密 → 服务端裁决 → **按设备加密的载荷**。
 *
 * 阶段② 之后，授权不再只是一个布尔判断。激活成功时服务端会下发：
 *
 *  - `blob`：用本机专属密钥 `Kd` 封装的 GLT2 容器（偏移表在里面）；
 *  - `wrapped`：`Kd` 本身，包在只有本机 TEE 私钥能解的 ECIES 里。
 *
 * 两者都落盘（`Kd` 经 Keystore 加密），引擎启动时通过环境变量拿到 `Kd`。
 * **没有激活就没有载荷**——不是"被 if 拦住"，是数据不存在。
 */
class LicenseRepository(
    context: Context,
    private val client: LicenseClient?,
) {
    private val appContext = context.applicationContext
    private val store = LicenseStore(appContext)
    private val deviceKey = DeviceKey()
    private val payloadFile = File(appContext.filesDir, PAYLOAD_NAME)

    /**
     * 本机是否具备硬件级设备身份（Widevine）。
     *
     * 整个授权链路的前置条件：取不到就**不做任何降级**，直接拒绝。
     * 详见 [DeviceFingerprint] 的说明。
     */
    val supported: Boolean = DeviceFingerprint.supported(appContext)

    /**
     * 内部绑定标识：真实指纹的 64 位 hex，与凭据里存的值比较用。
     * **不要**显示它（它是可重放的绑定凭证），界面用 [deviceCode]。
     */
    val deviceId: String = DeviceFingerprint.display(appContext).orEmpty()

    /** 界面/工单用设备码（指纹摘要，不可用于绑定）；不支持时为空串。 */
    val deviceCode: String = DeviceFingerprint.code(appContext).orEmpty()

    /**
     * 参与密码学的 32 字节身份，hex 形式随激活请求上传。
     *
     * 不支持时是空串 —— 这是刻意的 fail-closed：服务端会以「device_fp 必须是
     * 64 hex」拒绝，`isActivated()` 也恒为 false。
     */
    val deviceFpHex: String =
        DeviceFingerprint.raw(appContext)?.let(DeviceFingerprint::hex).orEmpty()

    /** 读取当前授权状态（不联网）；凭据与本机标识不匹配即视为无授权。 */
    fun cached(): LicenseRecord? = store.load()?.takeIf { it.deviceId == deviceId }

    /** 是否已在构建期配置授权服务地址。 */
    val configured: Boolean = client != null

    /**
     * 是否已授权：凭据 + 载荷密钥 + 容器三者齐备，且凭据属于本机。
     *
     * Debug 且**未配置授权服务**时整体放行，让本地调试能进主界面；引擎那边
     * 没有载荷仍然会拒绝运行，所以这个旁路不会假装成一次成功的提权。
     * 这里是唯一判定处 —— 登录窗口、主界面守卫、ViewModel 全部读它。
     */
    fun isActivated(): Boolean =
        debugBypass() ||
                (supported &&
                        cached()?.let {
                            it.token.isNotEmpty() &&
                                    it.cardKey.isNotEmpty() &&
                                    it.state != STATE_DISABLED &&
                                    (it.expireAt == 0L || it.expireAt > nowSeconds())
                        } == true &&
                        payloadKey() != null &&
                        payloadFile.isFile && payloadFile.length() > 0)

    /** 仅 Debug 构建且未配置服务地址时为真；Release 恒为 false。 */
    private fun debugBypass(): Boolean = BuildConfig.DEBUG && client == null

    /** 引擎需要的 32 字节载荷密钥；无授权时返回 null。 */
    fun payloadKey(): ByteArray? = store.loadPayloadKey()

    /**
     * 距离到期还剩多少秒；永久授权返回 null。
     * 已到期返回 0，调用方据此收回授权与界面状态。
     */
    fun expireRemainingSeconds(): Long? {
        val record = cached() ?: return null
        if (record.expireAt == 0L) return null
        return (record.expireAt - nowSeconds()).coerceAtLeast(0L)
    }

    /**
     * 本地到期检查入口：到期即收回授权并返回 false。
     * MainActivity 回到前台与每次运行提权前都会调用。
     */
    suspend fun checkExpiry(): Boolean = withContext(Dispatchers.IO) {
        val record = cached() ?: return@withContext false
        if (record.expireAt != 0L && record.expireAt <= nowSeconds()) {
            clear()
            false
        } else {
            true
        }
    }

    /**
     * 卡密摘要：`SHA-256(card_key)` 的前 16 字节，hex。
     *
     * 引擎拿它跟容器头里被 AEAD 认证过的 `card_tag` 比对。这一步让「门」不再是唯一
     * 防线：登录分支被打掉也拿不出这个值，容器照样解不开——卡密真正参与了偏移解密。
     */
    fun cardTagHex(): String? {
        // 本地记录与摘要都只认归一化（trim + uppercase）后的卡密，与服务端一致。
        val key = cached()?.cardKey?.trim()?.uppercase()?.takeIf { it.isNotEmpty() } ?: return null
        val digest = MessageDigest.getInstance("SHA-256")
            .digest(key.toByteArray(Charsets.UTF_8))
        return DeviceFingerprint.hex(digest.copyOfRange(0, CARD_TAG_SIZE))
    }

    /** 引擎需要的容器路径；不存在时返回 null。 */
    fun payloadPath(): String? = payloadFile.takeIf { it.isFile && it.length() > 0 }?.absolutePath

    /** 用卡密激活本机，并取回本机专属载荷。 */
    suspend fun activate(cardKey: String): ActivationResult = withContext(Dispatchers.IO) {
        val key = cardKey.trim().uppercase()
        if (key.isEmpty()) {
            return@withContext ActivationResult.Rejected(-1, appContext.getString(R.string.license_card_empty))
        }
        if (!supported) {
            return@withContext ActivationResult.Rejected(
                -1,
                appContext.getString(R.string.license_device_unsupported),
            )
        }
        val api = client
            ?: return@withContext ActivationResult.Unreachable(appContext.getString(R.string.license_config_missing))

        try {
            val response = api.activate(
                card = key,
                deviceFpHex = deviceFpHex,
                pubKeyHex = DeviceFingerprint.hex(deviceKey.publicKey()),
            )

            // ── 阶段一：把响应完整解析并校验完，一步都不落盘 ────────────────
            //
            // 顺序是安全属性，不是风格。早期版本先写密钥和容器、后校验 token，
            // 于是一条「code=0 但缺 token / expire 截断」的畸形响应会留下
            // 「新载荷 + 旧凭据」的混合态：isActivated() 仍为真、界面显示已授权，
            // 但 cardTagHex() 来自旧卡密、跟新容器头对不上，引擎必然拒绝 ——
            // 用户从"能用"变成"不能用"，而且旧授权已被覆盖、无法回退。
            val blob = response.bytes(GlBlob.T_BLOB)
                ?: return@withContext ActivationResult.Rejected(-1, appContext.getString(R.string.license_bad_payload))
            val wrapped = response.bytes(GlBlob.T_WRAPPED)
                ?: return@withContext ActivationResult.Rejected(-1, appContext.getString(R.string.license_bad_payload))

            val token = response.string(GlBlob.T_TOKEN_OUT).orEmpty()
            if (token.isEmpty()) {
                return@withContext ActivationResult.Rejected(-1, appContext.getString(R.string.license_no_token))
            }
            val expireBytes = response.bytes(GlBlob.T_EXPIRE)
            if (expireBytes == null || expireBytes.size != 8) {
                return@withContext ActivationResult.Rejected(-1, appContext.getString(R.string.license_bad_payload))
            }
            val expire = response.long(GlBlob.T_EXPIRE)
                ?: return@withContext ActivationResult.Rejected(-1, appContext.getString(R.string.license_bad_payload))

            // 解不开就是没授权：换机、卡密不符、被篡改都会走到这里。
            val kd = try {
                deviceKey.unwrap(wrapped, key)
            } catch (e: Exception) {
                return@withContext ActivationResult.Rejected(
                    -1,
                    appContext.getString(R.string.license_unwrap_failed),
                )
            }

            val record = LicenseRecord(
                deviceId = deviceId,
                cardKey = key,
                token = token,
                state = STATE_ENABLED,
                expireAt = expire,
                activatedAt = System.currentTimeMillis(),
            )
            return@withContext persistActivation(blob, kd, record)
        } catch (e: LicenseRejected) {
            ActivationResult.Rejected(e.code, e.message ?: appContext.getString(R.string.license_verify_failed))
        } catch (e: LicenseTransport) {
            ActivationResult.Unreachable(e.message ?: appContext.getString(R.string.license_network_error))
        } catch (e: Exception) {
            ActivationResult.Unreachable(e.message ?: appContext.getString(R.string.license_activate_failed))
        }
    }

    /** 保活：服务端要求在线时才有效。失败不抛异常，只回报 false。 */
    suspend fun heartbeat(): Boolean = refresh() != null

    /**
     * 保活 + 刷新到期信息。
     *
     * 服务端明确拒绝（业务码非 0）或 `0x36 state == 0` → 收回本地授权与载荷；
     * 传输失败（离线）→ 不再无条件放行，改为按本地 `expireAt` 判定，已过期同样收回。
     */
    suspend fun refresh(): LicenseRecord? = withContext(Dispatchers.IO) {
        val record = cached() ?: return@withContext null
        val api = client ?: return@withContext record
        try {
            val data = api.heartbeat(record.token)

            // heartbeat 现在必须回 0x36 state；缺失或非 1 一律 fail-closed。
            val state = data.u8(GlBlob.T_STATE)
            if (state == null || state != STATE_ENABLED) {
                clear()
                return@withContext null
            }

            val expireBytes = data.bytes(GlBlob.T_EXPIRE)
            val expire = if (expireBytes == null) {
                record.expireAt
            } else {
                data.long(GlBlob.T_EXPIRE) ?: run {
                    clear()
                    return@withContext null
                }
            }

            val updated = record.copy(expireAt = if (expire > 0L) expire else record.expireAt)
            store.save(updated)
            updated
        } catch (_: LicenseRejected) {
            clear()
            null
        } catch (_: Exception) {
            if (record.expireAt != 0L && record.expireAt <= nowSeconds()) {
                clear()
                null
            } else {
                record
            }
        }
    }

    /** 收回授权：凭据与载荷一起删，避免留下还能用的容器。 */
    fun clear() {
        store.clear()
        runCatching { payloadFile.delete() }
    }

    /**
     * 原子替换容器。
     *
     * 先写临时文件再 `rename`，这样引擎永远看不到半个文件；`rename(2)` 本身
     * 就是原子替换，**不需要先删目标** —— 先删会留下一个「offsets.glt 不存在」
     * 的窗口，引擎恰好在那时启动就会报缺载荷。任何失败都清掉临时文件。
     */
    private fun writePayload(blob: ByteArray): Boolean {
        val tmp = File(payloadFile.parentFile, "$PAYLOAD_NAME.tmp")
        return try {
            tmp.writeBytes(blob)
            if (!tmp.renameTo(payloadFile)) {
                runCatching { tmp.delete() }
                false
            } else {
                true
            }
        } catch (e: Exception) {
            runCatching { tmp.delete() }
            false
        }
    }

    /** 载荷、密钥、凭据三步一起落盘；任何一步失败都整体回滚到未授权。 */
    private fun persistActivation(blob: ByteArray, kd: ByteArray, record: LicenseRecord): ActivationResult {
        return try {
            if (!writePayload(blob)) {
                throw IOException("cannot write the activation payload")
            }
            store.savePayloadKey(kd)
            store.save(record)
            ActivationResult.Ok(record)
        } catch (e: Exception) {
            // 已经动过磁盘就必须把状态收干净：留下"凭据是旧的、载荷是新的"
            // 比直接退回未激活更糟 —— 前者看起来已授权却永远跑不起来。
            clear()
            ActivationResult.Unreachable(
                appContext.getString(R.string.license_payload_write_failed),
            )
        }
    }

    private companion object {
        const val PAYLOAD_NAME = "offsets.glt"
        const val CARD_TAG_SIZE = 16
    }
}

/** 供 UI 展示的授权快照。 */
data class LicenseSnapshot(
    val deviceId: String,
    val activated: Boolean,
    val state: String = "",
    val vipExpDate: String = "",
    val cardKeyMasked: String = "",
)

fun LicenseRecord?.toSnapshot(deviceId: String): LicenseSnapshot {
    val record = this?.takeIf { it.deviceId == deviceId }
    return LicenseSnapshot(
        deviceId = deviceId,
        activated = record != null &&
                record.token.isNotEmpty() &&
                record.cardKey.isNotEmpty() &&
                record.state != STATE_DISABLED &&
                (record.expireAt == 0L || record.expireAt > nowSeconds()),
        state = record?.state?.toString().orEmpty(),
        vipExpDate = record?.expiry.orEmpty(),
        cardKeyMasked = record?.cardKey?.let(::maskCardKey).orEmpty(),
    )
}

private fun maskCardKey(key: String): String =
    if (key.length <= 4) "****" else key.take(4) + "*".repeat((key.length - 4).coerceAtMost(12))
