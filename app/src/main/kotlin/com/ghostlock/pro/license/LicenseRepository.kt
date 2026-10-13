package com.ghostlock.pro.license

import android.content.Context
import com.ghostlock.pro.BuildConfig
import com.ghostlock.pro.R
import java.security.MessageDigest
import java.security.SecureRandom
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File

private fun nowSeconds(): Long = System.currentTimeMillis() / 1000L

/**
 * 一次会话的解密材料：Kd 只存在于内存，随取随用，绝不落盘。
 *
 * @param kd      32 字节载荷密钥，由服务端现场封进本机 TEE 公钥下发。
 * @param blob    GLT2 容器，与 Kd 一一对应，仅供本次运行。
 */
data class SessionKey(
    val kd: ByteArray,
    val blob: ByteArray,
)

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

    /**
     * Debug 旁路才有的内存密钥。Release 永远是 null：Kd 只在
     * [fetchSessionKey] 的返回值里活一次，投喂引擎后即被丢弃。
     */
    @Volatile
    private var debugKey: ByteArray? = null
    private val deviceKey = DeviceKey()
    private val payloadFile = File(appContext.filesDir, PAYLOAD_NAME)

    /**
     * 本机是否具备硬件级设备身份（Widevine）。
     *
     * 整个授权链路的前置条件：取不到就**不做任何降级**，直接拒绝。
     * 详见 [DeviceFingerprint] 的说明。
     */
    val supported: Boolean = DeviceFingerprint.supported(appContext)

    /** 界面上展示的设备码（真实 Widevine ID 的 64 位大写 hex）。 */
    val deviceId: String = DeviceFingerprint.display(appContext).orEmpty()

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
     * 本地是否持有有效凭据（不代表当前可用：真正的判定在 [fetchSessionKey]，
     * 它每次都会向服务端确认卡密状态）。
     *
     * Debug 且**未配置授权服务**时整体放行，让本地调试能进主界面。
     */
    fun isActivated(): Boolean =
        debugBypass() ||
                (supported &&
                        cached()?.let {
                            it.token.isNotEmpty() &&
                                    it.cardKey.isNotEmpty() &&
                                    it.state != STATE_DISABLED &&
                                    (it.expireAt == 0L || it.expireAt > nowSeconds())
                        } == true)

    /** 仅 Debug 构建且未配置服务地址时为真；Release 恒为 false。 */
    private fun debugBypass(): Boolean = BuildConfig.DEBUG && client == null

    /** Debug 旁路下允许在没有会话密钥时继续运行（仅本机调试）。 */
    fun debugSessionAllowed(): Boolean = debugBypass()

    /**
     * 仅供 Debug 旁路：Release 永远返回 null —— Kd 不落盘，没有本地密钥可取。
     */
    fun cachedDebugPayloadKey(): ByteArray? = if (debugBypass()) debugKey else null

    /**
     * 打开 App 时的在线核对：确认卡密仍然有效。
     *
     * 与 [fetchSessionKey] 用同一条服务端判定；失败时 [clear] 本地凭据，
     * 返回 false 让调用方退回登录窗口。
     */
    suspend fun verifyOnline(): Boolean = withContext(Dispatchers.IO) {
        if (debugBypass()) return@withContext true
        if (!cached()) return@withContext false
        if (fetchSessionKey() != null) {
            true
        } else {
            // 服务端明确拒绝时 fetchSessionKey 已 clear；网络不通也保持未授权，
            // 因为没有 Kd 就解不开任何东西，"能打开界面" 不等于 "能用"。
            false
        }
    }

    /**
     * 会话式取密钥：每次启动、每次运行提权前必须调用。
     *
     * 服务端现场校验卡密（删卡/封卡/过期立即 1001/1003），然后把 Kd 封进
     * 本机 TEE 公钥发回来。Kd 和容器**只存在于内存**，返回后由调用方立即
     * 投喂给引擎，不落盘。网络失败或服务端拒绝 = 本次无法使用（fail-closed）。
     */
    suspend fun fetchSessionKey(): SessionKey? = withContext(Dispatchers.IO) {
        val record = cached() ?: return@withContext null
        val api = client ?: return@withContext null
        try {
            val response = api.session(
                card = record.cardKey.trim().uppercase(),
                deviceFpHex = deviceFpHex,
                pubKeyHex = DeviceFingerprint.hex(deviceKey.publicKey()),
            )
            val blob = response.bytes(GlBlob.T_BLOB) ?: return@withContext null
            val wrapped = response.bytes(GlBlob.T_WRAPPED) ?: return@withContext null
            val kd = try {
                deviceKey.unwrap(wrapped, record.cardKey.trim().uppercase())
            } catch (_: Exception) {
                return@withContext null
            }
            // 服务端返回的到期时间同步回本地记录，界面显示与真实状态一致。
            response.long(GlBlob.T_EXPIRE)?.let { exp ->
                if (exp > 0L && record.expireAt != exp) {
                    store.save(record.copy(expireAt = exp))
                }
            }
            if (debugBypass()) debugKey = kd
            SessionKey(kd, blob)
        } catch (e: LicenseRejected) {
            clear()
            null
        } catch (_: Exception) {
            null
        }
    }

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

    /**
     * 引擎需要的容器路径。
     *
     * 会话模式下容器由 [fetchSessionKey] 现场返回，写入临时文件给引擎
     * 一次性使用，`clear()` 时删除。返回 null 表示当前没有可用的会话容器。
     */
    fun stageContainer(blob: ByteArray): String? {
        return try {
            payloadFile.writeBytes(blob)
            payloadFile.absolutePath
        } catch (_: Exception) {
            null
        }
    }

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
            // Kd 与容器**只用于这一刻的完整性校验**，随后即弃：它们不写盘。
            // 落盘的只有凭据；每次使用（打开 App / 点立即 Root）都由
            // fetchSessionKey 现场向服务端再要一份。
            @Suppress("UNUSED_EXPRESSION")
            blob.size
            kd.fill(0)
            store.save(record)
            return@withContext ActivationResult.Ok(record)
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

    /** 收回授权：凭据一并清掉，历史遗留的容器/密钥字段也删。 */
    fun clear() {
        store.clear()
        runCatching { payloadFile.delete() }
        debugKey?.fill(0)
        debugKey = null
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
