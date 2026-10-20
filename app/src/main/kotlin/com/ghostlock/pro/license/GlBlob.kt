package com.ghostlock.pro.license

/**
 * 授权层的二进制编解码。
 *
 * 为什么不用 JSON：JSON 的键名是**自描述**的。`"token"`、`"vipExpDate"`、
 * `"cardKey"` 这类字符串留在 dex 里，等于把整套授权数据结构的字段名、类型和用途
 * 直接交给逆向者——他不需要跑起来，`strings` 一遍就能画出数据流图。
 *
 * 这里改成定长头 + TLV，标签是**不连续的不透明数字**，值一律二进制：
 *
 * ```
 *   0..3   magic   u32 LE   区分「线路包」与「本地记录」，且不是可读 ASCII
 *   4      version u8       当前 1
 *   5      kind    u8       1 = 请求，2 = 响应/记录
 *   6..7   code    u16 LE   业务码（请求恒为 0）
 *   8..9   count   u16 LE   TLV 条目数
 *   10..11 reserved u16     恒为 0
 *   之后   条目 × count：tag u16 LE | len u16 LE | value
 * ```
 *
 * 标签故意跳号（0x21、0x22…而不是 1、2、3），这样连"第几个字段是什么"都推不出来。
 *
 * **这不是加密**：它挡的是"读懂结构"，不是"拿到内容"。真正的机密性由两件事提供——
 * 本地记录整块经 Keystore AES-GCM 加密后才落盘，线路上的载荷由 GLT2 的 AEAD 保护。
 */
object GlBlob {

    /** 线路包 magic：`0x9E4B37A1`。非 ASCII，不会与 JSON 混淆。 */
    const val MAGIC_WIRE = 0x9E4B37A1.toInt()

    /** 本地记录 magic：`0x3D71C5E9`。 */
    const val MAGIC_RECORD = 0x3D71C5E9.toInt()

    const val VERSION = 1
    const val KIND_REQUEST = 1
    const val KIND_RESPONSE = 2

    const val HEADER_SIZE = 12

    // ── 线路标签（请求）────────────────────────────────────────────────
    const val T_CARD = 0x21
    const val T_DEVICE_FP = 0x22
    const val T_PUBKEY = 0x23
    const val T_APP_VER = 0x24
    const val T_LOG = 0x25
    const val T_TOKEN = 0x35

    // ── 线路标签（响应）────────────────────────────────────────────────
    const val T_TOKEN_OUT = 0x31
    const val T_EXPIRE = 0x32
    const val T_BLOB = 0x33
    const val T_WRAPPED = 0x34
    const val T_STATE = 0x36
    const val T_MESSAGE = 0x41
    // ── 本地记录标签 ───────────────────────────────────────────────────
    const val R_DEVICE_ID = 0x51
    const val R_CARD_KEY = 0x52
    const val R_TOKEN = 0x53
    const val R_STATE = 0x54
    const val R_EXPIRY = 0x55
    const val R_ACTIVATED_AT = 0x56

    fun encode(magic: Int, kind: Int, code: Int, entries: List<Pair<Int, ByteArray>>): ByteArray {
        var size = HEADER_SIZE
        for ((_, value) in entries) size += 4 + value.size
        val out = ByteArray(size)

        putU32(out, 0, magic)
        out[4] = VERSION.toByte()
        out[5] = kind.toByte()
        putU16(out, 6, code)
        putU16(out, 8, entries.size)
        putU16(out, 10, 0)

        var pos = HEADER_SIZE
        for ((tag, value) in entries) {
            putU16(out, pos, tag)
            putU16(out, pos + 2, value.size)
            System.arraycopy(value, 0, out, pos + 4, value.size)
            pos += 4 + value.size
        }
        return out
    }

    /** 解析结果：业务码 + 标签到值的映射。magic/版本不符或结构截断时返回 null。 */
    fun decode(bytes: ByteArray, magic: Int): Decoded? {
        if (bytes.size < HEADER_SIZE) return null
        if (readU32(bytes, 0) != magic) return null
        if (bytes[4].toInt() != VERSION) return null

        val code = readU16(bytes, 6)
        val count = readU16(bytes, 8)
        val entries = HashMap<Int, ByteArray>(count)
        var pos = HEADER_SIZE
        repeat(count) {
            if (pos + 4 > bytes.size) return null
            val tag = readU16(bytes, pos)
            val len = readU16(bytes, pos + 2)
            pos += 4
            if (len < 0 || pos + len > bytes.size) return null
            entries[tag] = bytes.copyOfRange(pos, pos + len)
            pos += len
        }
        // 多出来的尾巴一律当作损坏，避免"前面看着对、后面被塞了东西"。
        if (pos != bytes.size) return null
        return Decoded(code, entries)
    }
    class Decoded(val code: Int, private val entries: Map<Int, ByteArray>) {
        fun bytes(tag: Int): ByteArray? = entries[tag]

        fun string(tag: Int): String? = entries[tag]?.toString(Charsets.UTF_8)

        /** u64 字段；缺失或长度不是 8 字节时返回 null，调用方按"拒绝"处理。 */
        fun long(tag: Int): Long? {
            val value = entries[tag] ?: return null
            if (value.size != 8) return null
            return readU64(value, 0)
        }

        /** 单字节字段；缺失或长度不是 1 字节时返回 null。 */
        fun u8(tag: Int): Int? {
            val value = entries[tag] ?: return null
            if (value.size != 1) return null
            return value[0].toInt() and 0xFF
        }
    }

    // ── 小端读写（逐字节，避免依赖平台对齐与字节序）──────────────────

    fun u16(value: Int) = ByteArray(2).also { putU16(it, 0, value) }

    fun u8(value: Int) = ByteArray(1).also { it[0] = value.toByte() }

    fun u32(value: Int) = ByteArray(4).also { putU32(it, 0, value) }

    fun u64(value: Long) = ByteArray(8).also { putU64(it, 0, value) }

    fun str(value: String) = value.toByteArray(Charsets.UTF_8)

    fun putU16(dst: ByteArray, at: Int, value: Int) {
        dst[at] = (value and 0xFF).toByte()
        dst[at + 1] = ((value ushr 8) and 0xFF).toByte()
    }

    fun putU32(dst: ByteArray, at: Int, value: Int) {
        for (i in 0 until 4) dst[at + i] = ((value ushr (8 * i)) and 0xFF).toByte()
    }

    fun putU64(dst: ByteArray, at: Int, value: Long) {
        for (i in 0 until 8) dst[at + i] = ((value ushr (8 * i)) and 0xFF).toByte()
    }

    fun readU16(src: ByteArray, at: Int): Int =
        (src[at].toInt() and 0xFF) or ((src[at + 1].toInt() and 0xFF) shl 8)

    fun readU32(src: ByteArray, at: Int): Int {
        var v = 0
        for (i in 0 until 4) v = v or ((src[at + i].toInt() and 0xFF) shl (8 * i))
        return v
    }

    fun readU64(src: ByteArray, at: Int): Long {
        var v = 0L
        for (i in 0 until 8) v = v or ((src[at + i].toLong() and 0xFF) shl (8 * i))
        return v
    }
}
