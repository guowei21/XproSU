package com.ghostlock.pro.license

import java.text.Normalizer

/**
 * 卡密归一化。
 *
 * 用户输入的卡密经常「看起来一样但不是同一个串」：输入法全角（Ａ 而不是 A）、
 * 从聊天窗口复制带进来的零宽字符、各种连字符变体（– — − －）、不间断空格……
 * 它们都会让 SHA-256 完全不同，于是卡明明有效却报「卡密无效」。
 *
 * **规则必须与服务端 `store.py:clean_card_key` 逐字节一致**：`card_tag`
 * （`SHA-256(卡密)[:16]`）由两端各自计算，任一侧不一致引擎就会拒绝容器。
 *
 * **对已经规范的卡密是幂等的** —— 老卡密照旧可用，库里历史哈希不变。
 */
object CardKey {

    /** 零宽 / 软连字符：视觉上不可见，但会改变哈希。 */
    private val ZERO_WIDTH = setOf(0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x00AD, 0x180E)

    /** 各种连字符变体，统一成 ASCII '-'。 */
    private const val DASH_LIKE =
        "\u2010\u2011\u2012\u2013\u2014\u2015\u2212\u2043\ufe58\ufe63\uff0d\u2500\u2501\u2e3a\u2e3b"

    private const val CARD_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

    /**
     * 把「看起来像同一张卡」的输入归一成同一个串。
     *
     * 顺序：NFKC（全角→半角）→ 丢零宽/软连字符 → 丢所有空白 → 连字符统一成 '-'
     * → 大写 → 必要时补横杠分组。
     */
    fun normalize(raw: String): String {
        val nfkc = Normalizer.normalize(raw, Normalizer.Form.NFKC)
        val sb = StringBuilder(nfkc.length)
        for (ch in nfkc) {
            if (ZERO_WIDTH.contains(ch.code)) continue
            if (ch.isWhitespace() || Character.isSpaceChar(ch)) continue
            if (DASH_LIKE.indexOf(ch) >= 0) {
                sb.append('-')
                continue
            }
            sb.append(ch)
        }
        var s = sb.toString().uppercase()
        // 用户整串漏打横杠时补回规范分组：20 位 Base32 → XXXXX-XXXXX-XXXXX-XXXXX
        if (s.length == 20 && s.all { CARD_ALPHABET.indexOf(it) >= 0 }) {
            s = (0 until 20 step 5).joinToString("-") { s.substring(it, it + 5) }
        }
        return s
    }
}
