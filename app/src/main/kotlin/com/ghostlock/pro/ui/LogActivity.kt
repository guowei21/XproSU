package com.ghostlock.pro.ui

import android.content.ClipData
import android.content.ClipboardManager
import android.graphics.Color
import android.graphics.Typeface
import android.os.Bundle
import android.text.method.ScrollingMovementMethod
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import androidx.activity.ComponentActivity
import com.ghostlock.pro.R
import com.ghostlock.pro.data.GlobalLog

/**
 * 全局日志查看器。
 *
 * 只读文件，不改状态：刷新重新取尾部，复制把当前内容放进剪贴板，清空需要确认。
 */
class LogActivity : ComponentActivity() {

    private lateinit var log: GlobalLog
    private lateinit var body: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        log = GlobalLog.get(this)

        body = TextView(this).apply {
            typeface = Typeface.MONOSPACE
            textSize = 10f
            setTextColor(Color.parseColor("#D1D5DB"))
            setBackgroundColor(Color.parseColor("#0B1220"))
            setPadding(24, 24, 24, 24)
            movementMethod = ScrollingMovementMethod()
        }

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(Color.parseColor("#0B1220"))
            addView(
                body,
                LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT,
                    0,
                    1f,
                ),
            )
            addView(buttonRow())
        }
        setContentView(root)

        refresh()
    }

    private fun buttonRow(): LinearLayout = LinearLayout(this).apply {
        orientation = LinearLayout.HORIZONTAL
        addView(action(R.string.log_refresh) { refresh() }, weight())
        addView(action(R.string.action_copy) {
            val text = body.text.toString()
            if (text.isEmpty()) {
                Toast.makeText(this@LogActivity, R.string.global_log_empty, Toast.LENGTH_SHORT).show()
            } else {
                getSystemService(ClipboardManager::class.java)
                    ?.setPrimaryClip(ClipData.newPlainText("global-log", text))
                Toast.makeText(this@LogActivity, R.string.global_log_copied, Toast.LENGTH_SHORT).show()
            }
        }, weight())
        addView(action(R.string.global_log_clear) {
            log.clear()
            refresh()
            Toast.makeText(this@LogActivity, R.string.global_log_cleared, Toast.LENGTH_SHORT).show()
        }, weight())
    }

    private fun weight() = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)

    private fun action(labelRes: Int, onClick: () -> Unit): Button = Button(this).apply {
        setText(labelRes)
        textSize = 13f
        setOnClickListener { onClick() }
    }

    private fun refresh() {
        val lines = log.tail(TAIL_LINES)
        body.text = if (lines.isEmpty()) {
            getString(R.string.global_log_empty)
        } else {
            lines.joinToString(separator = "\n")
        }
    }

    private companion object {
        const val TAIL_LINES = 3000
    }
}
