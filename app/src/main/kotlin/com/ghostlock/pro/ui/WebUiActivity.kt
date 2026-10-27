package com.ghostlock.pro.ui

import android.annotation.SuppressLint
import android.content.Intent
import android.graphics.Color
import android.os.Bundle
import android.view.Gravity
import android.view.ViewGroup
import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.FrameLayout
import android.widget.TextView
import androidx.activity.ComponentActivity
import androidx.activity.OnBackPressedCallback
import com.ghostlock.pro.R
import java.io.ByteArrayInputStream
import java.io.File

/**
 * DikSU 的本地管理页面。
 *
 * 提权结束前，引擎会以 root 身份把 `ksud webui --daemon` 拉起来，并把
 * `http://127.0.0.1:<port>/?t=<token>` 写进 `filesDir/webui.url`（0600，属主是本 App）。
 * 这里只负责把这个地址放进 WebView —— 管理动作（超级用户、模块、文件、终端）全部由
 * 页面背后的 ksud 执行，App 本身不碰这些逻辑。
 *
 * 没有 root、或者模块没加载时，文件不存在或服务已经退出，此时给出明确提示而不是白屏。
 */
class WebUiActivity : ComponentActivity() {

    private var webView: WebView? = null

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val url = readUrl()
        if (url == null) {
            showMessage(getString(R.string.webui_unavailable))
            return
        }

        val view = WebView(this).apply {
            settings.javaScriptEnabled = true
            settings.domStorageEnabled = true
            settings.allowFileAccess = false
            settings.allowContentAccess = false
            setBackgroundColor(Color.TRANSPARENT)
            webViewClient = object : WebViewClient() {
                override fun shouldOverrideUrlLoading(
                    view: WebView,
                    request: WebResourceRequest,
                ): Boolean {
                    val target = request.url
                    if (target.host == "127.0.0.1" || target.host == "localhost") return false
                    // 页面里的外链（文档、源码）交给浏览器，免得在管理页面里丢掉上下文。
                    runCatching { startActivity(Intent(Intent.ACTION_VIEW, target)) }
                    return true
                }

                override fun onReceivedHttpError(
                    view: WebView,
                    request: WebResourceRequest,
                    errorResponse: WebResourceResponse,
                ) {
                    // 令牌被轮换过（例如上一次会话在别处正常关闭了页面），这里只剩一个 403。
                    if (request.isForMainFrame && errorResponse.statusCode == 403) {
                        showMessage(getString(R.string.webui_expired))
                    }
                }

                override fun onPageFinished(view: WebView, url: String) {
                    // 页面在 pagehide 时会 sendBeacon('/api/close')，ksud 收到就轮换
                    // 令牌；拦掉这个调用，存下来的地址才能在关闭页面后继续用。
                    view.evaluateJavascript(
                        "navigator.sendBeacon=function(){return true};", null,
                    )
                }

                override fun shouldInterceptRequest(
                    view: WebView,
                    request: WebResourceRequest,
                ): WebResourceResponse? {
                    // 页面 pagehide 时会 beacon /api/close，ksud 收到就把令牌轮换掉 ——
                    // 那会让这里存着的地址在下次打开时失效。令牌本来只落在本 App 的
                    // 私有文件里，这个请求没有存在的必要，直接吞掉。
                    if (request.url.path == "/api/close") {
                        return WebResourceResponse(
                            "application/json",
                            "utf-8",
                            ByteArrayInputStream("{\"code\":0}".toByteArray()),
                        )
                    }
                    return null
                }
            }
            loadUrl(url)
        }
        setContentView(view)
        webView = view

        onBackPressedDispatcher.addCallback(this, object : OnBackPressedCallback(true) {
            override fun handleOnBackPressed() {
                val wv = webView
                if (wv != null && wv.canGoBack()) wv.goBack() else finish()
            }
        })
    }

    private fun readUrl(): String? = runCatching {
        val file = File(filesDir, URL_FILE)
        if (!file.isFile) return null
        file.readText().trim().takeIf { it.startsWith("http://127.0.0.1:") }
    }.getOrNull()

    private fun showMessage(text: String) {
        val label = TextView(this).apply {
            setText(text)
            gravity = Gravity.CENTER
            setPadding(48, 48, 48, 48)
            textSize = 15f
        }
        setContentView(
            FrameLayout(this).apply { addView(label, ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT) },
        )
    }

    override fun onDestroy() {
        webView?.let { view ->
            (view.parent as? ViewGroup)?.removeView(view)
            view.destroy()
        }
        webView = null
        super.onDestroy()
    }

    private companion object {
        /** 引擎写的文件；内容形如 `http://127.0.0.1:37021/?t=<token>`。 */
        const val URL_FILE = "webui.url"
    }
}
