package com.ghostlock.pro.ui

import android.annotation.SuppressLint
import android.content.Intent
import android.graphics.Color
import android.net.Uri
import android.os.Bundle
import android.view.Gravity
import android.view.ViewGroup
import android.webkit.ConsoleMessage
import android.webkit.CookieManager
import android.webkit.WebChromeClient
import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.FrameLayout
import android.widget.TextView
import androidx.activity.ComponentActivity
import androidx.activity.OnBackPressedCallback
import com.ghostlock.pro.R
import com.ghostlock.pro.data.GlobalLog
import java.io.ByteArrayInputStream
import java.io.File

/**
 * DikSU 的本地管理页面。
 *
 * 提权结束前，引擎会以 root 身份把 `ksud webui --daemon` 拉起来，并把
 * `http://127.0.0.1:<port>/?k=<token>` 写进 `filesDir/webui.url`（0600，属主是本 App）。
 *
 * 页面本身把 `?k=` 从地址栏抹掉，之后的接口调用全靠服务端种下的 `ksu_webui`
 * cookie——所以这里必须显式打开 cookie，并把令牌预先种进去；否则页面能渲染但每个
 * 接口都 403，表现就是"有 UI、没功能"。
 *
 * 页面的控制台输出和失败的接口都写进全局日志，用来定位问题。
 */
class WebUiActivity : ComponentActivity() {

    private var webView: WebView? = null
    private lateinit var log: GlobalLog

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        log = GlobalLog.get(this)
        val url = readUrl()
        if (url == null) {
            showMessage(getString(R.string.webui_unavailable))
            return
        }
        log.append("webui", "open $url")

        primeCookie(url)

        val view = WebView(this).apply {
            settings.javaScriptEnabled = true
            settings.domStorageEnabled = true
            settings.allowFileAccess = false
            settings.allowContentAccess = false
            setBackgroundColor(Color.TRANSPARENT)
            webChromeClient = object : WebChromeClient() {
                override fun onConsoleMessage(msg: ConsoleMessage): Boolean {
                    log.append("webui", "${msg.messageLevel()} ${msg.message()} @${msg.sourceId()}:${msg.lineNumber()}")
                    return true
                }
            }
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
                    log.append("webui", "http ${errorResponse.statusCode} ${request.method} ${request.url}")
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

    /**
     * 页面加载时服务端会回一个 `Set-Cookie: ksu_webui=…; HttpOnly; SameSite=Strict`，
     * 但 WebView 在部分机型上不会把它带进后续 XHR；这里按 URL 里的 `k` 主动种一次，
     * 保证接口调用能带上令牌。
     */
    private fun primeCookie(url: String) {
        val token = runCatching { Uri.parse(url).getQueryParameter("k") }.getOrNull()
        if (token.isNullOrEmpty()) return
        val cm = CookieManager.getInstance()
        cm.setAcceptCookie(true)
        val base = url.substringBefore('?')
        val origin = runCatching {
            val uri = Uri.parse(base)
            "${uri.scheme}://${uri.host}:${uri.port}"
        }.getOrNull() ?: return
        cm.setCookie(origin, "ksu_webui=$token; Path=/")
        cm.setCookie(origin + "/", "ksu_webui=$token; Path=/")
        cm.flush()
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
            FrameLayout(this).apply {
                addView(label, ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT)
            },
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
        /** 引擎写的文件；内容形如 `http://127.0.0.1:37021/?k=<token>`。 */
        const val URL_FILE = "webui.url"
    }
}
