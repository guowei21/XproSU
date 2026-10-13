package com.ghostlock.pro.ui

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Intent
import android.os.Bundle
import android.view.WindowInsetsController
import android.view.WindowManager
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Lock
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.ghostlock.pro.GhostlockApplication
import com.ghostlock.pro.R
import com.ghostlock.pro.license.ActivationResult
import kotlinx.coroutines.MainScope
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import top.yukonga.miuix.kmp.basic.ButtonDefaults
import top.yukonga.miuix.kmp.basic.Card
import top.yukonga.miuix.kmp.basic.Icon
import top.yukonga.miuix.kmp.basic.Scaffold
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.basic.TextButton
import top.yukonga.miuix.kmp.basic.TextField
import top.yukonga.miuix.kmp.theme.MiuixTheme
import top.yukonga.miuix.kmp.theme.darkColorScheme
import top.yukonga.miuix.kmp.theme.lightColorScheme

/**
 * 独立的登录 / 激活窗口。
 *
 * 它是 App 的入口（LAUNCHER），**不是主界面里的一个对话框**：主界面在拿到授权之前
 * 根本不会被创建。这样"门"就不只是一个可被跳过的判断——没有载荷密钥和卡密绑定值，
 * 主界面即使被强行拉起，引擎也解不开任何东西（见 `docs/stage2-protocol.md` §5）。
 *
 * 已经激活过的设备直接放行，不打扰老用户。
 */
class LoginActivity : ComponentActivity() {

    private val license by lazy { (application as GhostlockApplication).license }

    /** 激活是一次网络往返；窗口销毁时必须一起取消，否则回调会打到死掉的 Activity。 */
    private val scope = MainScope()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // 已激活 → 直接进主界面，不显示登录页。
        if (license.isActivated()) {
            enterMain()
            return
        }

        setContent {
            MiuixTheme(
                colors = if (isSystemInDarkTheme()) darkColorScheme() else lightColorScheme(),
            ) {
                Scaffold(modifier = Modifier.fillMaxSize()) { padding ->
                    LoginScreen(
                        deviceCode = license.deviceCode,
                        configured = license.configured,
                        onCopyDeviceCode = ::copyDeviceCode,
                        onActivate = ::activate,
                        modifier = Modifier
                            .fillMaxSize()
                            .padding(padding),
                    )
                }
            }
        }
        setupSystemBars()
    }

    override fun onDestroy() {
        scope.cancel()
        super.onDestroy()
    }

    private fun copyDeviceCode(code: String) {
        getSystemService(ClipboardManager::class.java)
            ?.setPrimaryClip(ClipData.newPlainText("device-code", code))
        Toast.makeText(this, R.string.copied_device_id, Toast.LENGTH_SHORT).show()
    }

    /**
     * 卡密 → 服务端裁决 → 本机专属载荷。
     *
     * `report(null)` 表示成功（调用方随即进主界面），非 null 是给用户看的失败原因。
     */
    private fun activate(card: String, report: (String?) -> Unit) {
        if (card.isEmpty()) {
            report(getString(R.string.license_card_empty))
            return
        }
        // 激活要联网，用户正盯着看：先别让屏幕灭。
        window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
        scope.launch {
            val result = license.activate(card)
            window.clearFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
            when (result) {
                is ActivationResult.Ok -> {
                    Toast.makeText(this@LoginActivity, R.string.activate_success, Toast.LENGTH_SHORT).show()
                    report(null)
                    enterMain()
                }

                is ActivationResult.Rejected -> report(result.message)
                is ActivationResult.Unreachable -> report(result.message)
            }
        }
    }
    /** 主界面自己也会在未授权时回退到这里，所以这里只负责单向放行。 */
    private fun enterMain() {
        startActivity(Intent(this, MainActivity::class.java))
        finish()
    }

    private fun setupSystemBars() {
        val controller = window.decorView.windowInsetsController ?: return
        val lightStatus = if (resources.getBoolean(R.bool.window_light_status_bar)) {
            WindowInsetsController.APPEARANCE_LIGHT_STATUS_BARS
        } else {
            0
        }
        val lightNavigation = if (resources.getBoolean(R.bool.window_light_navigation_bar)) {
            WindowInsetsController.APPEARANCE_LIGHT_NAVIGATION_BARS
        } else {
            0
        }
        controller.setSystemBarsAppearance(
            lightStatus or lightNavigation,
            WindowInsetsController.APPEARANCE_LIGHT_STATUS_BARS or
                    WindowInsetsController.APPEARANCE_LIGHT_NAVIGATION_BARS,
        )
    }
}

@Composable
private fun LoginScreen(
    deviceCode: String,
    configured: Boolean,
    onCopyDeviceCode: (String) -> Unit,
    onActivate: (String, (String?) -> Unit) -> Unit,
    modifier: Modifier = Modifier,
) {
    val isDark = isSystemInDarkTheme()
    var card by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var status by remember { mutableStateOf<String?>(null) }

    Column(
        modifier = modifier
            .verticalScroll(rememberScrollState())
            .imePadding()
            .navigationBarsPadding()
            .padding(horizontal = 20.dp, vertical = 24.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Box(
                modifier = Modifier
                    .size(48.dp)
                    .clip(RoundedCornerShape(16.dp))
                    .background(if (isDark) Color(0xFF1E293B) else Color(0xFFEFF6FF)),
                contentAlignment = Alignment.Center,
            ) {
                Icon(
                    imageVector = Icons.Rounded.Lock,
                    contentDescription = null,
                    tint = MiuixTheme.colorScheme.primary,
                    modifier = Modifier.size(26.dp),
                )
            }
            Column {
                Text(
                    text = stringResource(R.string.login_title),
                    fontSize = 20.sp,
                    fontWeight = FontWeight.Bold,
                    color = MiuixTheme.colorScheme.onSurface,
                )
                Text(
                    text = stringResource(R.string.login_subtitle),
                    fontSize = 12.sp,
                    color = MiuixTheme.colorScheme.onSurface.copy(alpha = 0.6f),
                )
            }
        }

        Card(modifier = Modifier.fillMaxWidth(), insideMargin = PaddingValues(16.dp)) {
            Column(
                modifier = Modifier.fillMaxWidth(),
                verticalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                Text(
                    text = stringResource(R.string.login_device_code_label),
                    fontSize = 12.sp,
                    color = MiuixTheme.colorScheme.onSurface.copy(alpha = 0.55f),
                )
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(12.dp))
                        .background(if (isDark) Color(0xFF121822) else Color(0xFFF8FAFC))
                        .clickable { onCopyDeviceCode(deviceCode) }
                        .padding(horizontal = 12.dp, vertical = 10.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text(
                        text = deviceCode.ifEmpty { "----" },
                        fontSize = 14.sp,
                        fontFamily = FontFamily.Monospace,
                        fontWeight = FontWeight.Bold,
                        color = MiuixTheme.colorScheme.onSurface,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                    Text(
                        text = stringResource(R.string.action_copy),
                        fontSize = 12.sp,
                        fontWeight = FontWeight.SemiBold,
                        color = MiuixTheme.colorScheme.primary,
                    )
                }

                TextField(
                    value = card,
                    onValueChange = {
                        card = it
                        status = null
                    },
                    label = stringResource(R.string.login_card_hint),
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                )

                status?.let {
                    Text(text = it, fontSize = 12.sp, color = Color(0xFFDC2626))
                }

                if (!configured) {
                    Text(
                        text = stringResource(R.string.license_not_configured),
                        fontSize = 12.sp,
                        color = Color(0xFFD97706),
                    )
                }

                TextButton(
                    text = stringResource(if (busy) R.string.login_activating else R.string.login_button),
                    enabled = !busy && configured,
                    colors = ButtonDefaults.textButtonColorsPrimary(),
                    onClick = {
                        busy = true
                        status = null
                        onActivate(card.trim()) { message ->
                            busy = false
                            status = message
                        }
                    },
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(50.dp),
                )
            }
        }

        Text(
            text = "GhostLock",
            fontSize = 11.sp,
            color = MiuixTheme.colorScheme.onSurface.copy(alpha = 0.35f),
        )
    }
}
