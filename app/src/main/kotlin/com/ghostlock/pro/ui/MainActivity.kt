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
import androidx.activity.viewModels
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.viewmodel.initializer
import androidx.lifecycle.viewmodel.viewModelFactory
import com.ghostlock.pro.GhostlockApplication
import com.ghostlock.pro.R
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

class MainActivity : ComponentActivity() {
    private val viewModel by viewModels<GhostlockViewModel> {
        viewModelFactory {
            initializer {
                val app = application as GhostlockApplication
                GhostlockViewModel(app.createRepository(), app.license)
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        viewModel.initialize()
        // 主界面即入口：未激活时 UI 完全可用，激活入口在授权卡片的「激活卡密」。
        // 未激活时直接弹一次激活框，减少一次点击。
        if (!viewModel.isActivated()) {
            viewModel.openActivateDialog()
        }
        setContent {
            GhostlockRoute(viewModel, ::handleEffect)
        }
        setupSystemBars()
    }

    override fun onResume() {
        super.onResume()
        // 回前台时向服务端核对一次卡密状态（删卡/封卡/过期立刻生效）。
        // 有本地凭据且核对失败才退回未激活态并弹激活框；离线时保持界面，
        // 由 fetchSessionKey 的 fail-closed 兜底（没有 Kd 就提不了权）。
        lifecycleScope.launch { viewModel.verifyOnResume() }
    }

    private fun handleEffect(effect: GhostlockEffect) {
        when (effect) {
            is GhostlockEffect.Toast -> Toast.makeText(this, effect.resourceId, Toast.LENGTH_SHORT).show()
            is GhostlockEffect.Message -> Toast.makeText(this, effect.text, Toast.LENGTH_LONG).show()
            is GhostlockEffect.Clipboard -> {
                getSystemService(ClipboardManager::class.java)
                    ?.setPrimaryClip(ClipData.newPlainText("ghostlock-log", effect.text))
            }

            is GhostlockEffect.KeepScreenAwake -> if (effect.enabled) {
                window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
            } else {
                window.clearFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
            }

            GhostlockEffect.LicenseExpired -> viewModel.onLicenseRevoked()
        }
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
private fun GhostlockRoute(
    viewModel: GhostlockViewModel,
    onEffect: (GhostlockEffect) -> Unit,
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    LaunchedEffect(viewModel.effects) {
        viewModel.effects.collect(onEffect)
    }
    // 前台周期性到期检查：付费卡也可能带限期，到点立即收回并退回登录。
    LaunchedEffect(state.isLicensed) {
        while (state.isLicensed) {
            if (!viewModel.checkLicenseNow()) break
            delay(30_000)
        }
    }
    GhostlockApp(
        state = state,
        actions = object : GhostlockActions {
            override fun onRun() = viewModel.onRun()
            override fun onCloseExecutionSheet() = viewModel.onCloseExecutionSheet()
            override fun onCopyLogs() = viewModel.copyLogs()
            override fun onClearLogs() = viewModel.clearLogs()
            override fun onOpenActivateDialog() = viewModel.openActivateDialog()
            override fun onSafeModeChanged(enabled: Boolean) = viewModel.toggleSafeMode(enabled)
            override fun onCpuPairSelected(index: Int) = viewModel.onCpuPairSelected(index)
            override fun onDialogInputChange(value: String) = viewModel.onDialogInputChange(value)
            override fun onDialogConfirm(value: String) = viewModel.onDialogConfirm(value)
            override fun onDialogDismiss() = viewModel.onDialogDismiss()
            override fun onDialogDismissFinished() = viewModel.onDialogDismissFinished()
        },
    )
}
