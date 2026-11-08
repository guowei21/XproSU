package com.xprosu

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.enableEdgeToEdge
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.compose.material3.SnackbarHostState
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.xprosu.ui.AppRoot
import com.xprosu.ui.IcTimerTheme

class MainActivity : ComponentActivity() {

    private val vm: MainViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
        setContent {
            IcTimerTheme {
                val state by vm.state.collectAsStateWithLifecycle()
                val snackbar = remember { SnackbarHostState() }

                LaunchedEffect(state.toast) {
                    val msg = state.toast ?: return@LaunchedEffect
                    snackbar.showSnackbar(msg)
                    vm.consumeToast()
                }

                // 前台服务要发通知，Android 13+ 必须先拿到通知权限
                val notifPerm = rememberLauncherForActivityResult(
                    ActivityResultContracts.RequestPermission(),
                ) { }
                LaunchedEffect(Unit) {
                    if (Build.VERSION.SDK_INT >= 33 &&
                        checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) !=
                        PackageManager.PERMISSION_GRANTED
                    ) {
                        notifPerm.launch(Manifest.permission.POST_NOTIFICATIONS)
                    }
                }

                val picker = rememberLauncherForActivityResult(
                    ActivityResultContracts.OpenDocument(),
                ) { uri ->
                    if (uri != null) {
                        runCatching {
                            contentResolver.takePersistableUriPermission(
                                uri,
                                Intent.FLAG_GRANT_READ_URI_PERMISSION,
                            )
                        }
                        vm.parseOffsets(uri)
                    }
                }

                AppRoot(
                    state = state,
                    snackbar = snackbar,
                    onConnect = vm::connect,
                    onPair = vm::startPairing,
                    onSubmitCode = vm::submitPairingCode,
                    onOpenWireless = vm::openWirelessDebugging,
                    onRun = vm::run,
                    onDiag = vm::diag,
                    onParse = { picker.launch(arrayOf("*/*")) },
                    onKsu = vm::setKsuIndex,
                    onSafeMode = vm::setSafeMode,
                    onClearLog = vm::clearLog,
                )
            }
        }
    }
}
