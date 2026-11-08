package com.xprosu.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material3.BottomSheetDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import com.xprosu.AppState

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AppRoot(
    state: AppState,
    snackbar: SnackbarHostState,
    onConnect: () -> Unit,
    onPair: () -> Unit,
    onSubmitCode: (String) -> Unit,
    onOpenWireless: () -> Unit,
    onRun: () -> Unit,
    onDiag: () -> Unit,
    onParse: () -> Unit,
    onKsu: (Int) -> Unit,
    onSafeMode: (Boolean) -> Unit,
    onClearLog: () -> Unit,
) {
    var logOpen by rememberSaveable { mutableStateOf(false) }
    var manualOpen by rememberSaveable { mutableStateOf(false) }
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)

    Scaffold(snackbarHost = { SnackbarHost(snackbar) }) { padding ->
        Box(Modifier.fillMaxSize().padding(padding)) {
            HomeScreen(
                state = state,
                onConnect = onConnect,
                onPair = onPair,
                onSubmitCode = onSubmitCode,
                onOpenWireless = onOpenWireless,
                onRun = onRun,
                onLog = { logOpen = true },
                onParse = onParse,
                onKsu = onKsu,
                onSafeMode = onSafeMode,
                onManual = { manualOpen = true },
            )
        }
    }

    if (logOpen) {
        ModalBottomSheet(
            onDismissRequest = { logOpen = false },
            sheetState = sheetState,
            containerColor = MaterialTheme.colorScheme.surface,
            dragHandle = { BottomSheetDefaults.DragHandle() },
        ) {
            LogSheet(
                state = state,
                onClear = onClearLog,
                onDiag = onDiag,
            )
        }
    }

    if (manualOpen) {
        ManualDialog(onClose = { manualOpen = false })
    }
}

@Composable
private fun ManualDialog(onClose: () -> Unit) {
    val context = LocalContext.current
    val manual = remember {
        runCatching {
            context.assets.open("manual.md").bufferedReader().use { it.readText() }
        }.getOrElse { "# 使用手册\n\n手册内容读取失败。" }
    }
    Dialog(
        onDismissRequest = onClose,
        properties = DialogProperties(usePlatformDefaultWidth = false),
    ) {
        Surface(Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.surface) {
            Column(Modifier.safeDrawingPadding()) {
                Row(
                    modifier = Modifier.fillMaxWidth().padding(start = 20.dp, end = 8.dp, top = 8.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text(
                        "使用手册",
                        style = MaterialTheme.typography.titleLarge,
                        modifier = Modifier.weight(1f),
                    )
                    IconButton(onClick = onClose) {
                        Icon(Icons.Filled.Close, contentDescription = "关闭")
                    }
                }
                HorizontalDivider()
                ManualBody(
                    text = manual,
                    modifier = Modifier
                        .weight(1f)
                        .verticalScroll(rememberScrollState())
                        .padding(horizontal = 20.dp, vertical = 12.dp),
                )
            }
        }
    }
}

private val NUMBERED = Regex("^\\d+\\.\\s.*")

@Composable
private fun ManualBody(text: String, modifier: Modifier = Modifier) {
    val lines = remember(text) { text.lines() }
    Column(modifier = modifier, verticalArrangement = Arrangement.spacedBy(6.dp)) {
        lines.forEach { raw ->
            val line = raw.trimEnd()
            when {
                line.isBlank() -> Spacer(Modifier.height(4.dp))
                line.startsWith("## ") -> Text(
                    line.removePrefix("## "),
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold,
                    color = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.padding(top = 10.dp),
                )
                line.startsWith("# ") -> Text(
                    line.removePrefix("# "),
                    style = MaterialTheme.typography.headlineSmall,
                )
                line.startsWith("- ") -> BulletLine(line.removePrefix("- "))
                NUMBERED.matches(line) -> NumberedLine(
                    line.substringBefore('.').trim(),
                    line.substringAfter('.').trim(),
                )
                else -> Text(rich(line), style = MaterialTheme.typography.bodyMedium)
            }
        }
    }
}

@Composable
private fun BulletLine(text: String) {
    Row(Modifier.fillMaxWidth()) {
        Text(
            "·",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.primary,
            modifier = Modifier.padding(end = 8.dp),
        )
        Text(rich(text), style = MaterialTheme.typography.bodyMedium, modifier = Modifier.weight(1f))
    }
}

@Composable
private fun NumberedLine(number: String, text: String) {
    Row(Modifier.fillMaxWidth()) {
        Text(
            "$number.",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.primary,
            modifier = Modifier.padding(end = 8.dp),
        )
        Text(rich(text), style = MaterialTheme.typography.bodyMedium, modifier = Modifier.weight(1f))
    }
}

/** 只处理 **粗体** 和 `代码`，够手册用了。 */
private fun rich(text: String): AnnotatedString = buildAnnotatedString {
    var i = 0
    while (i < text.length) {
        val boldAt = text.indexOf("**", i)
        val codeAt = text.indexOf('`', i)
        val next = listOf(boldAt, codeAt).filter { it >= 0 }.minOrNull()
        if (next == null) {
            append(text.substring(i))
            break
        }
        append(text.substring(i, next))
        if (next == boldAt) {
            val end = text.indexOf("**", next + 2)
            if (end < 0) {
                append(text.substring(next))
                break
            }
            withStyle(SpanStyle(fontWeight = FontWeight.SemiBold)) {
                append(text.substring(next + 2, end))
            }
            i = end + 2
        } else {
            val end = text.indexOf('`', next + 1)
            if (end < 0) {
                append(text.substring(next))
                break
            }
            withStyle(SpanStyle(fontFamily = FontFamily.Monospace)) {
                append(text.substring(next + 1, end))
            }
            i = end + 1
        }
    }
}
