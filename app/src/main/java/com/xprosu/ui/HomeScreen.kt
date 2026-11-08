package com.xprosu.ui

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.KeyboardArrowDown
import androidx.compose.material.icons.filled.KeyboardArrowUp
import androidx.compose.material.icons.filled.List
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.xprosu.AppState
import com.xprosu.KSU_NAMES
import com.xprosu.adb.AdbSessionBus
import com.xprosu.core.StagePhase
import com.xprosu.core.StageStatus

@Composable
fun HomeScreen(
    state: AppState,
    onConnect: () -> Unit,
    onPair: () -> Unit,
    onSubmitCode: (String) -> Unit,
    onOpenWireless: () -> Unit,
    onRun: () -> Unit,
    onLog: () -> Unit,
    onParse: () -> Unit,
    onKsu: (Int) -> Unit,
    onSafeMode: (Boolean) -> Unit,
    onManual: () -> Unit,
) {
    val done = state.stages.count { it.phase == StagePhase.DONE }
    val current = state.stages.firstOrNull { it.phase == StagePhase.RUNNING }

    var codeDialog by rememberSaveable { mutableStateOf(false) }
    // 配对码默认在通知栏里填（配对对话框还在设置页，切走就会丢），
    // 这个弹窗只给通知栏不好用时兜底。
    LaunchedEffect(state.link.phase) {
        if (state.link.phase == AdbSessionBus.Phase.CONNECTED) codeDialog = false
    }
    if (codeDialog) {
        PairingCodeDialog(
            port = state.link.port,
            onDismiss = { codeDialog = false },
            onConfirm = { code ->
                codeDialog = false
                onSubmitCode(code)
            },
        )
    }

    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(start = 20.dp, end = 20.dp, top = 12.dp, bottom = 32.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        item {
            HeroCard(
                state = state,
                currentStage = current?.title,
                onConnect = onConnect,
                onPair = onPair,
                onOpenWireless = onOpenWireless,
                onManualCode = { codeDialog = true },
                onRun = onRun,
            )
        }
        item { ProgressCard(state.stages, done, current?.title) }
        item { ToolsRow(state, onLog, onParse) }
        item { SettingsCard(state, onKsu, onSafeMode) }
        item { ManualFooter(onManual) }
    }
}

@Composable
private fun HeroCard(
    state: AppState,
    currentStage: String?,
    onConnect: () -> Unit,
    onPair: () -> Unit,
    onOpenWireless: () -> Unit,
    onManualCode: () -> Unit,
    onRun: () -> Unit,
) {
    val phase = state.link.phase
    val status = when {
        state.running -> "运行中"
        state.connected -> "已就绪"
        phase == AdbSessionBus.Phase.CODE_REQUIRED -> "等待配对码"
        phase == AdbSessionBus.Phase.NEEDS_PAIRING -> "需要配对"
        phase == AdbSessionBus.Phase.ERROR -> "连接失败"
        phase == AdbSessionBus.Phase.CONNECTED -> "已连接"
        phase == AdbSessionBus.Phase.CONNECTING -> "正在连接"
        phase != AdbSessionBus.Phase.IDLE -> "正在配对"
        else -> "未连接"
    }
    val tint = when {
        state.running -> MaterialTheme.colorScheme.tertiary
        state.connected -> MaterialTheme.colorScheme.primary
        phase == AdbSessionBus.Phase.ERROR -> MaterialTheme.colorScheme.error
        else -> MaterialTheme.colorScheme.outline
    }
    val hint = when {
        state.running -> currentStage?.let { "正在执行：$it" } ?: "正在执行"
        state.connected -> state.identity.lineSequence().firstOrNull().orEmpty()
        phase == AdbSessionBus.Phase.CONNECTED ->
            "ADB 已连上，但 shell 通道没响应：点「重试连接」"
        phase == AdbSessionBus.Phase.NEEDS_PAIRING ->
            "去设置 › 无线调试 › 使用配对码配对设备，然后下拉通知栏输入 6 位码"
        phase == AdbSessionBus.Phase.CODE_REQUIRED ->
            "下拉通知栏，点「输入配对码」填入设置里显示的 6 位数字"
        phase != AdbSessionBus.Phase.IDLE -> state.link.message ?: "配对进行中"
        else -> "走本机无线调试直连 adbd，不再需要 Shizuku"
    }

    Surface(
        shape = RoundedCornerShape(28.dp),
        color = MaterialTheme.colorScheme.surfaceContainerHigh,
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(Modifier.padding(20.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Box(Modifier.size(10.dp).clip(CircleShape).background(tint))
                Spacer(Modifier.width(10.dp))
                Text(
                    status,
                    style = MaterialTheme.typography.titleLarge,
                    fontWeight = FontWeight.SemiBold,
                )
                Spacer(Modifier.weight(1f))
                DeviceBadge(state)
            }
            Spacer(Modifier.height(14.dp))
            Text(
                if (state.device.isNotBlank()) state.device.trim() else "未读取到设备信息",
                style = MaterialTheme.typography.bodySmall,
                fontFamily = FontFamily.Monospace,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 3,
                overflow = TextOverflow.Ellipsis,
            )
            Spacer(Modifier.height(18.dp))
            Button(
                onClick = onRun,
                enabled = state.connected && !state.running,
                modifier = Modifier.fillMaxWidth().height(56.dp),
                shape = RoundedCornerShape(18.dp),
                colors = ButtonDefaults.buttonColors(
                    containerColor = MaterialTheme.colorScheme.primary,
                    contentColor = MaterialTheme.colorScheme.onPrimary,
                ),
            ) {
                if (state.running) {
                    CircularProgressIndicator(
                        modifier = Modifier.size(18.dp),
                        strokeWidth = 2.dp,
                        color = MaterialTheme.colorScheme.onPrimary,
                    )
                    Spacer(Modifier.width(10.dp))
                    Text("运行中…", style = MaterialTheme.typography.titleMedium)
                } else {
                    Icon(Icons.Filled.PlayArrow, contentDescription = null, modifier = Modifier.size(22.dp))
                    Spacer(Modifier.width(8.dp))
                    Text("一键越狱", style = MaterialTheme.typography.titleMedium)
                }
            }
            Spacer(Modifier.height(10.dp))
            Text(
                hint,
                style = MaterialTheme.typography.labelSmall,
                fontFamily = if (state.connected) FontFamily.Monospace else FontFamily.Default,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            if (!state.connected) {
                TextButton(
                    onClick = onConnect,
                    modifier = Modifier.fillMaxWidth().padding(top = 4.dp),
                ) {
                    Text(if (phase == AdbSessionBus.Phase.IDLE) "连接（无线 ADB）" else "重试连接")
                }
                TextButton(
                    onClick = onPair,
                    modifier = Modifier.fillMaxWidth(),
                ) { Text("用配对码重新配对") }
                if (phase == AdbSessionBus.Phase.CODE_REQUIRED) {
                    TextButton(
                        onClick = onManualCode,
                        modifier = Modifier.fillMaxWidth(),
                    ) { Text("在本页输入配对码（备用）") }
                }
                TextButton(
                    onClick = onOpenWireless,
                    modifier = Modifier.fillMaxWidth(),
                ) { Text("打开无线调试设置") }
            }
        }
    }
}

@Composable
private fun DeviceBadge(state: AppState) {
    val label = when {
        state.device.isBlank() -> null
        else -> state.device.lineSequence().firstOrNull { it.contains("V") || it.contains("PD") }
    } ?: return
    Surface(
        shape = CircleShape,
        color = MaterialTheme.colorScheme.secondaryContainer,
    ) {
        Text(
            label.trim(),
            modifier = Modifier.padding(horizontal = 10.dp, vertical = 4.dp),
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSecondaryContainer,
        )
    }
}

@Composable
private fun ProgressCard(stages: List<StageStatus>, done: Int, currentStage: String?) {
    var expanded by rememberSaveable { mutableStateOf(false) }
    val total = stages.size
    val progress = if (total == 0) 0f else done.toFloat() / total

    Surface(
        shape = RoundedCornerShape(24.dp),
        color = MaterialTheme.colorScheme.surfaceContainer,
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(Modifier.padding(20.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text("运行阶段", style = MaterialTheme.typography.titleSmall)
                Spacer(Modifier.weight(1f))
                Text(
                    "$done / $total",
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.primary,
                )
            }
            Spacer(Modifier.height(12.dp))
            LinearProgressIndicator(
                progress = { progress },
                modifier = Modifier.fillMaxWidth().height(6.dp).clip(CircleShape),
                color = MaterialTheme.colorScheme.primary,
                trackColor = MaterialTheme.colorScheme.surfaceContainerHighest,
            )
            Spacer(Modifier.height(12.dp))
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    currentStage ?: if (done == total && total > 0) "全部完成" else "等待开始",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.weight(1f),
                )
                TextButton(onClick = { expanded = !expanded }) {
                    Text(if (expanded) "收起" else "详情")
                    Icon(
                        if (expanded) Icons.Filled.KeyboardArrowUp else Icons.Filled.KeyboardArrowDown,
                        contentDescription = null,
                        modifier = Modifier.size(18.dp),
                    )
                }
            }
            AnimatedVisibility(visible = expanded) {
                Column(Modifier.padding(top = 4.dp)) {
                    stages.forEachIndexed { index, stage ->
                        StageRow(index + 1, stage)
                    }
                }
            }
        }
    }
}

@Composable
private fun StageRow(number: Int, stage: StageStatus) {
    val tint = when (stage.phase) {
        StagePhase.DONE -> MaterialTheme.colorScheme.primary
        StagePhase.RUNNING -> MaterialTheme.colorScheme.tertiary
        StagePhase.PENDING -> MaterialTheme.colorScheme.outlineVariant
    }
    Row(
        modifier = Modifier.fillMaxWidth().padding(vertical = 5.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Box(Modifier.size(7.dp).clip(CircleShape).background(tint))
        Spacer(Modifier.width(12.dp))
        Text(
            "$number. ${stage.title}",
            style = MaterialTheme.typography.bodySmall,
            fontWeight = if (stage.phase == StagePhase.RUNNING) FontWeight.SemiBold else FontWeight.Normal,
            modifier = Modifier.weight(1f),
        )
        Text(
            when (stage.phase) {
                StagePhase.DONE -> "完成"
                StagePhase.RUNNING -> "进行中"
                StagePhase.PENDING -> "等待"
            },
            style = MaterialTheme.typography.labelSmall,
            color = if (stage.phase == StagePhase.PENDING) {
                MaterialTheme.colorScheme.outline
            } else {
                tint
            },
        )
    }
}

@Composable
private fun ToolsRow(
    state: AppState,
    onLog: () -> Unit,
    onParse: () -> Unit,
) {
    Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
        ToolCard("日志", Icons.Filled.List, true, onLog, Modifier.weight(1f))
        ToolCard("解析偏移", Icons.Filled.Search, state.connected, onParse, Modifier.weight(1f))
    }
}

@Composable
private fun ToolCard(
    label: String,
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    enabled: Boolean,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val content = if (enabled) MaterialTheme.colorScheme.onSurface else MaterialTheme.colorScheme.outline
    Surface(
        shape = RoundedCornerShape(20.dp),
        color = MaterialTheme.colorScheme.surfaceContainer,
        modifier = modifier
            .height(84.dp)
            .clip(RoundedCornerShape(20.dp))
            .clickable(enabled = enabled, onClick = onClick),
    ) {
        Column(
            modifier = Modifier.fillMaxSize(),
            verticalArrangement = Arrangement.Center,
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Icon(icon, contentDescription = null, tint = content, modifier = Modifier.size(24.dp))
            Spacer(Modifier.height(6.dp))
            Text(label, style = MaterialTheme.typography.labelMedium, color = content)
        }
    }
}

@Composable
private fun SettingsCard(state: AppState, onKsu: (Int) -> Unit, onSafeMode: (Boolean) -> Unit) {
    var expanded by remember { mutableStateOf(false) }

    Surface(
        shape = RoundedCornerShape(24.dp),
        color = MaterialTheme.colorScheme.surfaceContainer,
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(Modifier.padding(horizontal = 20.dp, vertical = 16.dp)) {
            Text("运行选项", style = MaterialTheme.typography.titleSmall)
            Spacer(Modifier.height(6.dp))
            Box {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(14.dp))
                        .clickable { expanded = true }
                        .padding(vertical = 12.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Column(Modifier.weight(1f)) {
                        Text("Root 管理器", style = MaterialTheme.typography.bodyMedium)
                        Text(
                            KSU_NAMES[state.ksuIndex] +
                                if (state.detectedManager.isNotEmpty()) " · ${state.detectedManager}" else "",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                        )
                    }
                    Icon(
                        Icons.Filled.KeyboardArrowDown,
                        contentDescription = "选择管理器",
                        tint = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                DropdownMenu(expanded = expanded, onDismissRequest = { expanded = false }) {
                    KSU_NAMES.forEachIndexed { index, name ->
                        DropdownMenuItem(
                            text = { Text(name) },
                            onClick = {
                                onKsu(index)
                                expanded = false
                            },
                        )
                    }
                }
            }
            HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
            Row(
                modifier = Modifier.fillMaxWidth().padding(top = 10.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Column(Modifier.weight(1f)) {
                    Text("安全模式", style = MaterialTheme.typography.bodyMedium)
                    Text(
                        "提权时禁用全部 KSU 模块",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                Switch(checked = state.safeMode, onCheckedChange = onSafeMode)
            }
        }
    }
}

@Composable
private fun ManualFooter(onManual: () -> Unit) {
    TextButton(
        onClick = onManual,
        modifier = Modifier.fillMaxWidth(),
    ) {
        Text("使用手册与支持机型", style = MaterialTheme.typography.labelLarge)
    }
}

/** 配对码输入框：无线调试那边给的是 6 位数字，填完直接去配对。 */
@Composable
private fun PairingCodeDialog(
    port: Int,
    onDismiss: () -> Unit,
    onConfirm: (String) -> Unit,
) {
    var code by rememberSaveable { mutableStateOf("") }
    val ready = code.length == 6
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("输入配对码") },
        text = {
            Column {
                Text(
                    "在系统“无线调试”里点“使用配对码配对设备”，把弹出的 6 位码填到这里。",
                    style = MaterialTheme.typography.bodyMedium,
                )
                if (port > 0) {
                    Text(
                        "配对端口 $port",
                        style = MaterialTheme.typography.bodySmall,
                        fontFamily = FontFamily.Monospace,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(top = 8.dp),
                    )
                }
                OutlinedTextField(
                    value = code,
                    onValueChange = { raw ->
                        code = raw.filter { it.isDigit() }.take(6)
                    },
                    singleLine = true,
                    label = { Text("6 位配对码") },
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
                    modifier = Modifier.fillMaxWidth().padding(top = 12.dp),
                )
            }
        },
        confirmButton = {
            TextButton(onClick = { onConfirm(code) }, enabled = ready) { Text("配对") }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text("取消") }
        },
    )
}
