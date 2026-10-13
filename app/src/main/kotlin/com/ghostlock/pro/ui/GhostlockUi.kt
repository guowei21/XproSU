package com.ghostlock.pro.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Lock
import androidx.compose.material.icons.rounded.Security
import androidx.compose.material.icons.rounded.WarningAmber
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.ghostlock.pro.R
import top.yukonga.miuix.kmp.basic.ButtonDefaults
import top.yukonga.miuix.kmp.basic.Card
import top.yukonga.miuix.kmp.basic.CardDefaults
import top.yukonga.miuix.kmp.basic.Icon
import top.yukonga.miuix.kmp.basic.IconButton
import top.yukonga.miuix.kmp.basic.MiuixScrollBehavior
import top.yukonga.miuix.kmp.basic.Scaffold
import top.yukonga.miuix.kmp.basic.ScrollBehavior
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.basic.TextButton
import top.yukonga.miuix.kmp.basic.TextField
import top.yukonga.miuix.kmp.basic.TopAppBar
import top.yukonga.miuix.kmp.basic.rememberTopAppBarState
import top.yukonga.miuix.kmp.icon.MiuixIcons
import top.yukonga.miuix.kmp.icon.extended.Close
import top.yukonga.miuix.kmp.icon.extended.Copy
import top.yukonga.miuix.kmp.overlay.OverlayBottomSheet
import top.yukonga.miuix.kmp.overlay.OverlayDialog
import top.yukonga.miuix.kmp.preference.SwitchPreference
import top.yukonga.miuix.kmp.theme.MiuixTheme
import top.yukonga.miuix.kmp.theme.darkColorScheme
import top.yukonga.miuix.kmp.theme.lightColorScheme
import top.yukonga.miuix.kmp.utils.overScrollVertical


data class GhostlockUiState(
    val deviceName: String = "",
    val kernelRelease: String = "",
    val socName: String = "",
    val kernelSupported: Boolean = false,
    val running: Boolean = false,
    val safeModeEnabled: Boolean = false,
    val executionSheetVisible: Boolean = false,
    val executionSheetDismissible: Boolean = false,
    val dialogVisible: Boolean = false,
    val dialogType: DialogType = DialogType.NONE,
    val dialogTitleRes: Int = 0,
    val dialogMessageRes: Int = 0,
    val dialogInput: String = "",
    val logLines: List<GhostlockLogLine> = emptyList(),
    val deviceId: String = "",
    val isLicensed: Boolean = false,
    val lastRunFailed: Boolean = false,
    /** 构建期是否已配置 U验证 服务凭据。 */
    val licenseConfigured: Boolean = false,
    /** 服务端返回的到期时间原文，仅用于展示。 */
    val licenseExpiry: String = "",
    /** 正在向服务端校验卡密。 */
    val activating: Boolean = false,
    /** 提权进度 0..100，Release 交付版以此替代明文日志。 */
    val progress: Int = 0,
    /** 当前阶段名资源；0 表示尚未进入任何阶段。 */
    val progressLabelRes: Int = 0,
    /** 本机可用核心对标签；UI 会在其前面补一项「自动优选」。 */
    val cpuPairLabels: List<String> = emptyList(),
    /** 0 = 自动优选，其余为 [cpuPairLabels] 的下标 + 1。 */
    val cpuPairIndex: Int = -1,
    /** 明文运行日志是否可见：仅 Debug 构建为 true。 */
    val logsVisible: Boolean = false,
)

enum class DialogType { NONE, INPUT }

data class GhostlockLogLine(val text: String, val color: Int)

interface GhostlockActions {
    fun onRun()
    fun onCloseExecutionSheet()
    fun onCopyLogs()
    fun onClearLogs() = Unit
    fun onCopyDeviceId() = Unit
    fun onOpenActivateDialog() = Unit
    fun onSafeModeChanged(enabled: Boolean)
    fun onCpuPairSelected(index: Int) = Unit
    fun onDialogInputChange(value: String)
    fun onDialogConfirm(value: String)
    fun onDialogDismiss()
    fun onDialogDismissFinished()
}

@Composable
internal fun GhostlockApp(
    state: GhostlockUiState,
    actions: GhostlockActions,
) {
    val scrollBehavior = MiuixScrollBehavior(rememberTopAppBarState())
    MiuixTheme(
        colors = if (isSystemInDarkTheme()) darkColorScheme() else lightColorScheme(),
    ) {
        Scaffold(
            modifier = Modifier.fillMaxSize(),
            topBar = {
                TopAppBar(
                    title = "GhostLock",
                    scrollBehavior = scrollBehavior,
                    actions = {},
                )
            },
        ) { paddingValues ->
            BoxWithConstraints(
                modifier = Modifier.fillMaxSize(),
            ) {
                if (maxWidth < 768.dp) {
                    PortraitContent(
                        state = state,
                        actions = actions,
                        scrollBehavior = scrollBehavior,
                        modifier = Modifier
                            .fillMaxSize()
                            .padding(paddingValues),
                    )
                } else {
                    LandscapeContent(
                        state = state,
                        actions = actions,
                        scrollBehavior = scrollBehavior,
                        modifier = Modifier
                            .fillMaxSize()
                            .padding(paddingValues),
                    )
                }
            }
            GhostlockDialog(state = state, actions = actions)
            GhostlockExecutionSheet(state = state, actions = actions)
        }
    }
}

@Composable
private fun PortraitContent(
    state: GhostlockUiState,
    actions: GhostlockActions,
    scrollBehavior: ScrollBehavior,
    modifier: Modifier = Modifier,
) {
    LazyColumn(
        modifier = modifier
            .overScrollVertical()
            .fillMaxHeight()
            .nestedScroll(scrollBehavior.nestedScrollConnection)
            .imePadding(),
        contentPadding = PaddingValues(horizontal = 14.dp, vertical = 8.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        item(key = "hero") {
            HeroStatusCard(
                supported = state.kernelSupported,
                deviceName = state.deviceName,
                socName = state.socName,
                kernelRelease = state.kernelRelease,
                modifier = Modifier.fillMaxWidth(),
            )
        }
        item(key = "license") {
            LicenseCard(
                deviceId = state.deviceId,
                isLicensed = state.isLicensed,
                configured = state.licenseConfigured,
                expiry = state.licenseExpiry,
                onCopyId = actions::onCopyDeviceId,
                onActivateClick = actions::onOpenActivateDialog,
                modifier = Modifier.fillMaxWidth(),
            )
        }
        item(key = "run") {
            RunButton(
                running = state.running,
                supported = state.kernelSupported,
                isLicensed = state.isLicensed,
                lastRunFailed = state.lastRunFailed,
                progress = state.progress,
                progressLabelRes = state.progressLabelRes,
                showProgress = !state.logsVisible && (state.running || state.progress > 0),
                onClick = actions::onRun,
                modifier = Modifier.fillMaxWidth(),
            )
        }
        item(key = "maintenance") {
            MaintenanceCard(
                safeModeEnabled = state.safeModeEnabled,
                onSafeModeChanged = actions::onSafeModeChanged,
                cpuPairLabels = state.cpuPairLabels,
                cpuPairIndex = state.cpuPairIndex,
                onCpuPairSelected = actions::onCpuPairSelected,
                modifier = Modifier.fillMaxWidth(),
            )
        }
        // 交付版不显示明文运行日志，整块终端卡片一并隐藏。
        if (state.logsVisible) {
            item(key = "terminal") {
                ConsoleMonitorCard(
                    lines = state.logLines,
                    onCopy = actions::onCopyLogs,
                    onClear = actions::onClearLogs,
                    modifier = Modifier.fillMaxWidth(),
                )
            }
        }
    }
}

@Composable
private fun LandscapeContent(
    state: GhostlockUiState,
    actions: GhostlockActions,
    scrollBehavior: ScrollBehavior,
    modifier: Modifier = Modifier,
) {
    Row(
        modifier = modifier.padding(horizontal = 14.dp, vertical = 8.dp),
        horizontalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        Column(
            modifier = Modifier
                .weight(1f)
                .fillMaxHeight(),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            HeroStatusCard(
                supported = state.kernelSupported,
                deviceName = state.deviceName,
                socName = state.socName,
                kernelRelease = state.kernelRelease,
                modifier = Modifier.fillMaxWidth(),
            )
            LicenseCard(
                deviceId = state.deviceId,
                isLicensed = state.isLicensed,
                configured = state.licenseConfigured,
                expiry = state.licenseExpiry,
                onCopyId = actions::onCopyDeviceId,
                onActivateClick = actions::onOpenActivateDialog,
                modifier = Modifier.fillMaxWidth(),
            )
            RunButton(
                running = state.running,
                supported = state.kernelSupported,
                isLicensed = state.isLicensed,
                lastRunFailed = state.lastRunFailed,
                progress = state.progress,
                progressLabelRes = state.progressLabelRes,
                showProgress = !state.logsVisible && (state.running || state.progress > 0),
                onClick = actions::onRun,
                modifier = Modifier.fillMaxWidth(),
            )
        }
        Column(
            modifier = Modifier
                .weight(1f)
                .fillMaxHeight(),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            MaintenanceCard(
                safeModeEnabled = state.safeModeEnabled,
                onSafeModeChanged = actions::onSafeModeChanged,
                cpuPairLabels = state.cpuPairLabels,
                cpuPairIndex = state.cpuPairIndex,
                onCpuPairSelected = actions::onCpuPairSelected,
                modifier = Modifier.fillMaxWidth(),
            )
            if (state.logsVisible) {
                ConsoleMonitorCard(
                    lines = state.logLines,
                    onCopy = actions::onCopyLogs,
                    onClear = actions::onClearLogs,
                    modifier = Modifier.weight(1f),
                )
            }
        }
    }
}

/**
 * 1. 状态总览 Hero 综合卡片
 */
@Composable
private fun HeroStatusCard(
    supported: Boolean,
    deviceName: String,
    socName: String,
    kernelRelease: String,
    modifier: Modifier = Modifier,
) {
    val isDark = isSystemInDarkTheme()
    val badgeBg = if (supported) {
        if (isDark) Color(0xFF064E3B) else Color(0xFFECFDF5)
    } else {
        if (isDark) Color(0xFF78350F) else Color(0xFFFFFBEB)
    }
    val badgeColor = if (supported) {
        if (isDark) Color(0xFF6EE7B7) else Color(0xFF059669)
    } else {
        if (isDark) Color(0xFFFDE68A) else Color(0xFFD97706)
    }
    val iconBg = if (supported) {
        if (isDark) Color(0xFF064E3B) else Color(0xFFECFDF5)
    } else {
        if (isDark) Color(0xFF78350F) else Color(0xFFFFFBEB)
    }
    val iconTint = if (supported) {
        if (isDark) Color(0xFF34D399) else Color(0xFF10B981)
    } else {
        if (isDark) Color(0xFFFBBF24) else Color(0xFFF59E0B)
    }

    Card(
        modifier = modifier,
        insideMargin = PaddingValues(16.dp),
    ) {
        Column(
            modifier = Modifier.fillMaxWidth(),
            verticalArrangement = Arrangement.spacedBy(14.dp),
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(14.dp),
            ) {
                Box(
                    modifier = Modifier
                        .size(50.dp)
                        .clip(RoundedCornerShape(16.dp))
                        .background(iconBg),
                    contentAlignment = Alignment.Center,
                ) {
                    Icon(
                        imageVector = if (supported) Icons.Rounded.Security else Icons.Rounded.WarningAmber,
                        contentDescription = null,
                        tint = iconTint,
                        modifier = Modifier.size(28.dp),
                    )
                }

                Column(modifier = Modifier.weight(1f)) {
                    Box(
                        modifier = Modifier
                            .clip(RoundedCornerShape(6.dp))
                            .background(badgeBg)
                            .padding(horizontal = 7.dp, vertical = 2.dp),
                    ) {
                        Text(
                            text = stringResource(if (supported) R.string.kernel_supported else R.string.kernel_unsupported),
                            fontSize = 11.sp,
                            fontWeight = FontWeight.SemiBold,
                            color = badgeColor,
                        )
                    }
                    Text(
                        text = stringResource(if (supported) R.string.kernel_supported_title else R.string.kernel_unsupported_title),
                        fontSize = 17.sp,
                        fontWeight = FontWeight.Bold,
                        color = MiuixTheme.colorScheme.onSurface,
                        modifier = Modifier.padding(top = 3.dp),
                    )
                    Text(
                        text = stringResource(if (supported) R.string.kernel_supported_desc else R.string.kernel_unsupported_desc),
                        fontSize = 11.5.sp,
                        color = MiuixTheme.colorScheme.onSurface.copy(alpha = 0.65f),
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        modifier = Modifier.padding(top = 2.dp),
                    )
                }
            }

            // Inset Specs Panel
            SpecsPanel(
                deviceName = deviceName.ifEmpty { "vivo V2324A (X100 Pro)" },
                socName = socName.ifEmpty { "Dimensity 9300 (MT6989)" },
                kernelRelease = kernelRelease.ifEmpty { "6.1.145-android14-11-maybe-dirty" },
                offsetsInfo = "offsets.glt (940 B · 3组)",
            )
        }
    }
}

@Composable
private fun SpecsPanel(
    deviceName: String,
    socName: String,
    kernelRelease: String,
    offsetsInfo: String,
    modifier: Modifier = Modifier,
) {
    val isDark = isSystemInDarkTheme()
    val panelBg = if (isDark) Color(0xFF121822) else Color(0xFFF8FAFC)
    val panelBorder = if (isDark) Color(0x1AFFFFFF) else Color(0x0F000000)

    Column(
        modifier = modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(16.dp))
            .background(panelBg)
            .border(1.dp, panelBorder, RoundedCornerShape(16.dp))
            .padding(horizontal = 14.dp, vertical = 10.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        SpecRow(label = stringResource(R.string.device_label), value = deviceName)
        SpecRow(label = stringResource(R.string.soc_label), value = socName)
        SpecRow(
            label = stringResource(R.string.kernel_label),
            value = kernelRelease,
            isMono = true,
            isHighlight = true,
        )
        SpecRow(label = stringResource(R.string.offsets_label), value = offsetsInfo)
    }
}

@Composable
private fun SpecRow(
    label: String,
    value: String,
    isMono: Boolean = false,
    isHighlight: Boolean = false,
    modifier: Modifier = Modifier,
) {
    Row(
        modifier = modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            text = label,
            fontSize = 12.sp,
            color = MiuixTheme.colorScheme.onSurface.copy(alpha = 0.55f),
        )
        Text(
            text = value,
            fontSize = 11.5.sp,
            fontWeight = if (isHighlight) FontWeight.SemiBold else FontWeight.Normal,
            fontFamily = if (isMono) FontFamily.Monospace else FontFamily.Default,
            color = if (isHighlight) MiuixTheme.colorScheme.primary else MiuixTheme.colorScheme.onSurface,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
        )
    }
}

/**
 * 2. 商业化·设备授权与卡密管理卡片
 */
@Composable
private fun LicenseCard(
    deviceId: String,
    isLicensed: Boolean,
    configured: Boolean,
    expiry: String,
    onCopyId: () -> Unit,
    onActivateClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val isDark = isSystemInDarkTheme()
    val pillBg = if (isLicensed) {
        if (isDark) Color(0xFF064E3B) else Color(0xFFECFDF5)
    } else {
        if (isDark) Color(0xFF78350F) else Color(0xFFFFFBEB)
    }
    val pillColor = if (isLicensed) {
        if (isDark) Color(0xFF6EE7B7) else Color(0xFF059669)
    } else {
        if (isDark) Color(0xFFFDE68A) else Color(0xFFD97706)
    }
    val metaText = when {
        !configured -> stringResource(R.string.license_not_configured)
        isLicensed && expiry.isNotEmpty() -> stringResource(R.string.license_expiry_fmt, expiry)
        else -> stringResource(R.string.license_meta_desc)
    }

    Card(
        modifier = modifier,
        insideMargin = PaddingValues(15.dp),
    ) {
        Column(
            modifier = Modifier.fillMaxWidth(),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                ) {
                    Icon(
                        imageVector = Icons.Rounded.Lock,
                        contentDescription = null,
                        modifier = Modifier.size(15.dp),
                        tint = MiuixTheme.colorScheme.onSurface.copy(alpha = 0.7f),
                    )
                    Text(
                        text = stringResource(R.string.license_sec_title),
                        fontSize = 13.sp,
                        fontWeight = FontWeight.Bold,
                        color = MiuixTheme.colorScheme.onSurface.copy(alpha = 0.7f),
                    )
                }

                Box(
                    modifier = Modifier
                        .clip(RoundedCornerShape(999.dp))
                        .background(pillBg)
                        .padding(horizontal = 8.dp, vertical = 2.dp),
                ) {
                    Text(
                        text = "● " + stringResource(
                            if (isLicensed) R.string.license_pill_ok else R.string.license_pill_pending,
                        ),
                        fontSize = 11.sp,
                        fontWeight = FontWeight.SemiBold,
                        color = pillColor,
                    )
                }
            }

            // Device ID Box
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(12.dp))
                    .background(if (isDark) Color(0xFF121822) else Color(0xFFF8FAFC))
                    .border(
                        1.dp,
                        if (isDark) Color(0x1AFFFFFF) else Color(0x0F000000),
                        RoundedCornerShape(12.dp),
                    )
                    .padding(horizontal = 12.dp, vertical = 8.dp),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Column {
                    Text(
                        text = stringResource(R.string.license_device_id_desc),
                        fontSize = 10.5.sp,
                        color = MiuixTheme.colorScheme.onSurface.copy(alpha = 0.5f),
                    )
                    Text(
                        text = deviceId.ifEmpty { "----" },
                        fontSize = 11.sp,
                        lineHeight = 14.sp,
                        fontFamily = FontFamily.Monospace,
                        fontWeight = FontWeight.Bold,
                        color = MiuixTheme.colorScheme.onSurface,
                        modifier = Modifier.padding(top = 1.dp),
                    )
                }

                TextButton(
                    text = stringResource(R.string.action_copy),
                    onClick = onCopyId,
                    colors = ButtonDefaults.textButtonColors(),
                )
            }

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    text = metaText,
                    fontSize = 11.5.sp,
                    color = MiuixTheme.colorScheme.onSurface.copy(alpha = 0.55f),
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.weight(1f),
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    text = stringResource(R.string.action_activate_key) + " >",
                    fontSize = 12.sp,
                    fontWeight = FontWeight.SemiBold,
                    color = MiuixTheme.colorScheme.primary,
                    modifier = Modifier.clickable(onClick = onActivateClick),
                )
            }
        }
    }
}

/**
 * 3. 主操作高亮按钮 (Hero CTA)
 */
@Composable
private fun RunButton(
    running: Boolean,
    supported: Boolean,
    isLicensed: Boolean,
    lastRunFailed: Boolean,
    progress: Int,
    progressLabelRes: Int,
    showProgress: Boolean,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val buttonText = when {
        running -> stringResource(R.string.action_running)
        !supported -> stringResource(R.string.action_unsupported)
        !isLicensed -> stringResource(R.string.action_needs_activation)
        lastRunFailed -> stringResource(R.string.action_retry)
        else -> stringResource(R.string.action_run)
    }

    Column(
        modifier = modifier.fillMaxWidth(),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        if (showProgress) {
            ProgressPanel(progress = progress, labelRes = progressLabelRes)
        }
        TextButton(
            text = buttonText,
            enabled = supported && isLicensed && !running,
            colors = ButtonDefaults.textButtonColorsPrimary(),
            onClick = onClick,
            modifier = Modifier
                .fillMaxWidth()
                .height(52.dp),
        )
    }
}

/**
 * 交付版进度面板：以百分比与阶段名替代明文运行日志。
 */
@Composable
private fun ProgressPanel(progress: Int, labelRes: Int) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        insideMargin = PaddingValues(16.dp),
    ) {
        Column(
            modifier = Modifier.fillMaxWidth(),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    text = stringResource(if (labelRes != 0) labelRes else R.string.progress_preparing),
                    fontSize = 13.sp,
                    fontWeight = FontWeight.Medium,
                    color = MiuixTheme.colorScheme.onSurface,
                )
                Text(
                    text = "$progress%",
                    fontSize = 13.sp,
                    fontWeight = FontWeight.Bold,
                    color = MiuixTheme.colorScheme.primary,
                )
            }
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .height(6.dp)
                    .clip(RoundedCornerShape(3.dp))
                    .background(MiuixTheme.colorScheme.onSurface.copy(alpha = 0.10f)),
            ) {
                Box(
                    modifier = Modifier
                        .fillMaxWidth((progress / 100f).coerceIn(0f, 1f))
                        .fillMaxHeight()
                        .background(MiuixTheme.colorScheme.primary),
                )
            }
        }
    }
}

/**
 * 4. 参数配置与维护卡片
 */
@Composable
private fun MaintenanceCard(
    safeModeEnabled: Boolean,
    onSafeModeChanged: (Boolean) -> Unit,
    cpuPairLabels: List<String>,
    cpuPairIndex: Int,
    onCpuPairSelected: (Int) -> Unit,
    modifier: Modifier = Modifier,
) {
    Card(modifier = modifier) {
        Column(
            modifier = Modifier.fillMaxWidth(),
        ) {
            SwitchPreference(
                checked = safeModeEnabled,
                onCheckedChange = onSafeModeChanged,
                title = stringResource(R.string.safe_mode_label),
                summary = stringResource(R.string.safe_mode_summary),
            )

            if (cpuPairLabels.isNotEmpty()) {
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(1.dp)
                        .background(MiuixTheme.colorScheme.onSurface.copy(alpha = 0.06f)),
                )
                CpuPairSelector(
                    labels = cpuPairLabels,
                    selectedIndex = cpuPairIndex,
                    onSelect = onCpuPairSelected,
                )
            }
        }
    }
}

/**
 * 核心对选择：第 0 项固定为「自动优选」，其余为本机探测到的可用核心对。
 */
@Composable
private fun CpuPairSelector(
    labels: List<String>,
    selectedIndex: Int,
    onSelect: (Int) -> Unit,
) {
    val items = labels
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 12.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Text(
            text = stringResource(R.string.cpu_pair_label),
            fontSize = 15.sp,
            fontWeight = FontWeight.Medium,
            color = MiuixTheme.colorScheme.onSurface,
        )
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .horizontalScroll(rememberScrollState()),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            items.forEachIndexed { index, label ->
                val selected = index == selectedIndex
                Box(
                    modifier = Modifier
                        .clip(RoundedCornerShape(999.dp))
                        .background(
                            if (selected) MiuixTheme.colorScheme.primary
                            else MiuixTheme.colorScheme.onSurface.copy(alpha = 0.06f),
                        )
                        .clickable { onSelect(index) }
                        .padding(horizontal = 12.dp, vertical = 6.dp),
                ) {
                    Text(
                        text = label,
                        fontSize = 12.5.sp,
                        fontWeight = if (selected) FontWeight.SemiBold else FontWeight.Normal,
                        color = if (selected) Color.White else MiuixTheme.colorScheme.onSurface,
                    )
                }
            }
        }
    }
}

/**
 * 5. 实时工控运行终端（仅 Debug 构建展示）
 */
@Composable
private fun ConsoleMonitorCard(
    lines: List<GhostlockLogLine>,
    onCopy: () -> Unit,
    onClear: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val listState = rememberLazyListState()
    LaunchedEffect(lines.size) {
        if (lines.isNotEmpty()) listState.scrollToItem(lines.lastIndex)
    }

    Card(
        modifier = modifier,
        colors = CardDefaults.defaultColors(color = Color(0xFF090E17)),
        insideMargin = PaddingValues(14.dp),
    ) {
        Column(
            modifier = Modifier.fillMaxWidth(),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                ) {
                    Box(
                        modifier = Modifier
                            .size(6.dp)
                            .clip(CircleShape)
                            .background(Color(0xFF10B981)),
                    )
                    Text(
                        text = stringResource(R.string.console_title),
                        fontSize = 11.5.sp,
                        fontWeight = FontWeight.Bold,
                        fontFamily = FontFamily.Monospace,
                        color = Color(0xFF94A3B8),
                    )
                }

                Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    Text(
                        text = stringResource(R.string.action_clear),
                        fontSize = 11.sp,
                        color = Color(0xFF94A3B8),
                        modifier = Modifier.clickable(onClick = onClear),
                    )
                    Text(
                        text = "·",
                        fontSize = 11.sp,
                        color = Color(0xFF475569),
                    )
                    Text(
                        text = stringResource(R.string.action_copy),
                        fontSize = 11.sp,
                        color = Color(0xFF94A3B8),
                        modifier = Modifier.clickable(onClick = onCopy),
                    )
                }
            }

            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .height(140.dp)
                    .clip(RoundedCornerShape(8.dp))
                    .background(Color(0xFF06090F))
                    .padding(8.dp),
            ) {
                SelectionContainer {
                    LazyColumn(
                        state = listState,
                        modifier = Modifier.fillMaxSize(),
                    ) {
                        items(lines) { line ->
                            Text(
                                text = line.text.trimEnd('\r', '\n'),
                                color = lineColor(line.color),
                                fontFamily = FontFamily.Monospace,
                                fontSize = 10.sp,
                                lineHeight = 14.sp,
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun GhostlockExecutionSheet(
    state: GhostlockUiState,
    actions: GhostlockActions,
) {
    OverlayBottomSheet(
        show = state.executionSheetVisible,
        title = stringResource(R.string.log_title),
        allowDismiss = state.executionSheetDismissible,
        onDismissRequest = actions::onCloseExecutionSheet,
        startAction = {
            IconButton(onClick = actions::onCopyLogs) {
                Icon(
                    imageVector = MiuixIcons.Copy,
                    contentDescription = stringResource(R.string.action_copy),
                    tint = MiuixTheme.colorScheme.onBackground,
                )
            }
        },
        endAction = {
            IconButton(
                enabled = state.executionSheetDismissible,
                onClick = actions::onCloseExecutionSheet,
            ) {
                Icon(
                    imageVector = MiuixIcons.Close,
                    contentDescription = stringResource(R.string.action_close),
                )
            }
        },
        content = {
            LogPanel(
                lines = state.logLines,
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(min = 240.dp, max = 520.dp)
                    .navigationBarsPadding(),
            )
        },
    )
}

@Composable
private fun GhostlockDialog(
    state: GhostlockUiState,
    actions: GhostlockActions,
) {
    OverlayDialog(
        show = state.dialogVisible,
        title = if (state.dialogType == DialogType.NONE) null else stringResource(state.dialogTitleRes),
        onDismissRequest = actions::onDialogDismiss,
        onDismissFinished = actions::onDialogDismissFinished,
        content = {
            when (state.dialogType) {
                DialogType.INPUT -> {
                    TextField(
                        value = state.dialogInput,
                        onValueChange = actions::onDialogInputChange,
                        label = stringResource(state.dialogMessageRes),
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true,
                    )
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(top = 16.dp),
                    ) {
                        TextButton(
                            modifier = Modifier.weight(1f),
                            text = stringResource(R.string.cancel),
                            onClick = actions::onDialogDismiss,
                        )
                        Spacer(modifier = Modifier.width(12.dp))
                        TextButton(
                            modifier = Modifier.weight(1f),
                            text = if (state.activating) {
                                stringResource(R.string.action_running)
                            } else {
                                stringResource(R.string.activate_dialog_btn)
                            },
                            colors = ButtonDefaults.textButtonColorsPrimary(),
                            onClick = { actions.onDialogConfirm(state.dialogInput) },
                        )
                    }
                }

                DialogType.NONE -> Unit
            }
        },
    )
}

@Composable
private fun LogPanel(
    lines: List<GhostlockLogLine>,
    modifier: Modifier = Modifier,
) {
    val listState = rememberLazyListState()
    LaunchedEffect(lines.size) {
        if (lines.isNotEmpty()) listState.scrollToItem(lines.lastIndex)
    }
    Column(
        modifier = modifier
            .clip(RoundedCornerShape(8.dp))
            .background(Color(0xFF0B1220))
            .padding(12.dp),
    ) {
        SelectionContainer {
            LazyColumn(
                state = listState,
                modifier = Modifier
                    .fillMaxWidth()
                    .weight(1f)
                    .padding(top = 8.dp),
            ) {
                items(lines) { line ->
                    Text(
                        text = line.text.trimEnd('\r', '\n'),
                        color = lineColor(line.color),
                        fontFamily = FontFamily.Monospace,
                        fontSize = 11.sp,
                        lineHeight = 15.sp,
                    )
                }
            }
        }
    }
}

private fun lineColor(color: Int): Color = when (color) {
    0xFFFF6B6B.toInt() -> Color(0xFFFF6B6B)
    0xFF5FD68A.toInt() -> Color(0xFF5FD68A)
    0xFFFFC94D.toInt() -> Color(0xFFFFC94D)
    0xFF60A5FA.toInt() -> Color(0xFF60A5FA)
    else -> Color(0xFFD1D5DB)
}
