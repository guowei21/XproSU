package com.xprosu.ui

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

private val Light = lightColorScheme(
    primary = Color(0xFF0B6B53),
    onPrimary = Color(0xFFFFFFFF),
    primaryContainer = Color(0xFFB4F1DA),
    onPrimaryContainer = Color(0xFF002018),
    secondary = Color(0xFF4B635A),
    onSecondary = Color(0xFFFFFFFF),
    secondaryContainer = Color(0xFFCDE8DD),
    onSecondaryContainer = Color(0xFF072019),
    tertiary = Color(0xFF3D6373),
    onTertiary = Color(0xFFFFFFFF),
    tertiaryContainer = Color(0xFFC1E8FB),
    onTertiaryContainer = Color(0xFF001F2A),
    error = Color(0xFFBA1A1A),
    onError = Color(0xFFFFFFFF),
    errorContainer = Color(0xFFFFDAD6),
    onErrorContainer = Color(0xFF410002),
    background = Color(0xFFF6FAF7),
    onBackground = Color(0xFF171D1A),
    surface = Color(0xFFF6FAF7),
    onSurface = Color(0xFF171D1A),
    surfaceVariant = Color(0xFFDBE5DF),
    onSurfaceVariant = Color(0xFF3F4944),
    outline = Color(0xFF6F7973),
    outlineVariant = Color(0xFFBFC9C3),
    surfaceContainerLowest = Color(0xFFFFFFFF),
    surfaceContainerLow = Color(0xFFF0F5F1),
    surfaceContainer = Color(0xFFEAF0EC),
    surfaceContainerHigh = Color(0xFFE4EAE6),
    surfaceContainerHighest = Color(0xFFDEE4E0),
)

private val Dark = darkColorScheme(
    primary = Color(0xFF7FD8BA),
    onPrimary = Color(0xFF00382A),
    primaryContainer = Color(0xFF00513C),
    onPrimaryContainer = Color(0xFF9CF5D6),
    secondary = Color(0xFFB2CCC0),
    onSecondary = Color(0xFF1D352C),
    secondaryContainer = Color(0xFF334B41),
    onSecondaryContainer = Color(0xFFCDE8DD),
    tertiary = Color(0xFFA7CCE0),
    onTertiary = Color(0xFF073543),
    tertiaryContainer = Color(0xFF244C5B),
    onTertiaryContainer = Color(0xFFC1E8FB),
    error = Color(0xFFFFB4AB),
    onError = Color(0xFF690005),
    errorContainer = Color(0xFF93000A),
    onErrorContainer = Color(0xFFFFDAD6),
    background = Color(0xFF0E1513),
    onBackground = Color(0xFFDDE4DF),
    surface = Color(0xFF0E1513),
    onSurface = Color(0xFFDDE4DF),
    surfaceVariant = Color(0xFF3F4944),
    onSurfaceVariant = Color(0xFFBFC9C3),
    outline = Color(0xFF89938D),
    outlineVariant = Color(0xFF3F4944),
    surfaceContainerLowest = Color(0xFF090F0D),
    surfaceContainerLow = Color(0xFF161D1A),
    surfaceContainer = Color(0xFF1A211E),
    surfaceContainerHigh = Color(0xFF242B28),
    surfaceContainerHighest = Color(0xFF2F3633),
)

@Composable
fun IcTimerTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    content: @Composable () -> Unit,
) {
    MaterialTheme(
        colorScheme = if (darkTheme) Dark else Light,
        content = content,
    )
}
