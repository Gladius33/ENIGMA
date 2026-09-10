package com.enigma.securechat.ui.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.ui.graphics.Color

private val LightColors = lightColorScheme(
    primary = EnigmaPrimary,
    onPrimary = Color.White,
    secondary = EnigmaSecondary,
    tertiary = EnigmaEncrypted,
    background = EnigmaBackgroundLight,
    surface = EnigmaSurfaceLight,
    surfaceVariant = Color(0xFFE9ECF3),
    error = EnigmaDanger,
)

private val DarkColors = darkColorScheme(
    primary = EnigmaPrimaryDark,
    onPrimary = Color(0xFF101318),
    secondary = EnigmaSecondary,
    tertiary = EnigmaEncrypted,
    background = EnigmaBackgroundDark,
    surface = EnigmaSurfaceDark,
    surfaceVariant = Color(0xFF232936),
    error = EnigmaDanger,
)

@Composable
fun EnigmaTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    content: @Composable () -> Unit,
) {
    MaterialTheme(
        colorScheme = if (darkTheme) DarkColors else LightColors,
        typography = EnigmaTypography,
        shapes = EnigmaShapes,
        content = content,
    )
}
