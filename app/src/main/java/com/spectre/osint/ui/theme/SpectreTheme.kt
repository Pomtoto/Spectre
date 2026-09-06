package com.spectre.osint.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable

@Composable
fun SpectreTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = SpectreColors,
        typography = SpectreTypography,
        content = content
    )
}
