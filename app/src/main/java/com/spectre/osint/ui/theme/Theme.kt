package com.spectre.osint.ui.theme

import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.Font
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import com.spectre.osint.R
// ── Spectre palette ──────────────────────────────────────────────
val Bg        = Color(0xFF05080A)
val Surface   = Color(0xFF0B1216)
val Surface2  = Color(0xFF101B21)
val Border    = Color(0xFF1B2B31)

val Neon      = Color(0xFF00E68C)   // primary green
val NeonGlow  = Color(0xFF0A7A4E)
val Cyan      = Color(0xFF00D2FF)
val Red       = Color(0xFFFF3B5C)
val Amber     = Color(0xFFFFB020)
val Violet    = Color(0xFF9B6BFF)

val TextHi    = Color(0xFFE6F4EE)
val TextMid   = Color(0xFF9DB3AA)
val TextDim   = Color(0xFF5C6F68)

// ── Fonts ────────────────────────────────────────────────────────
val TajawalFamily = FontFamily(
    Font(R.font.tajawal_regular, FontWeight.Normal),
    Font(R.font.tajawal_medium, FontWeight.Medium),
    Font(R.font.tajawal_bold, FontWeight.Bold),
    Font(R.font.tajawal_extrabold, FontWeight.ExtraBold),
)

val Mono = FontFamily.Monospace

val SpectreColors = darkColorScheme(
    primary = Neon,
    onPrimary = Color(0xFF00130A),
    secondary = Cyan,
    onSecondary = Color(0xFF001318),
    tertiary = Violet,
    background = Bg,
    onBackground = TextHi,
    surface = Surface,
    onSurface = TextHi,
    surfaceVariant = Surface2,
    onSurfaceVariant = TextMid,
    error = Red,
    outline = Border,
)

val SpectreTypography = Typography(
    displayLarge = androidx.compose.ui.text.TextStyle(fontFamily = TajawalFamily, fontWeight = FontWeight.ExtraBold),
    displayMedium = androidx.compose.ui.text.TextStyle(fontFamily = TajawalFamily, fontWeight = FontWeight.ExtraBold),
    headlineLarge = androidx.compose.ui.text.TextStyle(fontFamily = TajawalFamily, fontWeight = FontWeight.Bold),
    headlineMedium = androidx.compose.ui.text.TextStyle(fontFamily = TajawalFamily, fontWeight = FontWeight.Bold),
    headlineSmall = androidx.compose.ui.text.TextStyle(fontFamily = TajawalFamily, fontWeight = FontWeight.Bold),
    titleLarge = androidx.compose.ui.text.TextStyle(fontFamily = TajawalFamily, fontWeight = FontWeight.Bold),
    titleMedium = androidx.compose.ui.text.TextStyle(fontFamily = TajawalFamily, fontWeight = FontWeight.Medium),
    titleSmall = androidx.compose.ui.text.TextStyle(fontFamily = TajawalFamily, fontWeight = FontWeight.Medium),
    bodyLarge = androidx.compose.ui.text.TextStyle(fontFamily = TajawalFamily),
    bodyMedium = androidx.compose.ui.text.TextStyle(fontFamily = TajawalFamily),
    bodySmall = androidx.compose.ui.text.TextStyle(fontFamily = TajawalFamily),
    labelLarge = androidx.compose.ui.text.TextStyle(fontFamily = TajawalFamily, fontWeight = FontWeight.Bold),
    labelMedium = androidx.compose.ui.text.TextStyle(fontFamily = TajawalFamily, fontWeight = FontWeight.Medium),
    labelSmall = androidx.compose.ui.text.TextStyle(fontFamily = TajawalFamily),
)
