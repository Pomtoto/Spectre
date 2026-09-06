package com.spectre.osint.ui

import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.KeyboardArrowLeft
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.spectre.osint.ui.theme.*

// ── شريط عنوان الشاشة الفرعية ────────────────────────────────────
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ToolScaffold(
    title: String,
    subtitle: String,
    onBack: () -> Unit,
    content: @Composable (PaddingValues) -> Unit
) {
    Scaffold(
        containerColor = Bg,
        topBar = {
            Surface(color = Surface, shadowElevation = 8.dp) {
                Row(
                    Modifier.fillMaxWidth().padding(horizontal = 8.dp, vertical = 10.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    IconButton(onClick = onBack) {
                        Icon(Icons.Filled.KeyboardArrowLeft, contentDescription = "رجوع", tint = Neon)
                    }
                    Column {
                        Text(title, color = Neon, fontFamily = FontFamily.Monospace, fontWeight = FontWeight.ExtraBold, fontSize = 17.sp, letterSpacing = 2.sp)
                        Text(subtitle, color = TextDim, fontSize = 11.sp, fontFamily = TajawalFamily)
                    }
                    Spacer(Modifier.weight(1f))
                    BlinkingCursor()
                }
            }
        }
    ) { pad -> content(pad) }
}

// ── مؤشر وامض بطابع طرفية ────────────────────────────────────────
@Composable
fun BlinkingCursor(color: Color = Neon) {
    var on by remember { mutableStateOf(true) }
    LaunchedEffect(Unit) {
        while (true) {
            kotlinx.coroutines.delay(600)
            on = !on
        }
    }
    Box(Modifier.width(10.dp).height(18.dp).background(if (on) color else Color.Transparent))
}

// ── صف معلومات (تسمية + قيمة) ────────────────────────────────────
@Composable
fun InfoRow(label: String, value: String, valueColor: Color = TextHi, mono: Boolean = true) {
    Row(Modifier.fillMaxWidth().padding(vertical = 5.dp), verticalAlignment = Alignment.Top) {
        Text(label, color = TextDim, fontSize = 12.5.sp, modifier = Modifier.width(118.dp))
        Text(
            value,
            color = valueColor,
            fontSize = 13.sp,
            fontFamily = if (mono) FontFamily.Monospace else TajawalFamily,
            modifier = Modifier.weight(1f)
        )
    }
}

// ── صف مع زر نسخ ─────────────────────────────────────────────────
@Composable
fun CopyRow(label: String, value: String, color: Color = Neon) {
    val clip = LocalClipboardManager.current
    Row(Modifier.fillMaxWidth().padding(vertical = 4.dp), verticalAlignment = Alignment.CenterVertically) {
        Text(label, color = TextDim, fontSize = 12.5.sp, modifier = Modifier.width(118.dp))
        Text(value, color = color, fontSize = 13.sp, fontFamily = FontFamily.Monospace, maxLines = 2, modifier = Modifier.weight(1f))
        IconButton(onClick = { clip.setText(AnnotatedString(value)) }, modifier = Modifier.size(28.dp)) {
            Icon(Icons.Filled.ContentCopy, "نسخ", tint = TextMid, modifier = Modifier.size(14.dp))
        }
    }
}

// ── بطاقة نتيجة ──────────────────────────────────────────────────
@Composable
fun ResultCard(title: String, color: Color = Neon, content: @Composable ColumnScope.() -> Unit) {
    Column(
        Modifier.fillMaxWidth()
            .padding(vertical = 6.dp)
            .clip(RoundedCornerShape(14.dp))
            .background(Surface)
            .border(1.dp, color.copy(alpha = 0.35f), RoundedCornerShape(14.dp))
            .padding(14.dp)
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Box(Modifier.size(8.dp).clip(RoundedCornerShape(2.dp)).background(color))
            Spacer(Modifier.width(8.dp))
            Text(title, color = TextHi, fontWeight = FontWeight.Bold, fontSize = 14.sp)
        }
        Spacer(Modifier.height(8.dp))
        content()
    }
}

// ── شارة حالة ────────────────────────────────────────────────────
@Composable
fun StatusPill(text: String, color: Color) {
    Row(
        Modifier.clip(RoundedCornerShape(8.dp))
            .background(color.copy(alpha = 0.12f))
            .border(1.dp, color.copy(alpha = 0.5f), RoundedCornerShape(8.dp))
            .padding(horizontal = 10.dp, vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Box(Modifier.size(6.dp).clip(RoundedCornerShape(3.dp)).background(color))
        Spacer(Modifier.width(6.dp))
        Text(text, color = color, fontSize = 12.sp, fontWeight = FontWeight.Bold)
    }
}

// ── زر تنفيذ ثقيل ────────────────────────────────────────────────
@Composable
fun ActionButton(text: String, icon: ImageVector? = null, enabled: Boolean = true, onClick: () -> Unit) {
    Row(
        Modifier.fillMaxWidth()
            .clip(RoundedCornerShape(12.dp))
            .background(if (enabled) Neon.copy(alpha = 0.12f) else Surface)
            .border(1.dp, if (enabled) Neon.copy(alpha = 0.7f) else Border, RoundedCornerShape(12.dp))
            .clickable(enabled = enabled) { onClick() }
            .padding(vertical = 13.dp),
        horizontalArrangement = Arrangement.Center,
        verticalAlignment = Alignment.CenterVertically
    ) {
        if (icon != null) {
            Icon(icon, null, tint = if (enabled) Neon else TextDim, modifier = Modifier.size(18.dp))
            Spacer(Modifier.width(8.dp))
        }
        Text(text, color = if (enabled) Neon else TextDim, fontWeight = FontWeight.Bold, fontSize = 14.sp)
    }
}

// ── حقل إدخال بطابع طرفية ────────────────────────────────────────
@Composable
fun TermField(value: String, onChange: (String) -> Unit, placeholder: String, mono: Boolean = true) {
    TextField(
        value = value,
        onValueChange = onChange,
        placeholder = { Text(placeholder, color = TextDim, fontSize = 13.sp) },
        singleLine = true,
        textStyle = androidx.compose.ui.text.TextStyle(
            color = TextHi,
            fontSize = 14.sp,
            fontFamily = if (mono) FontFamily.Monospace else TajawalFamily
        ),
        colors = TextFieldDefaults.colors(
            focusedContainerColor = Surface2,
            unfocusedContainerColor = Surface2,
            focusedIndicatorColor = Neon,
            unfocusedIndicatorColor = Border,
            cursorColor = Neon,
            focusedTextColor = TextHi,
            unfocusedTextColor = TextHi
        ),
        shape = RoundedCornerShape(10.dp),
        modifier = Modifier.fillMaxWidth()
    )
}

// ── مؤشر جارٍ التنفيذ ────────────────────────────────────────────
@Composable
fun ScanningBar(text: String = "جارٍ التنفيذ ..") {
    val alpha by rememberInfiniteTransition().animateFloat(
        initialValue = 0.35f, targetValue = 1f,
        animationSpec = androidx.compose.animation.core.infiniteRepeatable(
            androidx.compose.animation.core.tween(700),
            androidx.compose.animation.core.RepeatMode.Reverse
        )
    )
    Row(verticalAlignment = Alignment.CenterVertically) {
        Text(text, color = Neon.copy(alpha = alpha), fontFamily = FontFamily.Monospace, fontSize = 13.sp, letterSpacing = 1.sp)
        Spacer(Modifier.width(6.dp))
        Text("...", color = Neon.copy(alpha = alpha), fontFamily = FontFamily.Monospace, fontSize = 13.sp)
    }
}

// ── نص فارغ وسط الشاشة ───────────────────────────────────────────
@Composable
fun EmptyHint(text: String, sub: String? = null) {
    Column(Modifier.fillMaxWidth().padding(vertical = 30.dp), horizontalAlignment = Alignment.CenterHorizontally) {
        Text(text, color = TextMid, fontSize = 13.sp, fontFamily = TajawalFamily)
        if (sub != null) {
            Spacer(Modifier.height(6.dp))
            Text(sub, color = TextDim, fontSize = 11.sp, fontFamily = TajawalFamily)
        }
    }
}
