package com.spectre.osint.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.spectre.osint.ui.theme.*

// ════════════════════════════════════════════════════════════════
//  عرض نتائج بطابع طرفية — TLine(kind): 0 [+] 1 [!] 2 [-] 3 فضائي 4 [*] 5 [#]
// ════════════════════════════════════════════════════════════════
data class TLine(val text: String, val kind: Int = 3)

fun tOk(text: String) = TLine(text, 0)
fun tWarn(text: String) = TLine(text, 1)
fun tBad(text: String) = TLine(text, 2)
fun tDim(text: String) = TLine(text, 3)
fun tInfo(text: String) = TLine(text, 4)
fun tHead(text: String) = TLine(text, 5)

@Composable
fun TermCard(
    title: String,
    lines: List<TLine>,
    color: Color = Neon,
    header: String? = null
) {
    Column(
        Modifier
            .fillMaxWidth()
            .padding(vertical = 6.dp)
            .clip(RoundedCornerShape(12.dp))
            .background(Color(0xFF020608))
            .border(1.dp, color.copy(alpha = 0.35f), RoundedCornerShape(12.dp))
    ) {
        // شريط العنوان
        Row(
            Modifier.fillMaxWidth().background(Color(0xFF0A120D)).padding(horizontal = 12.dp, vertical = 7.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Box(Modifier.size(7.dp).clip(RoundedCornerShape(2.dp)).background(color))
            Spacer(Modifier.width(8.dp))
            Text(title, color = TextHi, fontFamily = FontFamily.Monospace, fontSize = 12.sp, letterSpacing = 1.sp)
            if (header != null) {
                Spacer(Modifier.weight(1f))
                Text(header, color = color, fontFamily = FontFamily.Monospace, fontSize = 10.sp)
            }
        }
        // الأسطر
        lines.forEach { l ->
            val (prefix, lc) = when (l.kind) {
                0 -> "[+]" to Neon
                1 -> "[!]" to Amber
                2 -> "[-]" to Red
                4 -> "[*]" to Cyan
                5 -> "[#]" to Violet
                else -> "   " to TextMid
            }
            Row(Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 2.5.dp)) {
                Text(prefix, color = lc, fontFamily = FontFamily.Monospace, fontSize = 11.5.sp)
                Spacer(Modifier.width(7.dp))
                Text(l.text, color = lc, fontFamily = FontFamily.Monospace, fontSize = 11.5.sp, lineHeight = 16.sp)
            }
        }
        Spacer(Modifier.height(6.dp))
    }
}
