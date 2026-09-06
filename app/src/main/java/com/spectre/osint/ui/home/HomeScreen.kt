package com.spectre.osint.ui.home

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.grid.GridCells
import androidx.compose.foundation.lazy.grid.LazyVerticalGrid
import androidx.compose.foundation.lazy.grid.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Dns
import androidx.compose.material.icons.filled.Email
import androidx.compose.material.icons.filled.Image
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.Link
import androidx.compose.material.icons.filled.Public
import androidx.compose.material.icons.filled.QrCode
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.spectre.osint.R
import com.spectre.osint.Screen
import com.spectre.osint.ui.theme.*

data class ToolEntry(
    val screen: Screen,
    val icon: ImageVector,
    val title: String,
    val sub: String,
    val tag: String
)

private val tools = listOf(
    ToolEntry(Screen.Exif, Icons.Filled.Image, "محلل الصور", "استخرج البيانات المخفية: الجهاز، الوقت، والموقع", "Image Forensics"),
    ToolEntry(Screen.Password, Icons.Filled.Key, "محلل كلمات المرور", "قياس القوة والفترة اللازمة للكسر + التسريبات", "Password Auditor"),
    ToolEntry(Screen.Ip, Icons.Filled.Public, "متتبع العناوين", "موقع أي عنوان IP أو نطاق، المزود، وكشف VPN", "IP Intelligence"),
    ToolEntry(Screen.Qr, Icons.Filled.QrCode, "قارئ وتوليد QR", "فك أي رمز QR أو توليد رمز جديد", "QR Module"),
    ToolEntry(Screen.Breach, Icons.Filled.Email, "كاشف التسريبات", "هل حسابك ضمن تسريبات معروفة؟", "Breach Finder"),
    ToolEntry(Screen.Whois, Icons.Filled.Dns, "استعلام النطاقات", "مالك النطاق، تاريخ التسجيل، وسجلات DNS", "Domain Intel"),
    ToolEntry(Screen.Link, Icons.Filled.Link, "فاحص الروابط", "كشف الوجهة الحقيقية لأي رابط قبل فتحه", "Link Inspector"),
)

@Composable
fun HomeScreen(onOpen: (Screen) -> Unit) {
    Column(
        Modifier
            .fillMaxSize()
            .background(Bg)
            .padding(horizontal = 18.dp)
    ) {
        Spacer(Modifier.height(28.dp))

        // ── الترويسة ──
        Row(verticalAlignment = Alignment.CenterVertically) {
            Box(
                Modifier
                    .size(58.dp)
                    .clip(RoundedCornerShape(16.dp))
                    .background(Surface)
                    .border(1.dp, Neon.copy(alpha = 0.6f), RoundedCornerShape(16.dp))
            ) {
                Icon(
                    painterResource(R.drawable.ic_logo),
                    contentDescription = "SPECTRE",
                    tint = Color.Unspecified,
                    modifier = Modifier.fillMaxSize()
                )
            }
            Spacer(Modifier.width(14.dp))
            Column {
                Text(
                    "SPECTRE",
                    color = Neon,
                    fontFamily = FontFamily.Monospace,
                    fontWeight = FontWeight.ExtraBold,
                    fontSize = 26.sp,
                    letterSpacing = 6.sp
                )
                Text(
                    "أدوات الاستخبارات المفتوحة",
                    color = TextMid,
                    fontFamily = TajawalFamily,
                    fontSize = 13.sp
                )
            }
        }

        Spacer(Modifier.height(14.dp))

        // ── شريط الحالة ──
        Row(verticalAlignment = Alignment.CenterVertically) {
            StatusMini("${tools.size} أدوات", Neon)
            Spacer(Modifier.width(8.dp))
            StatusMini("بدون روت", Cyan)
            Spacer(Modifier.width(8.dp))
            StatusMini("مصادر عامة", Violet)
            Spacer(Modifier.weight(1f))
            Text("v1.0", color = TextDim, fontFamily = FontFamily.Monospace, fontSize = 12.sp)
        }

        Spacer(Modifier.height(16.dp))

        // ── شبكة الأدوات ──
        LazyVerticalGrid(
            columns = GridCells.Fixed(2),
            horizontalArrangement = Arrangement.spacedBy(12.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            items(tools) { tool ->
                ToolCard(tool) { onOpen(tool.screen) }
            }
            item(span = { androidx.compose.foundation.lazy.grid.GridItemSpan(2) }) {
                Box(Modifier.padding(top = 6.dp, bottom = 18.dp)) {
                    Text(
                        "جميع البيانات تُجلب من مصادر عامة ومتاحة قانونياً لفهم المخاطر الأمنية — استخدم الأداة بمسؤولية.",
                        color = TextDim,
                        fontFamily = TajawalFamily,
                        fontSize = 11.sp,
                        lineHeight = 16.sp
                    )
                }
            }
        }
    }
}

@Composable
private fun StatusMini(text: String, color: Color) {
    Row(
        Modifier
            .clip(RoundedCornerShape(8.dp))
            .background(color.copy(alpha = 0.1f))
            .border(1.dp, color.copy(alpha = 0.35f), RoundedCornerShape(8.dp))
            .padding(horizontal = 10.dp, vertical = 5.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(text, color = color, fontSize = 11.5.sp, fontFamily = TajawalFamily, fontWeight = FontWeight.Bold)
    }
}

@Composable
private fun ToolCard(tool: ToolEntry, onClick: () -> Unit) {
    Column(
        Modifier
            .clip(RoundedCornerShape(16.dp))
            .background(Surface)
            .border(1.dp, Border, RoundedCornerShape(16.dp))
            .clickable { onClick() }
            .padding(14.dp)
    ) {
        Box(
            Modifier
                .size(42.dp)
                .clip(RoundedCornerShape(11.dp))
                .background(Neon.copy(alpha = 0.12f))
                .border(1.dp, Neon.copy(alpha = 0.4f), RoundedCornerShape(11.dp)),
            contentAlignment = Alignment.Center
        ) {
            Icon(tool.icon, null, tint = Neon, modifier = Modifier.size(22.dp))
        }
        Spacer(Modifier.height(10.dp))
        Text(tool.title, color = TextHi, fontWeight = FontWeight.Bold, fontSize = 14.5.sp, fontFamily = TajawalFamily)
        Spacer(Modifier.height(3.dp))
        Text(tool.sub, color = TextDim, fontSize = 11.sp, lineHeight = 15.sp, maxLines = 3, fontFamily = TajawalFamily)
        Spacer(Modifier.height(8.dp))
        Text(tool.tag, color = Neon.copy(alpha = 0.65f), fontSize = 9.5.sp, letterSpacing = 1.sp, fontFamily = FontFamily.Monospace)
    }
}
