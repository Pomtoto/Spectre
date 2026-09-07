package com.spectre.osint.ui.home

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.grid.GridCells
import androidx.compose.foundation.lazy.grid.GridItemSpan
import androidx.compose.foundation.lazy.grid.LazyVerticalGrid
import androidx.compose.foundation.lazy.grid.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.FolderOpen
import androidx.compose.material.icons.filled.Sensors
import androidx.compose.material.icons.filled.Wifi
import androidx.compose.material.icons.filled.*
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

data class ToolSection(val name: String, val ref: String, val tools: List<ToolEntry>)

private val sections = listOf(
    ToolSection("الاستطلاع", "RECON", listOf(
        ToolEntry(Screen.Port, Icons.Filled.NetworkCheck, "ماسح المنافذ", "فحص منافذ TCP لأي هدف + الأجهزة الحية بالشبكة", "portscan"),
        ToolEntry(Screen.SubEnum, Icons.Filled.TravelExplore, "تعداد النطاقات", "استخراج النطاقات الفرعية من سجل الشهادات", "subenum"),
        ToolEntry(Screen.Ip, Icons.Filled.Public, "متتبع العناوين", "موقع أي IP، المزود، وكشف VPN/Tor", "iptrace"),
        ToolEntry(Screen.Whois, Icons.Filled.Dns, "استعلام النطاقات", "مالك النطاق والتسجيل وسجلات DNS", "whois"),
        ToolEntry(Screen.Link, Icons.Filled.Link, "فاحص الروابط", "كشف الوجهة الحقيقية لأي رابط مختصر", "linkscan"),
    )),
    ToolSection("التحليل", "ANALYSIS", listOf(
        ToolEntry(Screen.Exif, Icons.Filled.Image, "محلل الصور", "الجهاز، الوقت، والموقع الجغرافي المخفي", "exif"),
        ToolEntry(Screen.Apk, Icons.Filled.Android, "محلل APK", "الشهادة، الصلاحيات، والمتتبعات من الحزمة", "apk-dex"),
        ToolEntry(Screen.File, Icons.Filled.Description, "فاحص الملفات", "التوقيع السحري والبصمات والنصوص", "file-sig"),
        ToolEntry(Screen.Http, Icons.Filled.Security, "تحليل HTTP", "رأسيات الأمان وبصمة الخادم", "http"),
    )),
    ToolSection("الاستطلاع الحي", "NETRECON", listOf(
        ToolEntry(Screen.Pcap, Icons.Filled.FolderOpen, "محلل PCAP", "تفكيك ملفات الالتقاط: HTTP، DNS، TLS-SNI، التدفقات", "pcap"),
        ToolEntry(Screen.Wifi, Icons.Filled.Wifi, "مسح الواي فاي", "نقاط الوصول، القناة، الإشارة، والتشفير حولك", "wifi"),
        ToolEntry(Screen.NetMon, Icons.Filled.Sensors, "مراقب الشبكة", "أجهزة الشبكة المحلية — ARP حي مع المورّدين", "netmon"),
    )),
    ToolSection("الأدوات", "TOOLKIT", listOf(
        ToolEntry(Screen.Password, Icons.Filled.Key, "محلل كلمات المرور", "القوة، زمن الكسر، والمواقع المسرّبة", "pw-audit"),
        ToolEntry(Screen.Breach, Icons.Filled.Email, "مراقب التسريبات", "أي موقع هُرق؟ حسابك وكلمتك في التسريبات؟", "breach-intel"),
        ToolEntry(Screen.Crypto, Icons.Filled.Calculate, "مختبر الترميز", "Hash وBase64 وHex وXOR وROT13", "crypto"),
        ToolEntry(Screen.Qr, Icons.Filled.QrCode, "قارئ QR", "فك وتوليد رموز QR", "qr"),
        ToolEntry(Screen.Device, Icons.Filled.PhoneAndroid, "فحص الجهاز", "حالة الحماية العامة لجهازك", "audit"),
    )),
)

@Composable
fun HomeScreen(onOpen: (Screen) -> Unit) {
    Column(
        Modifier
            .fillMaxSize()
            .background(Bg)
            .padding(horizontal = 18.dp)
    ) {
        Spacer(Modifier.height(26.dp))

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
                    "مجموعة الاستخبارات المفتوحة — PRO",
                    color = TextMid,
                    fontFamily = TajawalFamily,
                    fontSize = 13.sp
                )
            }
        }

        Spacer(Modifier.height(12.dp))

        Row(verticalAlignment = Alignment.CenterVertically) {
            StatusMini("${sections.sumOf { it.tools.size }} أداة", Neon)
            Spacer(Modifier.width(8.dp))
            StatusMini("بدون روت", Cyan)
            Spacer(Modifier.width(8.dp))
            StatusMini("TCP / DNS / HTTP", Violet)
            Spacer(Modifier.weight(1f))
            Text("v2.0 PRO", color = TextDim, fontFamily = FontFamily.Monospace, fontSize = 12.sp)
        }

        Spacer(Modifier.height(10.dp))

        // ── بطاقة المختبر (البطاقة الرئيسية) ──
        Box(
            Modifier
                .fillMaxWidth()
                .clip(RoundedCornerShape(18.dp))
                .background(Surface2)
                .border(1.dp, Neon.copy(alpha = 0.65f), RoundedCornerShape(18.dp))
                .clickable { onOpen(Screen.Lab) }
                .padding(16.dp)
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Box(
                    Modifier
                        .size(46.dp)
                        .clip(RoundedCornerShape(12.dp))
                        .background(Red.copy(alpha = 0.14f))
                        .border(1.dp, Red.copy(alpha = 0.5f), RoundedCornerShape(12.dp)),
                    contentAlignment = Alignment.Center
                ) {
                    Icon(Icons.Filled.Terminal, null, tint = Red, modifier = Modifier.size(24.dp))
                }
                Spacer(Modifier.width(12.dp))
                Column(Modifier.weight(1f)) {
                    Text("SPECTRE LAB", color = Red, fontFamily = FontFamily.Monospace, fontWeight = FontWeight.ExtraBold, fontSize = 15.sp, letterSpacing = 2.sp)
                    Spacer(Modifier.height(2.dp))
                    Text("مختبر اختراق حي داخل جهازك — SQLi \u00b7 XSS \u00b7 كسر تجزئة \u00b7 عبور مسارات", color = TextMid, fontSize = 11.5.sp, lineHeight = 15.sp, fontFamily = TajawalFamily)
                }
                Text("ابدأ", color = Red, fontWeight = FontWeight.Bold, fontSize = 12.sp, fontFamily = TajawalFamily)
            }
        }

        Spacer(Modifier.height(6.dp))

        // ── الشبكة ──
        LazyVerticalGrid(
            columns = GridCells.Fixed(2),
            horizontalArrangement = Arrangement.spacedBy(12.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            sections.forEach { sec ->
                item(span = { GridItemSpan(2) }) {
                    Row(
                        Modifier.padding(top = 10.dp, bottom = 2.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            "// ${sec.ref}",
                            color = Neon.copy(alpha = 0.8f),
                            fontFamily = FontFamily.Monospace,
                            fontSize = 12.sp,
                            letterSpacing = 2.sp
                        )
                        Spacer(Modifier.width(10.dp))
                        Text(sec.name, color = TextMid, fontSize = 13.sp, fontFamily = TajawalFamily, fontWeight = FontWeight.Bold)
                        Spacer(Modifier.weight(1f))
                        Box(Modifier.width(46.dp).height(1.dp).background(Border))
                    }
                }
                items(sec.tools) { tool ->
                    ToolCard(tool) { onOpen(tool.screen) }
                }
            }
            item(span = { GridItemSpan(2) }) {
                Box(Modifier.padding(top = 8.dp, bottom = 18.dp)) {
                    Column {
                        Text(
                            "جميع الفحوصات تُجرى على مصادر عامة وأهداف مسموح التعامل معها — استخدم الأدوات بمسؤولية.",
                            color = TextDim, fontFamily = TajawalFamily, fontSize = 11.sp, lineHeight = 16.sp
                        )
                        Spacer(Modifier.height(8.dp))
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Box(Modifier.size(6.dp).clip(RoundedCornerShape(3.dp)).background(Neon))
                            Spacer(Modifier.width(6.dp))
                            Text(
                                "SPECTRE — من إعداد Shadowpom · Root-Me 40 تحدي · HackingHub Hacker",
                                color = Neon.copy(alpha = 0.75f), fontFamily = FontFamily.Monospace, fontSize = 10.5.sp
                            )
                        }
                    }
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
        Row(verticalAlignment = Alignment.CenterVertically) {
            Box(
                Modifier
                    .size(38.dp)
                    .clip(RoundedCornerShape(10.dp))
                    .background(Neon.copy(alpha = 0.12f))
                    .border(1.dp, Neon.copy(alpha = 0.4f), RoundedCornerShape(10.dp)),
                contentAlignment = Alignment.Center
            ) {
                Icon(tool.icon, null, tint = Neon, modifier = Modifier.size(20.dp))
            }
            Spacer(Modifier.width(8.dp))
            Text(
                tool.tag,
                color = Neon.copy(alpha = 0.65f),
                fontSize = 9.5.sp,
                letterSpacing = 0.5.sp,
                fontFamily = FontFamily.Monospace
            )
        }
        Spacer(Modifier.height(9.dp))
        Text(tool.title, color = TextHi, fontWeight = FontWeight.Bold, fontSize = 14.sp, fontFamily = TajawalFamily)
        Spacer(Modifier.height(3.dp))
        Text(tool.sub, color = TextDim, fontSize = 10.5.sp, lineHeight = 14.sp, maxLines = 3, fontFamily = TajawalFamily)
    }
}
