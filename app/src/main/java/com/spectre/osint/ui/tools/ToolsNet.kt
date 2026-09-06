package com.spectre.osint.ui.tools

import android.content.Intent
import android.net.Uri
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.MyLocation
import androidx.compose.material.icons.filled.Public
import androidx.compose.material.icons.filled.Dns
import androidx.compose.material.icons.filled.Link
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.spectre.osint.core.*
import com.spectre.osint.ui.*
import com.spectre.osint.ui.theme.*
import kotlinx.coroutines.launch

// ════════════════════════════════════════════════════════════════
//  متتبع العناوين — IP Intelligence
// ════════════════════════════════════════════════════════════════
@Composable
fun IpScreen(onBack: () -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var query by remember { mutableStateOf("") }
    var info by remember { mutableStateOf<IpInfo?>(null) }
    var error by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }

    ToolScaffold("IP INTELLIGENCE", "أين يقع هذا العنوان؟ ومن يملكه؟", onBack) { pad ->
        Column(
            Modifier.padding(pad).padding(16.dp).verticalScroll(rememberScrollState())
        ) {
            TermField(query, { query = it }, "عنوان IP أو اسم نطاق …")
            Spacer(Modifier.height(10.dp))
            ActionButton("تنفيذ الاستعلام", Icons.Filled.Public, enabled = query.isNotBlank()) {
                busy = true; error = null; info = null
                scope.launch {
                    val r = ipLookup(query)
                    busy = false
                    r.fold(
                        onSuccess = { info = it },
                        onFailure = { error = it.message }
                    )
                }
            }

            if (busy) { Spacer(Modifier.height(16.dp)); ScanningBar("جارٍ الاستعلام عن المعلومات") }
            error?.let {
                Spacer(Modifier.height(14.dp))
                Text(it, color = Red, fontSize = 13.sp, fontFamily = TajawalFamily)
            }

            val i = info
            if (i != null) {
                ResultCard("الهوية", Neon) {
                    CopyRow("العنوان", i.ip)
                    InfoRow("النوع", i.type.ifBlank { "—" }, valueColor = TextMid)
                    InfoRow("الحالة", "${i.flag} ${i.country}", valueColor = TextHi, mono = false)
                    InfoRow("المدينة", listOf(i.city, i.region).filter { it.isNotBlank() }.joinToString(" — "), valueColor = TextHi, mono = false)
                    InfoRow("الرموز البريدية", i.postal, valueColor = TextMid)
                }
                ResultCard("المزوّد والاستضافة", Cyan) {
                    InfoRow("المزوّد ISP", i.isp, valueColor = TextHi, mono = false)
                    InfoRow("المنظمة", i.org, valueColor = TextMid, mono = false)
                    InfoRow("ASN", i.asn, valueColor = TextMid)
                    InfoRow("المنطقة الزمنية", i.timezone, valueColor = TextMid, mono = false)
                }
                ResultCard("كشف الإخفاء", Violet) {
                    ShieldLine("VPN", i.vpn)
                    ShieldLine("Proxy", i.proxy)
                    ShieldLine("Tor", i.tor)
                    ShieldLine("Relay", i.relay)
                    ShieldLine("استضافة سحابية", i.hosting)
                }
                ResultCard("الموقع التقريبي", Red) {
                    InfoRow("الإحداثيات", "%.4f, %.4f".format(i.lat, i.lon), valueColor = TextMid)
                    Spacer(Modifier.height(6.dp))
                    ActionButton("فتح في الخرائط", Icons.Filled.MyLocation) {
                        try {
                            context.startActivity(
                                Intent(Intent.ACTION_VIEW, Uri.parse("geo:${i.lat},${i.lon}?q=${i.lat},${i.lon}"))
                            )
                        } catch (e: Exception) {}
                    }
                }
            }

            if (i == null && !busy) {
                EmptyHint(
                    "أدخل عنوان IP أو نطاقاً للاستعلام",
                    "تُجلب البيانات من مصادر عامة — بدون مفاتيح أو تسجيل"
                )
            }
            Spacer(Modifier.height(24.dp))
        }
    }
}

@Composable
private fun ShieldLine(label: String, active: Boolean) {
    Row(Modifier.fillMaxWidth().padding(vertical = 3.dp), horizontalArrangement = Arrangement.SpaceBetween) {
        Text(label, color = TextMid, fontSize = 12.5.sp, fontFamily = TajawalFamily)
        Text(
            if (active) "نشط" else "غير رصد",
            color = if (active) Red else Neon,
            fontWeight = FontWeight.Bold,
            fontSize = 12.5.sp,
            fontFamily = TajawalFamily
        )
    }
}

// ════════════════════════════════════════════════════════════════
//  استعلام النطاقات — Domain Intelligence
// ════════════════════════════════════════════════════════════════
@Composable
fun WhoisScreen(onBack: () -> Unit) {
    val scope = rememberCoroutineScope()
    var domain by remember { mutableStateOf("") }
    var who by remember { mutableStateOf<WhoisData?>(null) }
    var dns by remember { mutableStateOf<List<Dns.Rec>>(emptyList()) }
    var error by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }

    ToolScaffold("DOMAIN INTELLIGENCE", "من سجّل النطاق؟ وماذا تظهر سجلات DNS؟", onBack) { pad ->
        Column(
            Modifier.padding(pad).padding(16.dp).verticalScroll(rememberScrollState())
        ) {
            TermField(domain, { domain = it }, "example.com")
            Spacer(Modifier.height(10.dp))
            ActionButton("استعلام شامل", Icons.Filled.Dns, enabled = domain.isNotBlank()) {
                busy = true; error = null; who = null; dns = emptyList()
                scope.launch {
                    val w = whois(domain)
                    val d = Dns.query(domain.trim().lowercase().removePrefix("www."), 1) +
                        Dns.query(domain.trim().lowercase().removePrefix("www."), 15) +
                        Dns.query(domain.trim().lowercase().removePrefix("www."), 2)
                    dns = d
                    busy = false
                    w.fold(
                        onSuccess = { who = it },
                        onFailure = { error = it.message }
                    )
                }
            }

            if (busy) { Spacer(Modifier.height(16.dp)); ScanningBar("جارٍ الاستعلام من RDAP وDNS") }
            error?.let {
                Spacer(Modifier.height(14.dp))
                Text(it, color = Red, fontSize = 13.sp, fontFamily = TajawalFamily)
            }

            val w = who
            if (w != null) {
                ResultCard("التسجيل", Neon) {
                    InfoRow("النطاق", w.domain, valueColor = TextMid)
                    InfoRow("المسجّل", w.registrar.ifBlank { "غير معلن" }, valueColor = TextHi, mono = false)
                    if (w.emails.isNotEmpty()) CopyRow("البريد", w.emails.joinToString(", "))
                    InfoRow("التسجيل الأول", w.created, valueColor = TextMid)
                    InfoRow("آخر تحديث", w.updated, valueColor = TextMid)
                    InfoRow("تاريخ الانتهاء", w.expires, valueColor = TextMid)
                }
                ResultCard("الحالة والحماية", Cyan) {
                    InfoRow("الحالة", if (w.status.isEmpty()) "—" else w.status.joinToString(" · "), valueColor = TextMid, mono = false)
                    InfoRow("DNSSEC", if (w.dnssec) "مفعّل" else "غير مفعّل", valueColor = if (w.dnssec) Neon else Amber, mono = false)
                }
                if (w.nameservers.isNotEmpty()) {
                    ResultCard("خوادم الأسماء", Violet) {
                        w.nameservers.forEach { ns -> InfoRow("NS", ns, valueColor = TextMid) }
                    }
                }
            }

            if (dns.isNotEmpty()) {
                ResultCard("سجلات DNS", TextHi) {
                    dns.forEach { rec ->
                        InfoRow(rec.type, rec.data, valueColor = TextMid)
                    }
                }
            }

            if (w == null && !busy && dns.isEmpty()) {
                EmptyHint(
                    "أدخل نطاقاً لاستخراج معلومات تسجيله",
                    "يغطي RDAP سجلات التسجيل، وDNS عبر Google DoH"
                )
            }
            Spacer(Modifier.height(24.dp))
        }
    }
}

// ════════════════════════════════════════════════════════════════
//  فاحص الروابط — Link Inspector
// ════════════════════════════════════════════════════════════════
@Composable
fun LinkScreen(onBack: () -> Unit) {
    val scope = rememberCoroutineScope()
    var url by remember { mutableStateOf("") }
    var rep by remember { mutableStateOf<LinkReport?>(null) }
    var error by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }

    ToolScaffold("LINK INSPECTOR", "أين يذهب هذا الرابط فعلاً؟", onBack) { pad ->
        Column(
            Modifier.padding(pad).padding(16.dp).verticalScroll(rememberScrollState())
        ) {
            TermField(url, { url = it }, "https://…")
            Spacer(Modifier.height(10.dp))
            ActionButton("تحليل الرابط", Icons.Filled.Link, enabled = url.isNotBlank()) {
                busy = true; error = null; rep = null
                scope.launch {
                    val r = analyzeLink(url)
                    busy = false
                    r.fold(
                        onSuccess = { rep = it },
                        onFailure = { error = it.message }
                    )
                }
            }

            if (busy) { Spacer(Modifier.height(16.dp)); ScanningBar("جارٍ تتبع السلسلة والوجهة") }
            error?.let {
                Spacer(Modifier.height(14.dp))
                Text(it, color = Red, fontSize = 13.sp, fontFamily = TajawalFamily)
            }

            val r = rep
            if (r != null) {
                val sc = when (r.verdictScore) { 0 -> Red; 1 -> Amber; else -> Neon }
                ResultCard("التقييم النهائي", sc) {
                    StatusPill(r.verdict, sc)
                    Spacer(Modifier.height(10.dp))
                    r.flags.forEach { f ->
                        Row(Modifier.padding(vertical = 2.dp)) {
                            Text("▪ ", color = sc, fontSize = 12.sp)
                            Text(f, color = TextMid, fontSize = 12.5.sp, fontFamily = TajawalFamily)
                        }
                    }
                }
                ResultCard("سلسلة التوجيه", TextHi) {
                    r.chain.forEach { hop ->
                        Text(hop, color = TextMid, fontSize = 11.sp, fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace, lineHeight = 17.sp)
                    }
                }
                ResultCard("الوجهة النهائية", Cyan) {
                    CopyRow("الرابط", r.finalUrl, Cyan)
                    InfoRow("النطاق", r.host, valueColor = TextHi, mono = false)
                    if (r.ip != null) InfoRow("عنوان IP", r.ip, valueColor = TextMid)
                    r.geo?.let { g ->
                        InfoRow("الدولة", g.country, valueColor = TextMid, mono = false)
                        InfoRow("المزوّد", g.isp, valueColor = TextMid, mono = false)
                    }
                    r.whois?.let { w ->
                        InfoRow("المسجّل", w.registrar.ifBlank { "غير معلن" }, valueColor = TextMid, mono = false)
                        InfoRow("انتهاء النطاق", w.expires, valueColor = TextMid)
                    }
                }
            }

            if (r == null && !busy) {
                EmptyHint(
                    "الصق رابطاً للتحقق من وجهته",
                    "يفحص إعادة التوجيه، النطاق، الاستضافة، وعلامات التصيد"
                )
            }
            Spacer(Modifier.height(24.dp))
        }
    }
}
