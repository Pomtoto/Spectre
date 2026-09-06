package com.spectre.osint.ui.tools

import android.content.Context
import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.FolderOpen
import androidx.compose.material.icons.filled.MyLocation
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Wifi
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.spectre.osint.core.*
import com.spectre.osint.core.capture.*
import com.spectre.osint.ui.*
import com.spectre.osint.ui.theme.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.InputStream

// ════════════════════════════════════════════════════════════════
//  محلل PCAP — تحليل ملفات الالتقاط (Wireshark/PCAPdroid/tshark)
// ════════════════════════════════════════════════════════════════
@Composable
fun PcapScreen(onBack: () -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var lines by remember { mutableStateOf<List<TLine>>(emptyList()) }
    var error by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }
    var fileName by remember { mutableStateOf<String?>(null) }

    fun run(uri: Uri) {
        busy = true; error = null; lines = emptyList()
        scope.launch {
            val result = withContext(Dispatchers.IO) {
                runCatching {
                    val bytes = context.contentResolver.openInputStream(uri)?.use { readLimited(it, 96_000_000) }
                        ?: throw Exception("تعذر قراءة الملف")
                    parsePcap(bytes).getOrThrow()
                }
            }
            busy = false
            result.fold(
                onSuccess = { s ->
                    val out = ArrayList<TLine>()
                    out.add(tHead("PCAP ANALYSIS — ${fileName ?: "capture"}"))
                    out.add(tInfo("الحزم: ${s.packets} • الحجم: ${"%.1f".format(s.bytes / 1048576.0)} MB • المدة: ${s.durationMs / 1000} ثانية"))
                    out.add(tInfo("طبقة الربط: ${s.linkType}"))
                    out.add(tDim("البروتوكولات:"))
                    s.protoCount.entries.sortedByDescending { it.value }.forEach { (k, v) ->
                        out.add(TLine("$k: $v", 3))
                    }
                    if (s.dnsNames.isNotEmpty()) {
                        out.add(tDim("استعلامات DNS (${s.dnsNames.size}):"))
                        s.dnsNames.take(25).forEach { out.add(TLine(it, 3)) }
                    }
                    if (s.httpRequests.isNotEmpty()) {
                        out.add(tDim("طلبات HTTP (${s.httpRequests.size}):"))
                        s.httpRequests.take(25).forEach { out.add(TLine(it, 3)) }
                    }
                    if (s.snis.isNotEmpty()) {
                        out.add(tDim("بصمات TLS SNI (${s.snis.size}):"))
                        s.snis.take(20).forEach { out.add(TLine(it, 3)) }
                    }
                    out.add(tDim("أعلى الأطراف حديثاً:"))
                    s.topTalkers.take(10).forEach { (ip, bytes) ->
                        out.add(TLine("$ip  →  ${"%.2f".format(bytes / 1024.0)} KB", 4))
                    }
                    if (s.errors.isNotEmpty()) {
                        val errTxt = s.errors.joinToString("\n") + if (s.errors.size > 1) " (+${s.errors.size - 1})" else ""
                        out.add(tWarn(errTxt))
                    }
                    out.add(tOk("التفكيك مكتمل"))
                    lines = out
                },
                onFailure = { error = it.message }
            )
        }
    }

    val picker = rememberLauncherForActivityResult(ActivityResultContracts.GetContent()) { u ->
        if (u != null) {
            fileName = queryName(context, u)
            run(u)
        }
    }

    ToolScaffold("PCAP ANALYZER", "تفكيك ملفات الالتقاط — HTTP · DNS · TLS-SNI · التدفقات", onBack) { pad ->
        Column(
            Modifier.padding(pad).padding(16.dp).verticalScroll(rememberScrollState())
        ) {
            ActionButton("اختيار ملف التقاط (.pcap / .cap)", Icons.Filled.FolderOpen, enabled = !busy) {
                picker.launch("*/*")
            }
            if (busy) { Spacer(Modifier.height(12.dp)); ScanningBar("جارٍ تفكيك الحزم") }
            error?.let {
                Spacer(Modifier.height(10.dp))
                Text(it, color = Red, fontSize = 13.sp, fontFamily = TajawalFamily)
            }
            if (lines.isNotEmpty()) {
                Spacer(Modifier.height(14.dp))
                TermCard("تقرير التفكيك", lines, color = Cyan)
            }
            if (lines.isEmpty() && !busy) {
                EmptyHint(
                    "أدخل ملف التقاط من Wireshark أو PCAPdroid",
                    "ملف من جهازك أو من حاسوبك — كله يحلل محلياً"
                )
            }
            Spacer(Modifier.height(24.dp))
        }
    }
}

private fun readLimited(ins: InputStream, max: Long): ByteArray {
    val out = java.io.ByteArrayOutputStream()
    val buf = ByteArray(65536)
    var total = 0L
    while (total < max) {
        val n = ins.read(buf, 0, minOf(buf.size.toLong(), max - total).toInt())
        if (n < 0) break
        out.write(buf, 0, n)
        total += n
    }
    return out.toByteArray()
}

private fun queryName(context: Context, uri: Uri): String? {
    return try {
        context.contentResolver.query(uri, null, null, null, null)?.use { c ->
            val idx = c.getColumnIndex(android.provider.OpenableColumns.DISPLAY_NAME)
            if (idx >= 0 && c.moveToFirst()) c.getString(idx) else null
        }
    } catch (e: Exception) { null }
}

// ════════════════════════════════════════════════════════════════
//  مسح الواي فاي — تعرّف بيئة التردد المحيطة
// ════════════════════════════════════════════════════════════════
@Composable
fun WifiScreen(onBack: () -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var rows by remember { mutableStateOf<List<WifiRow>>(emptyList()) }
    var info by remember { mutableStateOf<IfaceInfo?>(null) }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    var gwResults by remember { mutableStateOf<List<TLine>>(emptyList()) }

    fun scan() {
        busy = true; error = null
        scope.launch {
            rows = withContext(Dispatchers.IO) { scanWifi(context) }
            info = withContext(Dispatchers.IO) { localNetInfo(context) }
            busy = false
        }
    }

    val permLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) { grants ->
        if (grants.values.any { it }) scan()
        else error = "صلاحية الموقع مطلوبة لقراءة نتائج المسح — فعّلها من إعدادات النظام"
    }

    ToolScaffold("WIFI RECON", "محيط التردد: SSID · القناة · الإشارة · التشفير", onBack) { pad ->
        Column(Modifier.padding(pad).padding(16.dp).verticalScroll(rememberScrollState())) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                ActionButton("مسح المحيط", Icons.Filled.Wifi, enabled = !busy) {
                    permLauncher.launch(arrayOf(
                        android.Manifest.permission.ACCESS_FINE_LOCATION,
                        android.Manifest.permission.ACCESS_COARSE_LOCATION
                    ))
                }
                Spacer(Modifier.weight(1f))
                ActionButton("فحص البوابة", Icons.Filled.Security, enabled = info?.gateway != null && !busy) {
                    val gw = info?.gateway ?: return@ActionButton
                    busy = true; gwResults = emptyList()
                    scope.launch {
                        val (_, hits) = portScan(gw, listOf(21, 22, 23, 53, 80, 443, 8080, 8443), concurrency = 6, timeoutMs = 1200)
                        val out = ArrayList<TLine>()
                        out.add(tHead("GATEWAY PROBE — $gw"))
                        if (hits.isEmpty()) out.add(tWarn("لا منافذ معروفة مستجيبة"))
                        else hits.forEach { out.add(TLine("${it.port}  open  ${it.service}", 0)) }
                        gwResults = out
                        busy = false
                    }
                }
            }

            info?.let { i ->
                Spacer(Modifier.height(12.dp))
                ResultCard("واجهتك الحالية", Neon) {
                    InfoRow("العنوان المحلي", i.ip ?: "—")
                    InfoRow("البوابة", i.gateway ?: "—", valueColor = Cyan)
                    InfoRow("القناع", i.netmask ?: "—", valueColor = TextMid)
                    InfoRow("DNS", i.gateway ?: i.dns ?: "—", valueColor = TextMid)
                }
            }

            if (busy) { Spacer(Modifier.height(10.dp)); ScanningBar("جارٍ مسح الترددات") }
            error?.let {
                Spacer(Modifier.height(10.dp))
                Text(it, color = Red, fontSize = 13.sp)
            }

            if (rows.isNotEmpty()) {
                Spacer(Modifier.height(12.dp))
                ResultCard("نقاط الوصول (${rows.size}) — مرتبة بالإشارة", TextHi) {
                    rows.take(12).forEach { w ->
                        val q = when {
                            w.rssi >= -55 -> "ممتازة"
                            w.rssi >= -67 -> "جيدة"
                            else -> "ضعيفة"
                        }
                        val col = when { w.rssi >= -55 -> Neon; w.rssi >= -67 -> Amber; else -> Red }
                        Row(Modifier.fillMaxWidth().padding(vertical = 3.dp), verticalAlignment = Alignment.CenterVertically) {
                            Text(w.ssid.ifBlank { "(مخفي)" }, color = TextHi, fontSize = 12.5.sp, maxLines = 1,
                                modifier = Modifier.weight(1f), fontFamily = TajawalFamily, fontWeight = androidx.compose.ui.text.font.FontWeight.Bold)
                            Spacer(Modifier.width(8.dp))
                            Text("CH${w.channel}", color = TextDim, fontSize = 10.5.sp, fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace)
                            Spacer(Modifier.width(8.dp))
                            Text(w.security, color = Cyan, fontSize = 10.5.sp, fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace)
                        }
                        Row(Modifier.padding(start = 2.dp, bottom = 3.dp)) {
                            Text(w.bssid, color = TextDim, fontSize = 10.sp, fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace)
                            Spacer(Modifier.width(10.dp))
                            Text("${w.rssi} dBm · $q", color = col, fontSize = 10.sp, fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace)
                        }
                    }
                }
            }

            if (gwResults.isNotEmpty()) {
                Spacer(Modifier.height(10.dp))
                TermCard("نتيجة فحص البوابة", gwResults, color = Red)
            }
            if (rows.isEmpty() && !busy) {
                EmptyHint("اضغط مسح المحيط", "يتطلب تفعيل الموقع لأسباب قياسية — لا تشارك موقعك في أي مكان")
            }
            Spacer(Modifier.height(24.dp))
        }
    }
}

// ════════════════════════════════════════════════════════════════
//  مراقب الشبكة المحلي — ARP حي + مورّدون + فحص فوري
// ════════════════════════════════════════════════════════════════
@Composable
fun NetMonScreen(onBack: () -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var rows by remember { mutableStateOf<List<ArpRow>>(emptyList()) }
    var info by remember { mutableStateOf<IfaceInfo?>(null) }
    var target by remember { mutableStateOf<String?>(null) }
    var scanLines by remember { mutableStateOf<List<TLine>>(emptyList()) }
    var busy by remember { mutableStateOf(false) }
    var refreshTick by remember { mutableStateOf(0) }

    // تحديث حي كل 4 ثوانٍ
    LaunchedEffect(refreshTick) {
        while (true) {
            rows = withContext(Dispatchers.IO) { readArpTable() }
            info = withContext(Dispatchers.IO) { localNetInfo(context) }
            delay(4000)
        }
    }

    fun probe(ip: String) {
        busy = true; target = ip; scanLines = emptyList()
        scope.launch {
            val (_, hits) = portScan(ip, listOf(21, 22, 23, 53, 80, 443, 445, 8080, 8443), concurrency = 6, timeoutMs = 1100)
            val out = ArrayList<TLine>()
            out.add(tHead("HOST PROBE — $ip"))
            if (hits.isEmpty()) out.add(tWarn("لا منافذ معروفة مستجيبة"))
            else hits.forEach { h ->
                out.add(if (h.banner.isNotBlank()) TLine("${h.port}  open  ${h.service}  ::  ${h.banner.take(50)}", 0)
                else TLine("${h.port}  open  ${h.service}", 0))
            }
            scanLines = out
            busy = false
        }
    }

    ToolScaffold("NET MONITOR", "أجهزة الشبكة المحلية — جدول ARP حي", onBack) { pad ->
        Column(Modifier.padding(pad).padding(16.dp).verticalScroll(rememberScrollState())) {
            info?.let { i ->
                ResultCard("واجهتك", Neon) {
                    InfoRow("العنوان", i.ip ?: "—")
                    InfoRow("البوابة", i.gateway ?: "—", valueColor = Cyan)
                }
            }
            Spacer(Modifier.height(8.dp))
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text("تحديث كل 4 ثوانٍ", color = TextDim, fontSize = 11.sp, fontFamily = TajawalFamily)
                Spacer(Modifier.weight(1f))
                ActionButton("تحديث الآن", Icons.Filled.Refresh) { refreshTick++ }
            }
            Spacer(Modifier.height(8.dp))

            if (rows.isEmpty() && !busy) {
                EmptyHint("لا يوجد جيران مسجلون بعد", "افتح أي تطبيق/تصفح الإنترنت ليظهر الجيران — أو استخدم ماسح الأجهزة")
            }
            rows.forEach { r ->
                Row(
                    Modifier
                        .fillMaxWidth()
                        .padding(vertical = 3.dp)
                        .clip(RoundedCornerShape(10.dp))
                        .background(Surface)
                        .border(1.dp, if (r.complete) Border else Red.copy(alpha = 0.4f), RoundedCornerShape(10.dp))
                        .padding(horizontal = 12.dp, vertical = 8.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(Modifier.weight(1f)) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Text(r.ip, color = if (r.complete) TextHi else Amber,
                                fontSize = 13.sp, fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace, fontWeight = androidx.compose.ui.text.font.FontWeight.Bold)
                            Spacer(Modifier.width(6.dp))
                            if (!r.complete) {
                                Text("احتراق", color = Red, fontSize = 9.sp, fontFamily = TajawalFamily)
                            }
                        }
                        Text("${r.mac} · ${vendorOf(r.mac)}", color = TextDim, fontSize = 10.5.sp, fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace)
                    }
                    Box(
                        Modifier
                            .clip(RoundedCornerShape(8.dp))
                            .background(Neon.copy(alpha = 0.1f))
                            .border(1.dp, Neon.copy(alpha = 0.5f), RoundedCornerShape(8.dp))
                            .clickable { probe(r.ip) }
                            .padding(horizontal = 12.dp, vertical = 6.dp)
                    ) {
                        Text("فحص", color = Neon, fontSize = 11.sp, fontFamily = TajawalFamily, fontWeight = androidx.compose.ui.text.font.FontWeight.Bold)
                    }
                }
            }
            if (busy) { Spacer(Modifier.height(10.dp)); ScanningBar("فحص $target") }
            if (scanLines.isNotEmpty()) {
                Spacer(Modifier.height(10.dp))
                TermCard("الفحص", scanLines, color = Red)
            }
            Spacer(Modifier.height(24.dp))
        }
    }
}
