package com.spectre.osint.ui.tools

import android.os.Handler
import android.os.Looper
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Code
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.PowerSettingsNew
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Terminal
import androidx.compose.material3.Text
import androidx.compose.material3.TextField
import androidx.compose.material3.TextFieldDefaults
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.spectre.osint.core.lab.*
import com.spectre.osint.ui.*
import com.spectre.osint.ui.theme.*
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLEncoder
import kotlin.concurrent.thread

// ════════════════════════════════════════════════════════════════
//  SPECTRE LAB — مختبر اختراق حي داخل الجهاز (127.0.0.1 فقط)
// ════════════════════════════════════════════════════════════════
@Composable
fun LabScreen(onBack: () -> Unit) {
    val context = LocalContext.current
    val lab = remember { LabServer(context.applicationContext) }
    val handler = remember { Handler(Looper.getMainLooper()) }
    val term = remember { mutableStateListOf<TLine>() }

    var running by remember { mutableStateOf(false) }
    var port by remember { mutableStateOf(0) }
    var tab by remember { mutableStateOf(0) } // 0 خادم | 1 SQLi | 2 كسر | 3 ويب
    var webSub by remember { mutableStateOf(0) } // 0 XSS | 1 files

    var u by remember { mutableStateOf("admin' OR '1'='1") }
    var p by remember { mutableStateOf("x") }
    var hash by remember { mutableStateOf("") }
    var cracked by remember { mutableStateOf<String?>(null) }
    var crackInfo by remember { mutableStateOf("") }
    var payload by remember { mutableStateOf("<script>alert('XSS')</script>") }
    var fpath by remember { mutableStateOf("secret_router.txt") }

    DisposableEffect(Unit) {
        lab.onExchange = { line, kind ->
            handler.post {
                term.add(TLine(line, kind))
                while (term.size > 320) term.removeAt(0)
            }
        }
        onDispose { lab.stop() }
    }

    fun extractHashes(body: String) {
        // يحفظ التجزئات المستخرجة لتغذية أداة الكسر
        Regex("[a-f0-9]{32}").findAll(body).forEach { m ->
            if (hash.isBlank()) hash = m.value
        }
    }

    fun fire(method: String, pathQ: String, form: Map<String, String> = emptyMap()) {
        thread {
            try {
                val url = URL("http://127.0.0.1:$port$pathQ")
                val conn = url.openConnection() as HttpURLConnection
                conn.requestMethod = method
                conn.connectTimeout = 3500
                conn.readTimeout = 6000
                if (method == "POST") {
                    conn.doOutput = true
                    conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded")
                    val b = form.entries.joinToString("&") {
                        URLEncoder.encode(it.key, "UTF-8") + "=" + URLEncoder.encode(it.value, "UTF-8")
                    }
                    conn.outputStream.use { it.write(b.toByteArray(Charsets.UTF_8)) }
                }
                val code = conn.responseCode
                val body = (if (code in 200..299) conn.inputStream else conn.errorStream)
                    ?.bufferedReader()?.use { it.readText() } ?: ""
                handler.post {
                    term.add(TLine("> $method $pathQ  ←  $code", if (code == 200) 0 else 1))
                    body.lineSequence().take(14).forEach { term.add(TLine("| $it", 3)) }
                    if (code == 200 && pathQ.contains("/login")) {
                        extractHashes(body)
                    }
                }
            } catch (e: Exception) {
                handler.post { term.add(TLine("! فشل الاتصال بالخادم — شغّله أولاً", 2)) }
            }
        }
    }

    ToolScaffold("SPECTRE LAB", "مختبر اختراق حي داخل جهازك — 127.0.0.1", onBack) { pad ->
        Column(
            Modifier.padding(pad).padding(16.dp).verticalScroll(rememberScrollState())
        ) {
            // ── حالة الخادم ──
            Row(verticalAlignment = Alignment.CenterVertically) {
                StatusPill(
                    if (running) "الخادم حي — 127.0.0.1:$port" else "الخادم متوقف",
                    if (running) Neon else Red
                )
                Spacer(Modifier.weight(1f))
                ActionButton(
                    if (running) "إيقاف" else "تشغيل",
                    Icons.Filled.PowerSettingsNew,
                    onClick = {
                        if (running) { lab.stop(); running = false }
                        else { running = lab.start(); port = lab.port }
                    }
                )
            }
            Spacer(Modifier.height(8.dp))
            Text(
                "بيئة معزولة على جهازك فقط — لا تصل من الشبكة",
                color = TextDim, fontSize = 10.5.sp, fontFamily = TajawalFamily
            )

            // ── أقسام المختبر ──
            Spacer(Modifier.height(12.dp))
            Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                listOf("الخادم", "حقن SQL", "كسر التجزئة", "XSS وملفات").forEachIndexed { i, name ->
                    val sel = tab == i
                    Box(
                        Modifier
                            .clip(RoundedCornerShape(9.dp))
                            .background(if (sel) Neon.copy(alpha = 0.15f) else Surface)
                            .border(1.dp, if (sel) Neon.copy(alpha = 0.7f) else Border, RoundedCornerShape(9.dp))
                            .clickableNoRipple { tab = i }
                            .padding(horizontal = 12.dp, vertical = 7.dp)
                    ) {
                        Text(name, color = if (sel) Neon else TextDim, fontSize = 12.sp, fontFamily = TajawalFamily)
                    }
                }
            }
            Spacer(Modifier.height(14.dp))

            when (tab) {
                0 -> {
                    ResultCard("أهداف المختبر", Neon) {
                        InfoRow("الهدف 1", "بوابة المصادقة — حقن SQL", valueColor = TextMid, mono = false)
                        InfoRow("الهدف 2", "صفحة المراسلة — XSS", valueColor = TextMid, mono = false)
                        InfoRow("الهدف 3", "مجلد المستندات — عبور مسارات", valueColor = TextMid, mono = false)
                        InfoRow("قاعدة البيانات", "SQLite — 5 حسابات بتجزئة MD5", valueColor = TextMid, mono = false)
                    }
                    ResultCard("أدوات الجلسة", Cyan) {
                        InfoRow("المضافة", "كسر التجزئة الحقيقي MD5/SHA-1", valueColor = TextMid, mono = false)
                        InfoRow("المصدر", "كل شيء على جهازك — لا إنترنت", valueColor = TextMid, mono = false)
                    }
                }
                1 -> {
                    Text("المستخدم (الحمولة)", color = TextDim, fontSize = 11.5.sp, fontFamily = TajawalFamily)
                    Spacer(Modifier.height(4.dp))
                    TermField(u, { u = it }, "username")
                    Spacer(Modifier.height(8.dp))
                    Text("كلمة المرور", color = TextDim, fontSize = 11.5.sp, fontFamily = TajawalFamily)
                    Spacer(Modifier.height(4.dp))
                    TermField(p, { p = it }, "password")
                    Spacer(Modifier.height(10.dp))
                    LabPayloads.sqli.forEach { (label, pl) ->
                        Row(
                            Modifier
                                .fillMaxWidth()
                                .padding(vertical = 3.dp)
                                .clip(RoundedCornerShape(8.dp))
                                .background(Surface2)
                                .border(1.dp, Border, RoundedCornerShape(8.dp))
                                .clickableNoRipple { u = pl }
                                .padding(horizontal = 10.dp, vertical = 8.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text(label, color = Cyan, fontSize = 12.sp, fontFamily = TajawalFamily, modifier = Modifier.width(120.dp))
                            Text(pl, color = TextMid, fontSize = 11.sp, fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace, maxLines = 1)
                        }
                    }
                    Spacer(Modifier.height(10.dp))
                    ActionButton("تنفيذ الهجوم (POST /login)", Icons.Filled.Security, enabled = running) {
                        fire("POST", "/login", mapOf("username" to u, "password" to p))
                    }
                }
                2 -> {
                    ResultCard("تجزئة للكسر", Neon) {
                        Text(
                            "استخرج التجزئات من هجوم SQL ثم انسخها هنا — أو اختر من الحسابات:",
                            color = TextDim, fontSize = 11.5.sp, fontFamily = TajawalFamily
                        )
                        Spacer(Modifier.height(8.dp))
                        LabDb.allUsers(context).forEach { row ->
                            Row(Modifier.padding(vertical = 2.dp)) {
                                Text("${row[0]}  ", color = Cyan, fontSize = 11.5.sp, fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace)
                                Text(
                                    row[1], color = TextMid, fontSize = 11.5.sp,
                                    fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace,
                                    modifier = Modifier.clickableNoRipple { hash = row[1]; cracked = null; crackInfo = "" }
                                )
                            }
                        }
                    }
                    Spacer(Modifier.height(8.dp))
                    TermField(hash, { hash = it; cracked = null; crackInfo = "" }, "MD5 أو SHA-1")
                    Spacer(Modifier.height(10.dp))
                    ActionButton("كسر التجزئة (قاموس مدمج)", Icons.Filled.Key, enabled = hash.isNotBlank()) {
                        val r = HashLab.crack(hash)
                        cracked = r.first
                        crackInfo = "جرّبنا ${r.second} كلمة"
                    }
                    cracked?.let {
                        Spacer(Modifier.height(10.dp))
                        if (it != null) {
                            ResultCard("نتيجة الهجوم", Red) {
                                Text("كلمة المرور الأصلية: ", color = TextMid, fontSize = 12.5.sp, fontFamily = TajawalFamily)
                                Text(it, color = Red, fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace, fontWeight = androidx.compose.ui.text.font.FontWeight.Bold, fontSize = 16.sp)
                                Text(crackInfo, color = TextDim, fontSize = 11.sp, fontFamily = TajawalFamily)
                            }
                        } else {
                            ResultCard("نتيجة الهجوم", Amber) {
                                Text("لم تظهر في القاموس", color = Amber, fontSize = 13.sp, fontFamily = TajawalFamily)
                            }
                        }
                    }
                }
                else -> {
                    // XSS / Traversal
                    Row {
                        WebChip("XSS انعكاسي", webSub == 0) { webSub = 0 }
                        Spacer(Modifier.width(8.dp))
                        WebChip("عبور المسارات", webSub == 1) { webSub = 1 }
                    }
                    Spacer(Modifier.height(10.dp))
                    val presets = if (webSub == 0) LabPayloads.xss else LabPayloads.traversal
                    presets.forEach { (label, pl) ->
                        Row(
                            Modifier
                                .fillMaxWidth()
                                .padding(vertical = 3.dp)
                                .clip(RoundedCornerShape(8.dp))
                                .background(Surface2)
                                .border(1.dp, Border, RoundedCornerShape(8.dp))
                                .clickableNoRipple { if (webSub == 0) payload = pl else fpath = pl }
                                .padding(horizontal = 10.dp, vertical = 8.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text(label, color = Cyan, fontSize = 12.sp, fontFamily = TajawalFamily, modifier = Modifier.width(120.dp))
                            Text(pl, color = TextMid, fontSize = 11.sp, fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace, maxLines = 1)
                        }
                    }
                    Spacer(Modifier.height(10.dp))
                    if (webSub == 0) {
                        TermField(payload, { payload = it }, "حمولة XSS")
                        Spacer(Modifier.height(8.dp))
                        ActionButton("إرسال & عرض الرد", Icons.Filled.Code, enabled = running) {
                            fire("GET", "/xss?msg=" + URLEncoder.encode(payload, "UTF-8"))
                        }
                    } else {
                        TermField(fpath, { fpath = it }, "مسار نسبي — جرّب ../")
                        Spacer(Modifier.height(8.dp))
                        ActionButton("قراءة الملف", Icons.Filled.Code, enabled = running) {
                            fire("GET", "/files/" + URLEncoder.encode(fpath, "UTF-8").replace("+", "%20"))
                        }
                    }
                }
            }

            // ── سجل الجلسة ──
            Spacer(Modifier.height(16.dp))
            TermCard("جلسة المختبر — تبادل HTTP حقيقي", term.toList(), color = if (running) Neon else TextMid)
            Spacer(Modifier.height(24.dp))
        }
    }
}

@Composable
private fun WebChip(label: String, selected: Boolean, onClick: () -> Unit) {
    Box(
        Modifier
            .clip(RoundedCornerShape(9.dp))
            .background(if (selected) Cyan.copy(alpha = 0.15f) else Surface)
            .border(1.dp, if (selected) Cyan.copy(alpha = 0.7f) else Border, RoundedCornerShape(9.dp))
            .clickableNoRipple(onClick)
            .padding(horizontal = 14.dp, vertical = 7.dp)
    ) {
        Text(label, color = if (selected) Cyan else TextDim, fontSize = 12.sp, fontFamily = TajawalFamily)
    }
}
