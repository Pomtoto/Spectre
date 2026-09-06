package com.spectre.osint.ui.tools

import android.content.Context
import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.PickVisualMediaRequest
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Android
import androidx.compose.material.icons.filled.Description
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.spectre.osint.core.*
import com.spectre.osint.ui.*
import com.spectre.osint.ui.theme.*
import kotlinx.coroutines.launch

// ════════════════════════════════════════════════════════════════
//  تحليل HTTP — أمان الرأسيات والبصمة
// ════════════════════════════════════════════════════════════════
@Composable
fun HttpScreen(onBack: () -> Unit) {
    val scope = rememberCoroutineScope()
    var url by remember { mutableStateOf("") }
    var lines by remember { mutableStateOf<List<TLine>>(emptyList()) }
    var error by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }

    ToolScaffold("HTTP ANALYSIS", "رأسيات الأمان وبصمة الخادم لأي موقع", onBack) { pad ->
        Column(
            Modifier.padding(pad).padding(16.dp).verticalScroll(rememberScrollState())
        ) {
            TermField(url, { url = it }, "https://example.com")
            Spacer(Modifier.height(10.dp))
            ActionButton("تحليل الاستجابة", Icons.Filled.Security, enabled = url.isNotBlank() && !busy) {
                busy = true; error = null; lines = emptyList()
                scope.launch {
                    val r = httpAnalyze(url)
                    busy = false
                    r.fold(
                        onSuccess = { h ->
                            val out = ArrayList<TLine>()
                            out.add(tHead("HTTP PROBE — ${h.status}"))
                            out.add(tInfo("الوجهة: ${h.finalUrl.take(70)}"))
                            out.add(tInfo("الخادم: ${h.server}"))
                            if (h.poweredBy != "—") out.add(tWarn("X-Powered-By: ${h.poweredBy} — يكشف التقنية"))
                            out.add(tInfo("التشفير: ${h.protocol}"))
                            out.add(tDim("رأسيات الأمان: ${h.present.size}/${SECURITY_HEADERS.size}"))
                            h.present.forEach { out.add(tOk("$it  محميّ")) }
                            h.missing.forEach { out.add(tWarn("$it  مفقودة")) }
                            if (h.cookieFlags.any { it.contains("بدون حماية") }) {
                                out.add(tBad("Cookies بدون أعلام حماية"))
                                h.cookieFlags.forEach { out.add(tBad("cookie: $it")) }
                            } else if (h.cookieFlags.isNotEmpty()) {
                                h.cookieFlags.forEach { out.add(tOk("cookie: $it")) }
                            }
                            out.add(tDim("التقييم: ${h.score}%"))
                            lines = out
                        },
                        onFailure = { error = it.message }
                    )
                }
            }
            if (busy) { Spacer(Modifier.height(12.dp)); ScanningBar("جارٍ إرسال طلب التحليل") }
            error?.let { Spacer(Modifier.height(10.dp)); Text(it, color = Red, fontSize = 13.sp) }
            if (lines.isNotEmpty()) {
                Spacer(Modifier.height(14.dp))
                TermCard("تقرير الرأسيات", lines, color = Violet)
            }
            Spacer(Modifier.height(24.dp))
        }
    }
}

// ════════════════════════════════════════════════════════════════
//  محلل APK
// ════════════════════════════════════════════════════════════════
@Composable
fun ApkScreen(onBack: () -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var lines by remember { mutableStateOf<List<TLine>>(emptyList()) }
    var error by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }

    fun run(uri: Uri) {
        busy = true; error = null; lines = emptyList()
        scope.launch {
            val r = analyzeApk(context, uri)
            busy = false
            r.fold(
                onSuccess = { a ->
                    val out = ArrayList<TLine>()
                    out.add(tHead("APK DECONSTRUCT — ${"%.1f".format(a.size / 1048576.0)} MB"))
                    out.add(tInfo("مدخلات الحزمة: ${a.entries} • DEX: ${a.dexCount} • غير مضغوط: ${"%.1f".format(a.totalUncompressed / 1048576.0)} MB"))
                    out.add(tInfo("التوقيع: ${if (a.signedV1) "V1 ($a.certAlgo)" else "بدون V1"}"))
                    out.add(tInfo("المُصدر: ${a.certSubject}"))
                    out.add(tInfo("صالح حتى: ${a.certTo}"))
                    if (a.libs.isNotEmpty()) out.add(tInfo("مكتبات أصلية: ${a.libs.joinToString(" ")}"))
                    out.add(tDim("الصلاحيات: ${a.permissions.size}"))
                    val dangerous = a.permissions.filter { it in DANGEROUS_PERMS }
                    a.permissions.forEach { p ->
                        if (p in DANGEROUS_PERMS) out.add(tWarn("$p"))
                        else out.add(TLine(p, 3))
                    }
                    if (a.trackers.isNotEmpty()) {
                        out.add(tDim("متتبعات: ${a.trackers.size}"))
                        a.trackers.forEach { out.add(tBad("tracker: $it")) }
                    }
                    if (dangerous.size >= 4) {
                        out.add(tWarn("عدد الصلاحيات الخطيرة مرتفع (${dangerous.size})"))
                    }
                    out.add(tDim("تحليل مباشر من ثنائي الحزمة"))
                    lines = out
                },
                onFailure = { error = it.message }
            )
        }
    }

    val picker = rememberLauncherForActivityResult(ActivityResultContracts.GetContent()) { u ->
        if (u != null) run(u)
    }

    ToolScaffold("APK DECONSTRUCTOR", "تحليل حزمة APK: الشهادة، الصلاحيات، المتتبعات", onBack) { pad ->
        Column(
            Modifier.padding(pad).padding(16.dp).verticalScroll(rememberScrollState())
        ) {
            ActionButton("اختيار ملف APK", Icons.Filled.Android, enabled = !busy) {
                picker.launch("application/vnd.android.package-archive")
            }
            if (busy) { Spacer(Modifier.height(12.dp)); ScanningBar("جارٍ تفكيك الحزمة") }
            error?.let { Spacer(Modifier.height(10.dp)); Text(it, color = Red, fontSize = 13.sp) }
            if (lines.isNotEmpty()) {
                Spacer(Modifier.height(14.dp))
                TermCard("تقرير الحزمة", lines, color = Cyan)
            }
            Spacer(Modifier.height(24.dp))
        }
    }
}

// ════════════════════════════════════════════════════════════════
//  فاحص الملفات — توقيع + بصمات + نصوص
// ════════════════════════════════════════════════════════════════
@Composable
fun FileScreen(onBack: () -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var lines by remember { mutableStateOf<List<TLine>>(emptyList()) }
    var error by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }

    fun run(uri: Uri, name: String?) {
        busy = true; error = null; lines = emptyList()
        scope.launch {
            val r = analyzeFile(context, uri, name)
            busy = false
            r.fold(
                onSuccess = { f ->
                    val out = ArrayList<TLine>()
                    out.add(tHead("FILE SIG — ${f.detected}"))
                    out.add(tInfo("الحجم: ${"%.1f".format(f.size / 1024.0)} KB"))
                    out.add(if (f.matchesExt) tOk("الامتداد مطابق للنوع") else tWarn("الامتداد لا يطابق المحتوى الحقيقي"))
                    out.add(tDim("MD5    ${f.md5}"))
                    out.add(tDim("SHA-1  ${f.sha1}"))
                    out.add(tDim("SHA256 ${f.sha256}"))
                    if (f.strings.isNotEmpty()) {
                        out.add(tDim("نصوص مضمّنة (أول ${f.strings.size}):"))
                        f.strings.forEach { out.add(TLine(it.take(70), 3)) }
                    }
                    lines = out
                },
                onFailure = { error = it.message }
            )
        }
    }

    val picker = rememberLauncherForActivityResult(ActivityResultContracts.GetContent()) { u ->
        if (u != null) run(u, null)
    }

    ToolScaffold("FILE INSPECTOR", "التعرف على أي ملف: التوقيع، البصمات، النصوص المضمّنة", onBack) { pad ->
        Column(
            Modifier.padding(pad).padding(16.dp).verticalScroll(rememberScrollState())
        ) {
            ActionButton("اختيار ملف", Icons.Filled.Description, enabled = !busy) {
                picker.launch("*/*")
            }
            if (busy) { Spacer(Modifier.height(12.dp)); ScanningBar("جارٍ التحليل") }
            error?.let { Spacer(Modifier.height(10.dp)); Text(it, color = Red, fontSize = 13.sp) }
            if (lines.isNotEmpty()) {
                Spacer(Modifier.height(14.dp))
                TermCard("نتيجة الفحص", lines, color = Amber)
            }
            Spacer(Modifier.height(24.dp))
        }
    }
}
