package com.spectre.osint.ui.tools

import android.os.Build
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Calculate
import androidx.compose.material.icons.filled.PhoneAndroid
import androidx.compose.material3.Text
import androidx.compose.material3.TextField
import androidx.compose.material3.TextFieldDefaults
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.draw.clip
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.shape.RoundedCornerShape
import com.spectre.osint.core.*
import com.spectre.osint.ui.*
import com.spectre.osint.ui.theme.*
import kotlinx.coroutines.launch

// ════════════════════════════════════════════════════════════════
//  مختبر الترميز — Crypto Lab
// ════════════════════════════════════════════════════════════════
private val cryptoOps = listOf(
    "MD5" to "MD5", "SHA-1" to "SHA-1", "SHA-256" to "SHA-256", "SHA-512" to "SHA-512",
    "Base64 تشفير" to "b64e", "Base64 فك" to "b64d",
    "Hex تشفير" to "hexE", "Hex فك" to "hexD",
    "URL تشفير" to "urlE", "URL فك" to "urlD",
    "ROT13" to "rot13", "XOR" to "xor"
)

@Composable
fun CryptoScreen(onBack: () -> Unit) {
    val clip = androidx.compose.ui.platform.LocalClipboardManager.current
    var input by remember { mutableStateOf("") }
    var key by remember { mutableStateOf("") }
    var output by remember { mutableStateOf("") }
    var chosen by remember { mutableStateOf(0) }

    val lines = buildList {
        val tag = cryptoOps[chosen].first
        val res = when (cryptoOps[chosen].second) {
            "MD5" -> Crypter.md5(input)
            "SHA-1" -> Crypter.sha1(input)
            "SHA-256" -> Crypter.sha256(input)
            "SHA-512" -> Crypter.sha512(input)
            "b64e" -> Crypter.b64e(input)
            "b64d" -> Crypter.b64d(input)
            "hexE" -> Crypter.hexE(input)
            "hexD" -> Crypter.hexD(input)
            "urlE" -> Crypter.urlE(input)
            "urlD" -> Crypter.urlD(input)
            "rot13" -> Crypter.rot13(input)
            else -> Crypter.xor(input, key)
        }
        if (input.isNotBlank() || tag == "Base64 فك") {
            add(tHead("SPECTRE $tag"))
            add(tInfo("المدخل: ${input.take(60)}"))
            add(tDim("المخرجات:"))
            if (res.contains("غير صالحة") || res.contains("أدخل مفتاحاً")) add(tWarn(res))
            else add(tOk(res))
            add(tDim("نسخة: $tag"))
        }
    }

    ToolScaffold("CRYPTO LAB", "تجزئة، تشفير وفك: Base64/Hex/URL/XOR/ROT13", onBack) { pad ->
        Column(
            Modifier.padding(pad).padding(16.dp).verticalScroll(rememberScrollState())
        ) {
            // اختيار العملية
            Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                cryptoOps.forEachIndexed { idx, (name, _) ->
                    val sel = chosen == idx
                    Box(
                        Modifier
                            .clip(RoundedCornerShape(9.dp))
                            .background(if (sel) Neon.copy(alpha = 0.15f) else Surface)
                            .border(1.dp, if (sel) Neon.copy(alpha = 0.7f) else Border, RoundedCornerShape(9.dp))
                            .clickableNoRipple { chosen = idx }
                            .padding(horizontal = 12.dp, vertical = 7.dp)
                    ) {
                        Text(name, color = if (sel) Neon else TextDim, fontSize = 12.sp)
                    }
                }
            }
            Spacer(Modifier.height(12.dp))

            if (cryptoOps[chosen].second == "xor") {
                TermField(key, { key = it }, "مفتاح XOR")
                Spacer(Modifier.height(8.dp))
            }
            TextField(
                value = input,
                onValueChange = { input = it },
                modifier = Modifier.fillMaxWidth(),
                minLines = 2,
                colors = TextFieldDefaults.colors(
                    focusedContainerColor = Surface2, unfocusedContainerColor = Surface2,
                    focusedIndicatorColor = Neon, unfocusedIndicatorColor = Border, cursorColor = Neon,
                    focusedTextColor = TextHi, unfocusedTextColor = TextHi
                ),
                textStyle = androidx.compose.ui.text.TextStyle(color = TextHi, fontSize = 14.sp),
                placeholder = { Text("النص أو القيمة", color = TextDim) },
                shape = RoundedCornerShape(10.dp)
            )
            Spacer(Modifier.height(10.dp))
            Row {
                ActionButton("تنفيذ", Icons.Filled.Calculate, enabled = input.isNotBlank()) {
                    val res = when (cryptoOps[chosen].second) {
                        "MD5" -> Crypter.md5(input); "SHA-1" -> Crypter.sha1(input)
                        "SHA-256" -> Crypter.sha256(input); "SHA-512" -> Crypter.sha512(input)
                        "b64e" -> Crypter.b64e(input); "b64d" -> Crypter.b64d(input)
                        "hexE" -> Crypter.hexE(input); "hexD" -> Crypter.hexD(input)
                        "urlE" -> Crypter.urlE(input); "urlD" -> Crypter.urlD(input)
                        "rot13" -> Crypter.rot13(input)
                        else -> Crypter.xor(input, key)
                    }
                    output = res
                }
            }
            if (output.isNotBlank()) {
                Spacer(Modifier.height(10.dp))
                CopyRow("النتيجة", output, Neon)
            }
            if (lines.isNotEmpty()) {
                Spacer(Modifier.height(12.dp))
                TermCard("سجل العملية", lines, color = Neon)
            }
            Spacer(Modifier.height(24.dp))
        }
    }
}

// ════════════════════════════════════════════════════════════════
//  فحص أمان الجهاز — Device Audit
// ════════════════════════════════════════════════════════════════
@Composable
fun DeviceAuditScreen(onBack: () -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var lines by remember { mutableStateOf<List<TLine>>(emptyList()) }
    var busy by remember { mutableStateOf(false) }
    var score by remember { mutableStateOf<Int?>(null) }

    ToolScaffold("DEVICE AUDIT", "حالة الحماية العامة لجهازك", onBack) { pad ->
        Column(
            Modifier.padding(pad).padding(16.dp).verticalScroll(rememberScrollState())
        ) {
            ActionButton("بدء الفحص", Icons.Filled.PhoneAndroid, enabled = !busy) {
                busy = true; lines = emptyList(); score = null
                scope.launch {
                    val (checks, sc) = auditDevice(context)
                    busy = false
                    score = sc
                    val out = ArrayList<TLine>()
                    out.add(tHead("DEVICE AUDIT — ${Build.MODEL}"))
                    checks.forEach { c ->
                        val colorLine = if (c.good) tOk(c.title + ": " + c.value) else tBad(c.title + ": " + c.value)
                        out.add(colorLine)
                    }
                    out.add(tDim("التقييم العام: $sc%"))
                    lines = out
                }
            }
            if (busy) { Spacer(Modifier.height(12.dp)); ScanningBar("جارٍ قراءة حالة النظام") }
            if (score != null) {
                Spacer(Modifier.height(12.dp))
                StatusPill(
                    when { score!! >= 80 -> "الجهاز محصّن"; score!! >= 50 -> "تحسينات مطلوبة"; else -> "مخاطر مرتفعة" },
                    when { score!! >= 80 -> Neon; score!! >= 50 -> Amber; else -> Red }
                )
            }
            if (lines.isNotEmpty()) {
                Spacer(Modifier.height(14.dp))
                TermCard("تقرير الحماية", lines, color = if ((score ?: 100) >= 80) Neon else Amber)
            }
            Spacer(Modifier.height(24.dp))
        }
    }
}
