package com.spectre.osint.ui.tools

import android.content.Intent
import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.PickVisualMediaRequest
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Image
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.MyLocation
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.spectre.osint.core.*
import com.spectre.osint.ui.*
import com.spectre.osint.ui.theme.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

// ════════════════════════════════════════════════════════════════
//  محلل الصور — Image Forensics
// ════════════════════════════════════════════════════════════════
@Composable
fun ExifScreen(onBack: () -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var uri by remember { mutableStateOf<Uri?>(null) }
    var exif by remember { mutableStateOf<ExifData?>(null) }
    var geoName by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }

    val picker = rememberLauncherForActivityResult(ActivityResultContracts.PickVisualMedia()) { u ->
        if (u != null) {
            uri = u; exif = null; geoName = null; error = null; busy = true
            scope.launch {
                val e = withContext(Dispatchers.IO) { readExif(context, u) }
                if (e == null) error = "تعذر قراءة بيانات الصورة أو أن الملف غير مدعوم"
                else {
                    exif = e
                    if (e.hasGps) geoName = reverseGeocode(e.lat!!, e.lon!!)
                }
                busy = false
            }
        }
    }

    ToolScaffold("IMAGE FORENSICS", "استخراج كل ما هو مخفي داخل الصورة", onBack) { pad ->
        Column(
            Modifier.padding(pad).padding(16.dp).verticalScroll(rememberScrollState())
        ) {
            ActionButton("اختيار صورة من المعرض", Icons.Filled.Image) {
                picker.launch(PickVisualMediaRequest(ActivityResultContracts.PickVisualMedia.ImageOnly))
            }

            if (busy) { Spacer(Modifier.height(18.dp)); ScanningBar("جارٍ فحص البيانات الوصفية") }
            error?.let {
                Spacer(Modifier.height(14.dp))
                Text(it, color = Red, fontSize = 13.sp, fontFamily = TajawalFamily)
            }

            val d = exif
            if (d != null) {
                ResultCard("بيانات الجهاز المصوِّر") {
                    InfoRow("الشركة المصنّعة", d.make)
                    InfoRow("الموديل", d.model)
                    InfoRow("البرنامج", d.software)
                    InfoRow("التاريخ والوقت", d.dateTaken)
                }
                ResultCard("إعدادات الالتقاط") {
                    InfoRow("الأبعاد", "${d.width} × ${d.height}")
                    InfoRow("الحساسية ISO", d.iso)
                    InfoRow("الفتحة", d.fNumber)
                    InfoRow("زمن التعريض", d.exposure)
                    InfoRow("البعد البؤري", d.focal)
                }
                ResultCard(
                    if (d.hasGps) "الموقع الجغرافي — تم التقاطها هنا" else "الموقع الجغرافي",
                    color = if (d.hasGps) Red else Neon
                ) {
                    if (d.hasGps) {
                        CopyRow("الإحداثيات", "%.6f, %.6f".format(d.lat!!, d.lon!!), Red)
                        InfoRow("العنوان", geoName ?: "جارٍ تحديد الموقع…", valueColor = TextMid, mono = false)
                        InfoRow("الارتفاع", d.altitude)
                        Spacer(Modifier.height(6.dp))
                        ActionButton("فتح الموقع في الخرائط", Icons.Filled.MyLocation) {
                            try {
                                val geo = "geo:${d.lat},${d.lon}?q=${d.lat},${d.lon}"
                                context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(geo)))
                            } catch (e: Exception) {}
                        }
                    } else {
                        Text(
                            "لا توجد إحداثيات GPS — الصورة نظيفة من بصمة الموقع",
                            color = Neon, fontSize = 12.5.sp, fontFamily = TajawalFamily
                        )
                    }
                }
                ResultCard("البيانات الخام (DMS)") {
                    InfoRow("خط العرض", d.gpsRawLat, valueColor = TextMid)
                    InfoRow("خط الطول", d.gpsRawLon, valueColor = TextMid)
                }
            }

            if (uri == null && !busy) {
                EmptyHint(
                    "اختر صورة لبدء التحليل",
                    "تظهر النتائج: الجهاز، وقت الالتقاط، والموقع الجغرافي إن كان مرفقاً"
                )
            }
            Spacer(Modifier.height(24.dp))
        }
    }
}

// ════════════════════════════════════════════════════════════════
//  محلل كلمات المرور — Password Auditor
// ════════════════════════════════════════════════════════════════
private fun generatePassword(len: Int = 16): String {
    val chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#%&*"
    return (1..len).map { chars.random() }.joinToString("")
}

@Composable
fun PasswordScreen(onBack: () -> Unit) {
    val scope = rememberCoroutineScope()
    var pw by remember { mutableStateOf("") }
    var visible by remember { mutableStateOf(false) }
    var report by remember { mutableStateOf<PwReport?>(null) }
    var leak by remember { mutableStateOf<Long?>(null) }
    var busy by remember { mutableStateOf(false) }

    fun analyze() {
        if (pw.isEmpty()) return
        report = analyzePassword(pw); leak = null; busy = true
        scope.launch {
            leak = hibpPasswordCount(pw)
            busy = false
        }
    }

    ToolScaffold("PASSWORD AUDITOR", "هل كلمة مرورك قابلة للكسر؟ وهل سُرقت من قبل؟", onBack) { pad ->
        Column(
            Modifier.padding(pad).padding(16.dp).verticalScroll(rememberScrollState())
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                TextField(
                    value = pw,
                    onValueChange = { pw = it },
                    modifier = Modifier.weight(1f),
                    visualTransformation = if (visible) VisualTransformation.None else PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                    singleLine = true,
                    colors = TextFieldDefaults.colors(
                        focusedContainerColor = Surface2,
                        unfocusedContainerColor = Surface2,
                        focusedIndicatorColor = Neon,
                        unfocusedIndicatorColor = Border,
                        cursorColor = Neon,
                        focusedTextColor = TextHi,
                        unfocusedTextColor = TextHi
                    ),
                    textStyle = androidx.compose.ui.text.TextStyle(color = TextHi, fontSize = 14.sp),
                    placeholder = { Text("كلمة المرور", color = TextDim) },
                    shape = androidx.compose.foundation.shape.RoundedCornerShape(10.dp),
                    trailingIcon = {
                        IconButton(onClick = { visible = !visible }) {
                            Icon(
                                if (visible) Icons.Filled.VisibilityOff else Icons.Filled.Visibility,
                                "إظهار",
                                tint = TextMid
                            )
                        }
                    }
                )
            }

            Spacer(Modifier.height(10.dp))
            ActionButton("بدء الفحص", Icons.Filled.Key, enabled = pw.isNotEmpty()) { analyze() }
            Spacer(Modifier.height(6.dp))
            Text(
                "توليد كلمة مرور عشوائية قوية",
                color = Cyan,
                fontSize = 12.sp,
                fontFamily = TajawalFamily,
                modifier = Modifier.clickableNoRipple { pw = generatePassword() }
            )

            if (busy) { Spacer(Modifier.height(18.dp)); ScanningBar("جارٍ فحص قواعد التسريبات") }

            val r = report
            if (r != null) {
                val sc = when (r.score) { 0 -> Red; 1 -> Amber; else -> Neon }
                val label = when (r.score) { 0 -> "ضعيفة"; 1 -> "متوسطة"; else -> "قوية" }
                ResultCard("تقدير القوة", sc) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        StatusPill(label, sc)
                        Spacer(Modifier.width(10.dp))
                        Text("%.0f بت إنتروبيا".format(r.bits), color = TextMid, fontSize = 12.sp)
                    }
                    Spacer(Modifier.height(8.dp))
                    InfoRow("الطول", "${r.len} حرفاً")
                    InfoRow("التراكيب", if (r.classes.isEmpty()) "—" else r.classes.joinToString(" + "), valueColor = TextMid, mono = false)
                    InfoRow("كسر بدون اتصال", r.offline, sc)
                    InfoRow("كسر عبر الإنترنت", r.online, sc)
                }
                ResultCard("المواقع المسرّبة", if (leak == null) TextMid else if (leak == 0L) Neon else Red) {
                    when {
                        leak == null -> ScanningBar("جارٍ فحص HIBP")
                        leak == 0L -> Text(
                            "لم تظهر كلمة المرور هذه في أي تسريب معروف",
                            color = Neon, fontSize = 13.sp, fontFamily = TajawalFamily
                        )
                        else -> Text(
                            "ظهرت ${leak} مرات في قواعد التسريبات — اعتبرها مكشوفة تماماً",
                            color = Red, fontWeight = androidx.compose.ui.text.font.FontWeight.Bold,
                            fontSize = 13.sp, fontFamily = TajawalFamily
                        )
                    }
                }
            }

            if (r == null) {
                EmptyHint(
                    "اكتب كلمة مرور لاختبار قوتها",
                    "الفحص يتم محلياً، والتسريبات عبر خدمة HIBP المفتوحة"
                )
            }
            Spacer(Modifier.height(24.dp))
        }
    }
}
