package com.spectre.osint.ui.tools

import android.content.Context
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Email
import androidx.compose.material.icons.filled.Language
import androidx.compose.material.icons.filled.Password
import androidx.compose.material3.Text
import androidx.compose.material3.TextField
import androidx.compose.material3.TextFieldDefaults
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.spectre.osint.core.*
import com.spectre.osint.ui.*
import com.spectre.osint.ui.theme.*
import kotlinx.coroutines.launch

// ════════════════════════════════════════════════════════════════
//  مراقب التسريبات — 3 أوضاع: موقع / حساب / كلمة مرور
// ════════════════════════════════════════════════════════════════
@Composable
fun BreachScreen(onBack: () -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val prefs = remember { context.getSharedPreferences("spectre", Context.MODE_PRIVATE) }

    var tab by remember { mutableStateOf(0) }  // 0 موقع | 1 حساب | 2 كلمة مرور

    // وضع الموقع
    var domain by remember { mutableStateOf("") }
    var siteLines by remember { mutableStateOf<List<TLine>>(emptyList()) }
    var siteVerdict by remember { mutableStateOf<Pair<String, Int>?>(null) } // نص + 0خطر/1تحذير/2سليم

    // وضع الحساب
    var account by remember { mutableStateOf("") }
    var key by remember { mutableStateOf(prefs.getString("hibp_key", "") ?: "") }
    var showKey by remember { mutableStateOf(false) }
    var acctResult by remember { mutableStateOf<BreachResult?>(null) }

    // وضع كلمة المرور
    var pw by remember { mutableStateOf("") }
    var pwCount by remember { mutableStateOf<Long?>(null) }
    var pwBusy by remember { mutableStateOf(false) }

    var busy by remember { mutableStateOf(false) }

    fun checkSite() {
        val catalog = loadCatalog(context)
        val hits = searchDomainBreaches(catalog, domain)
        val out = ArrayList<TLine>()
        val dq = normalizeDomain(domain)
        out.add(tHead("BREACH RECORD — $dq"))
        out.add(tInfo("المصدر: فهرس التسريبات المرفق v4.1 (سجلات عامة موثقة)"))
        if (hits.isEmpty()) {
            out.add(tWarn("لا سجلات مسربة موثقة لهذا النطاق في الفهرس"))
            out.add(tInfo("مع ذلك، سجلات السارقين (stealer logs) تُستعلم لكل حساب وليس لكل موقع"))
            out.add(tInfo("استخدم تبويب الحساب لفحص بريدك، وتبويب كلمة المرور لفحص كلماتك"))
            siteVerdict = "لا سجلات موثقة" to 2
        } else {
            val total = hits.sumOf { it.count }
            out.add(tOk("${hits.size} تسريباً موثقاً (${formatCount(total)} سجل)"))
            hits.forEach { b ->
                out.add(
                    TLine("${b.date}  ${b.name}  ·  ${formatCount(b.count)} حساب", 0)
                )
                out.add(TLine("         بيانات: ${b.classes.joinToString("، ")}", 3))
            }
            if (hits.any { it.stealer }) {
                out.add(tWarn("تتضمن السجلات من سجلات سارقين — اعتبر كلمات مرورك لكل المواقع المستخدمة مكشوفة"))
            }
            siteVerdict = "${hits.size} تسريباً موثقاً" to if (hits.any { it.stealer }) 0 else 1
        }
        // أكبر تسريب عالمي للمرجع
        val top = loadCatalog(context).sortedByDescending { it.count }.take(3)
        out.add(tDim("أكبر التسريبات المسجلة عالمياً:"))
        top.forEach { out.add(TLine("${it.name} — ${formatCount(it.count)}", 4)) }
        siteLines = out
    }

    fun checkAccount() {
        if (account.isBlank()) return
        prefs.edit().putString("hibp_key", key).apply()
        busy = true; acctResult = null
        scope.launch {
            acctResult = checkBreaches(account, key)
            busy = false
        }
    }

    fun checkPw() {
        if (pw.isBlank()) return
        pwBusy = true; pwCount = null
        scope.launch {
            pwCount = hibpPasswordCount(pw)
            pwBusy = false
        }
    }

    ToolScaffold("BREACH INTELLIGENCE", "هل هُرق هذا الموقع أو حسابك أو كلمتك؟", onBack) { pad ->
        Column(
            Modifier.padding(pad).padding(16.dp).verticalScroll(rememberScrollState())
        ) {
            // ── الأوضاع ──
            Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                listOf("موقع", "حساب", "كلمة مرور").forEachIndexed { i, label ->
                    val sel = tab == i
                    Box(
                        Modifier
                            .clip(RoundedCornerShape(9.dp))
                            .background(if (sel) Neon.copy(alpha = 0.15f) else Surface)
                            .border(1.dp, if (sel) Neon.copy(alpha = 0.7f) else Border, RoundedCornerShape(9.dp))
                            .clickableNoRipple { tab = i }
                            .padding(horizontal = 16.dp, vertical = 8.dp)
                    ) {
                        Text(label, color = if (sel) Neon else TextDim, fontSize = 12.5.sp, fontWeight = FontWeight.Bold, fontFamily = TajawalFamily)
                    }
                }
            }
            Spacer(Modifier.height(14.dp))

            when (tab) {
                0 -> {
                    TermField(domain, { domain = it }, "example.com أو أي موقع")
                    Spacer(Modifier.height(10.dp))
                    ActionButton("استعلام الموقع", Icons.Filled.Language, enabled = domain.isNotBlank() && !busy) {
                        siteVerdict = null; siteLines = emptyList(); checkSite()
                    }
                    siteVerdict?.let { (txt, sc) ->
                        Spacer(Modifier.height(12.dp))
                        val col = when (sc) { 1 -> Amber; 0 -> Red; else -> Neon }
                        StatusPill(txt, col)
                    }
                    if (siteLines.isNotEmpty()) {
                        Spacer(Modifier.height(10.dp))
                        TermCard("ملف النطاق", siteLines, color = Cyan)
                    }
                    Spacer(Modifier.height(6.dp))
                    Text(
                        "ملاحظة: الفهرس المرفق يغطي أبرز التسريبات الموثقة — الفحص الحيّ الكامل لأي حساب عبر Have I Been Pwned في تبويب «حساب».",
                        color = TextDim, fontSize = 11.sp, lineHeight = 16.sp, fontFamily = TajawalFamily
                    )
                }
                1 -> {
                    TermField(account, { account = it }, "البريد الإلكتروني أو رقم الهاتف")
                    Spacer(Modifier.height(10.dp))
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(
                            if (showKey) "إخفاء المفتاح" else "إعدادات المفتاح",
                            color = Cyan, fontSize = 12.sp, fontFamily = TajawalFamily,
                            modifier = Modifier.clickableNoRipple { showKey = !showKey }
                        )
                        Spacer(Modifier.width(8.dp))
                        Box(Modifier.size(6.dp).clip(RoundedCornerShape(3.dp)).background(if (key.isNotBlank()) Neon else TextDim))
                    }
                    if (showKey) {
                        Spacer(Modifier.height(8.dp))
                        TextField(
                            value = key, onValueChange = { key = it },
                            modifier = Modifier.fillMaxWidth(), singleLine = true,
                            colors = TextFieldDefaults.colors(
                                focusedContainerColor = Surface2, unfocusedContainerColor = Surface2,
                                focusedIndicatorColor = Cyan, unfocusedIndicatorColor = Border, cursorColor = Cyan,
                                focusedTextColor = TextHi, unfocusedTextColor = TextHi
                            ),
                            textStyle = androidx.compose.ui.text.TextStyle(color = TextHi, fontSize = 13.sp),
                            placeholder = { Text("مفتاح API مجاني من haveibeenpwned.com", color = TextDim) },
                            shape = RoundedCornerShape(10.dp)
                        )
                        Spacer(Modifier.height(6.dp))
                        Text(
                            "مفتاح مجاني: سجّل في haveibeenpwned.com ثم أنشئ مفتاح API من صفحة الإعدادات. يبقى على جهازك فقط.",
                            color = TextDim, fontSize = 11.sp, lineHeight = 16.sp, fontFamily = TajawalFamily
                        )
                    }
                    Spacer(Modifier.height(10.dp))
                    ActionButton("فحص الحساب", Icons.Filled.Email, enabled = account.isNotBlank() && !busy) { checkAccount() }
                    if (busy) { Spacer(Modifier.height(12.dp)); ScanningBar("جارٍ البحث في قاعدة HIBP") }

                    when (val r = acctResult) {
                        is BreachResult.NoKey -> {
                            Spacer(Modifier.height(14.dp))
                            Text("يلزم مفتاح API مجاني — افتح «إعدادات المفتاح» أعلاه.", color = Amber, fontSize = 13.sp, fontFamily = TajawalFamily)
                        }
                        is BreachResult.BadKey -> {
                            Spacer(Modifier.height(14.dp))
                            Text("المفتاح غير صالح — تحقق منه ثم أعد المحاولة.", color = Red, fontSize = 13.sp, fontFamily = TajawalFamily)
                        }
                        is BreachResult.Err -> {
                            Spacer(Modifier.height(14.dp))
                            Text(r.msg, color = Red, fontSize = 13.sp, fontFamily = TajawalFamily)
                        }
                        is BreachResult.Ok -> {
                            if (r.items.isEmpty()) {
                                Spacer(Modifier.height(12.dp))
                                ResultCard("نتيجة الفحص", Neon) {
                                    StatusPill("لا تسريب مسجل لهذا الحساب", Neon)
                                    Spacer(Modifier.height(8.dp))
                                    Text(
                                        "غير وارد في قاعدة Have I Been Pwned — استمر بتفعيل المصادقة الثنائية.",
                                        color = TextMid, fontSize = 12.5.sp, fontFamily = TajawalFamily
                                    )
                                }
                            } else {
                                Spacer(Modifier.height(12.dp))
                                ResultCard("المخاطر — ${r.items.size} تسريباً", Red) {
                                    Text(
                                        "الحساب مسرّب — غيّر كلمة المرور فوراً وحدّث كل حساب يستخدمها.",
                                        color = Red, fontSize = 12.5.sp, fontFamily = TajawalFamily
                                    )
                                }
                                r.items.forEach { b ->
                                    ResultCard("${b.title}", if (b.count > 10_000_000L) Red else Amber) {
                                        InfoRow("النطاق", b.domain, valueColor = TextMid, mono = false)
                                        InfoRow("تاريخ التسريب", b.date, valueColor = TextMid)
                                        CopyRow("الحسابات", "%,d".format(b.count))
                                        InfoRow("البيانات المكشوفة", b.classes.joinToString("، "), valueColor = TextMid, mono = false)
                                    }
                                }
                            }
                        }
                        null -> if (!busy) EmptyHint(
                            "أدخل حساباً للتحقق من تسريبه",
                            "التحقق من حساباتك أنت — استخدام بيانات الآخرين غير مشروع"
                        )
                    }
                }
                else -> {
                    TermField(pw, { pw = it }, "كلمة المرور لفحصها في قاعدة التسريبات")
                    Spacer(Modifier.height(10.dp))
                    ActionButton("فحص كلمة المرور", Icons.Filled.Password, enabled = pw.isNotBlank() && !pwBusy) { checkPw() }
                    if (pwBusy) { Spacer(Modifier.height(12.dp)); ScanningBar("جارٍ الاستعلام (k-anonymity)") }
                    pwCount?.let { c ->
                        Spacer(Modifier.height(12.dp))
                        if (c == 0L) {
                            ResultCard("نتيجة الفحص", Neon) {
                                StatusPill("لم تظهر في أي تسريب معروف", Neon)
                                Spacer(Modifier.height(8.dp))
                                Text("لا تظهر هذه الكلمة في قاعدة Pwned Passwords — تبقى قوية.", color = TextMid, fontSize = 12.5.sp, fontFamily = TajawalFamily)
                            }
                        } else {
                            ResultCard("نتيجة الفحص", Red) {
                                StatusPill("ظهرت $c مرات في التسريبات", Red)
                                Spacer(Modifier.height(8.dp))
                                Text(
                                    "هذه الكلمة مكشوفة — لا تعتمدها في أي حساب. التغيير الفوري إلزامي.",
                                    color = TextMid, fontSize = 12.5.sp, fontFamily = TajawalFamily
                                )
                            }
                        }
                    }
                    if (pwCount == null && !pwBusy) EmptyHint(
                        "اكتب كلمة مرور لفحصها",
                        "يتم عبر بروتوكول k-anonymity — لا تُرسل الكلمة نفسها أبداً"
                    )
                }
            }
            Spacer(Modifier.height(24.dp))
        }
    }
}
