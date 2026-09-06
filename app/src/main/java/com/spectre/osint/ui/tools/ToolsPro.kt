package com.spectre.osint.ui.tools

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Devices
import androidx.compose.material.icons.filled.NetworkCheck
import androidx.compose.material.icons.filled.TravelExplore
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.spectre.osint.core.*
import com.spectre.osint.ui.*
import com.spectre.osint.ui.theme.*
import kotlinx.coroutines.launch

// ════════════════════════════════════════════════════════════════
//  ماسح المنافذ — Port Scanner (TCP Connect، بدون روت)
// ════════════════════════════════════════════════════════════════
@Composable
fun PortScreen(onBack: () -> Unit) {
    val scope = rememberCoroutineScope()
    var target by remember { mutableStateOf("") }
    var lines by remember { mutableStateOf<List<TLine>>(emptyList()) }
    var aliveLines by remember { mutableStateOf<List<TLine>>(emptyList()) }
    var error by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }
    var progress by remember { mutableStateOf(0) }

    ToolScaffold("PORT SCANNER", "فحص منافذ TCP لأي هدف — بدون روت", onBack) { pad ->
        Column(
            Modifier.padding(pad).padding(16.dp).verticalScroll(rememberScrollState())
        ) {
            TermField(target, { target = it }, "عنوان IP أو نطاق …")
            Spacer(Modifier.height(8.dp))
            Row {
                ActionButton("فحص المنافذ", Icons.Filled.NetworkCheck, enabled = target.isNotBlank() && !busy) {
                    busy = true; error = null; lines = emptyList(); progress = 0
                    scope.launch {
                        val host = target.trim()
                        val (total, hits) = portScan(host) { d, t -> progress = d }
                        busy = false
                        val out = ArrayList<TLine>()
                        out.add(tHead("SPECTRE PORTSCAN — $host"))
                        out.add(tDim("Nmap-style TCP Connect • ${total} منفذاً شائعاً"))
                        if (hits.isEmpty()) {
                            out.add(tWarn("لم تُرصد منافذ مفتوحة في القائمة"))
                            out.add(tInfo("قد يكون الهدف مغلقاً أو المحاولة محجوبة"))
                        } else {
                            out.add(tOk("${hits.size} منفذ مفتوح"))
                            hits.forEach { h ->
                                out.add(
                                    if (h.banner.isNotBlank())
                                        TLine("${h.port}  open  ${h.service}  ::  ${h.banner.take(60)}", 0)
                                    else
                                        TLine("${h.port}  open  ${h.service}", 0)
                                )
                            }
                        }
                        out.add(tDim("اكتمل الفحص"))
                        lines = out
                    }
                }
            }
            if (busy) {
                Spacer(Modifier.height(12.dp))
                ScanningBar("جارٍ فحص المنفذ $progress / ${COMMON_PORTS.size}")
            }
            error?.let { Spacer(Modifier.height(10.dp)); Text(it, color = Red, fontSize = 13.sp) }

            if (lines.isNotEmpty()) {
                Spacer(Modifier.height(14.dp))
                TermCard("نتيجة الفحص", lines)
            }
            Spacer(Modifier.height(18.dp))
            ActionButton("فحص الأجهزة الحية في النطاق", Icons.Filled.Devices, enabled = target.isNotBlank() && !busy) {
                busy = true; error = null; aliveLines = emptyList()
                scope.launch {
                    val base = target.trim().substringBeforeLast('.')
                    val out = ArrayList<TLine>()
                    out.add(tHead("ALIVE HOST SWEEP — $base.1-254"))
                    val alive = aliveScan(base)
                    busy = false
                    if (alive.isEmpty()) {
                        out.add(tWarn("لا أجهزة مستجيبة في النطاق"))
                    } else {
                        out.add(tOk("${alive.size} جهاز مستجيب"))
                        alive.forEach { out.add(TLine("$it", 0)) }
                    }
                    out.add(tDim("فحص عبر منافذ 22/80/443/8080"))
                    aliveLines = out
                }
            }
            if (aliveLines.isNotEmpty() && !busy) {
                Spacer(Modifier.height(12.dp))
                TermCard("الأجهزة النشطة", aliveLines, color = Cyan)
            }
            Spacer(Modifier.height(24.dp))
        }
    }
}

// ════════════════════════════════════════════════════════════════
//  تعداد النطاقات الفرعية — Subdomain Enumeration
// ════════════════════════════════════════════════════════════════
@Composable
fun SubEnumScreen(onBack: () -> Unit) {
    val scope = rememberCoroutineScope()
    var domain by remember { mutableStateOf("") }
    var lines by remember { mutableStateOf<List<TLine>>(emptyList()) }
    var error by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }

    ToolScaffold("SUB ENUMERATION", "استخراج النطاقات الفرعية من سجل الشهادات (crt.sh)", onBack) { pad ->
        Column(
            Modifier.padding(pad).padding(16.dp).verticalScroll(rememberScrollState())
        ) {
            TermField(domain, { domain = it }, "example.com")
            Spacer(Modifier.height(10.dp))
            ActionButton("تعداد النطاقات", Icons.Filled.TravelExplore, enabled = domain.isNotBlank() && !busy) {
                busy = true; error = null; lines = emptyList()
                scope.launch {
                    val r = enumSubdomains(domain)
                    busy = false
                    r.fold(
                        onSuccess = { subs ->
                            val out = ArrayList<TLine>()
                            out.add(tHead("SUB ENUM — ${domain.trim()}"))
                            out.add(tDim("المصدر: سجل الشفافية crt.sh"))
                            if (subs.isEmpty()) {
                                out.add(tWarn("لا نطاقات فرعية مسجلة"))
                            } else {
                                val alive = subs.count { it.alive }
                                out.add(tOk("${subs.size} نطاقاً فرعياً (${alive} نشط)"))
                                subs.forEach { s ->
                                    out.add(
                                        if (s.alive) TLine("${s.name}  [A]", 0)
                                        else TLine("${s.name}", 3)
                                    )
                                }
                            }
                            lines = out
                        },
                        onFailure = { error = it.message }
                    )
                }
            }
            if (busy) { Spacer(Modifier.height(12.dp)); ScanningBar("جارٍ سحب السجل والتحقق") }
            error?.let { Spacer(Modifier.height(10.dp)); Text(it, color = Red, fontSize = 13.sp) }
            if (lines.isNotEmpty()) {
                Spacer(Modifier.height(14.dp))
                TermCard("قائمة النطاقات", lines, color = Cyan)
            }
            Spacer(Modifier.height(24.dp))
        }
    }
}
