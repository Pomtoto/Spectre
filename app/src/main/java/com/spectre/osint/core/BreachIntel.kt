package com.spectre.osint.core

import com.spectre.osint.R

import android.content.Context
import org.json.JSONArray

// ════════════════════════════════════════════════════════════════
//  كتالوج التسريبات — فهرس عام مرفق (يُحدَّث مع كل إصدار)
//  + استعلام حي عبر HIBP للحسابات وكلمات المرور
// ════════════════════════════════════════════════════════════════

data class CatBreach(
    val name: String,
    val domain: String,
    val date: String,        // yyyy-MM-dd
    val count: Long,
    val classes: List<String>,
    val stealer: Boolean
)

private val classAr = mapOf(
    "email" to "عناوين البريد",
    "pass" to "كلمات المرور",
    "name" to "الأسماء",
    "phone" to "أرقام الهواتف",
    "user" to "أسماء المستخدمين",
    "ip" to "عناوين IP",
    "addr" to "العناوين",
    "dob" to "تواريخ الميلاد",
    "card" to "بطاقات الدفع",
    "ssn" to "أرقام الهوية",
    "msg" to "رسائل خاصة",
    "other" to "بيانات أخرى"
)

fun loadCatalog(context: Context): List<CatBreach> {
    return try {
        val raw = context.resources.openRawResource(R.raw.breach_catalog)
        val text = raw.bufferedReader().use { it.readText() }
        val arr = JSONArray(text)
        (0 until arr.length()).map { i ->
            val o = arr.getJSONObject(i)
            val classes = o.optString("k").split(",").map { it.trim() }.filter { it.isNotEmpty() }
                .map { classAr[it] ?: it }
            CatBreach(
                o.optString("n"),
                o.optString("d"),
                o.optString("y"),
                o.optLong("c"),
                classes,
                o.optInt("s", 0) == 1
            )
        }
    } catch (e: Exception) { emptyList() }
}

/** يبسّط اسم النطاق من أي صيغة إدخال */
fun normalizeDomain(input: String): String {
    var d = input.trim().lowercase()
    d = d.removePrefix("https://").removePrefix("http://")
    d = d.substringBefore("/").substringBefore(":").substringBefore("?")
    d = d.removePrefix("www.").removePrefix("m.")
    return d.trim()
}

/** يبحث في الكتالوج عن تسريبات مرتبطة بنطاق */
fun searchDomainBreaches(catalog: List<CatBreach>, input: String): List<CatBreach> {
    val dq = normalizeDomain(input)
    if (dq.isBlank() || !dq.contains(".")) return emptyList()
    return catalog.filter { b ->
        val bd = b.domain.trim().lowercase()
        bd == dq || bd.endsWith(".$dq") || dq.endsWith(".$bd")
    }.sortedByDescending { it.count }
}

/** صياغة عدد مضغوطة احترافية */
fun formatCount(c: Long): String = when {
    c >= 1_000_000_000 -> "%.1f مليار".format(c / 1e9).replace(".0", "")
    c >= 1_000_000 -> "%.1f مليون".format(c / 1e6).replace(".0", "")
    c >= 1_000 -> "%.1f ألف".format(c / 1e3).replace(".0", "")
    else -> c.toString()
}
