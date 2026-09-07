package com.spectre.osint.core

import android.content.Context
import com.spectre.osint.R
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONArray

// ════════════════════════════════════════════════════════════════
//  كتالوج التسريبات — فهرس عام مرفق (يُحدَّث مع كل إصدار)
//  + كتالوج حي من HIBP + تحليل قطاع سجلات السارقين
//  ملاحظة مسؤولة: هذا الملف بيانات عامة فقط — لا يعرض بيانات ضحايا
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

private val hibpClassAr = mapOf(
    "Email addresses" to "عناوين البريد",
    "Passwords" to "كلمات المرور",
    "Usernames" to "أسماء المستخدمين",
    "Phone numbers" to "أرقام الهواتف",
    "IP addresses" to "عناوين IP",
    "Names" to "الأسماء",
    "Dates of birth" to "تواريخ الميلاد",
    "Addresses" to "العناوين",
    "Physical addresses" to "العناوين",
    "Credit cards" to "بطاقات الدفع",
    "Partial credit card data" to "بيانات بطاقات جزئية",
    "Bank account numbers" to "أرقام حسابات بنكية",
    "Government IDs" to "وثائق حكومية",
    "Password hashes" to "تجزئة كلمات المرور",
    "Social media profiles" to "حسابات التواصل",
    "Security questions" to "أسئلة الأمان",
    "Job titles" to "المسميات الوظيفية",
    "Website activity" to "نشاط المواقع",
    "Device information" to "معلومات الجهاز",
    "Browser user agents" to "متصفحات",
    "Geographic locations" to "المواقع الجغرافية"
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

/** كتالوج HIBP الحي — يلزم مفتاح المستخدم؛ بيانات عامة (اسم/نطاق/تاريخ/عدد) فقط */
suspend fun fetchLiveCatalog(key: String): List<CatBreach> = withContext(Dispatchers.IO) {
    if (key.isBlank()) return@withContext emptyList()
    val r = Net.get(
        "https://haveibeenpwned.com/api/v3/breaches?truncateResponse=true",
        headers = mapOf("hibp-api-key" to key.trim()),
        connectTimeoutMs = 20000,
        readTimeoutMs = 30000
    )
    if (r.code != 200 || r.body == null) return@withContext emptyList()
    try {
        val arr = JSONArray(r.body)
        (0 until arr.length()).map { i ->
            val o = arr.getJSONObject(i)
            val dc = o.optJSONArray("DataClasses") ?: JSONArray()
            val classes = (0 until dc.length()).map { k -> hibpClassAr[dc.optString(k)] ?: "بيانات أخرى" }.distinct()
            val name = o.optString("Name")
            CatBreach(
                name,
                o.optString("Domain"),
                o.optString("BreachDate"),
                o.optLong("PwnCount"),
                classes,
                name.contains("stealer", true) || name.contains("txtbase", true) ||
                    name.contains("combo", true) || o.optBoolean("IsMalware")
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

/** يبحث في الفهرس عن تسريبات مرتبطة بنطاق */
fun searchDomainBreaches(catalog: List<CatBreach>, input: String): List<CatBreach> {
    val dq = normalizeDomain(input)
    if (dq.isBlank() || !dq.contains(".")) return emptyList()
    return catalog.filter { b ->
        val bd = b.domain.trim().lowercase()
        bd == dq || bd.endsWith(".$dq") || dq.endsWith(".$bd")
    }.sortedByDescending { it.count }
}

// ── تحليل القطاع: أي المواقع المستهدفة من سجلات السارقين ────────
private val casinoTokens = listOf(
    "playojo", "bovada", "bet365", "betway", "unibet", "1xbet", "leovegas",
    "betano", "mostbet", "22bet", "melbet", "parimatch", "williamhill", "betfair",
    "betsson", "ggbet", "vbet", "draftkings", "fanduel", "pinnacle", "bitstarz",
    "888casino", "pokerstars", "casino", "poker", "gambl", "slot", "jackpot",
    "wager", "betting", "bingo", "betvictor", "coral", "ladbrokes", "mansion"
)
private val cryptoTokens = listOf(
    "binance", "coinbase", "kraken", "bitfinex", "bybit", "okx", "crypto",
    "bitcoin", "blockchain", "exodus", "metamask", "trustwallet", "ledger", "gate"
)
private val financeTokens = listOf(
    "payday", "forex", "trading", "bank", "invest", "wallet", "paypal", "revolut"
)

fun sectorRisk(host: String): String? {
    val h = host.lowercase()
    val out = ArrayList<String>()
    if (casinoTokens.any { h.contains(it) }) out.add("كازينو ومراهنات")
    if (cryptoTokens.any { h.contains(it) }) out.add("عملات رقمية")
    if (financeTokens.any { h.contains(it) }) out.add("تمويل ودفع إلكتروني")
    if (out.isEmpty()) return null
    return out.joinToString(" · ")
}

/** صياغة عدد مضغوطة احترافية */
fun formatCount(c: Long): String = when {
    c >= 1_000_000_000 -> "%.1f مليار".format(c / 1e9).replace(".0", "")
    c >= 1_000_000 -> "%.1f مليون".format(c / 1e6).replace(".0", "")
    c >= 1_000 -> "%.1f ألف".format(c / 1e3).replace(".0", "")
    else -> c.toString()
}
