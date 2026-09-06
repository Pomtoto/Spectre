package com.spectre.osint.core

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL

// ════════════════════════════════════════════════════════════════
//  تعداد النطاقات الفرعية — سجل شهادات crt.sh (مصدر عام)
// ════════════════════════════════════════════════════════════════
data class SubDomain(val name: String, val alive: Boolean)

suspend fun enumSubdomains(domain: String, verifyLimit: Int = 40): Result<List<SubDomain>> =
    withContext(Dispatchers.IO) {
        val d = domain.trim().lowercase().removePrefix("www.").substringBefore("/").substringBefore(":")
        if (!d.contains(".")) return@withContext Result.failure(Exception("نطاق غير صالح"))
        val r = Net.get(
            "https://crt.sh/?q=%25.$d&output=json",
            connectTimeoutMs = 12000,
            readTimeoutMs = 25000
        )
        if (r.code != 200 || r.body == null) {
            return@withContext Result.failure(Exception("الخدمة غير متاحة حالياً (crt.sh) — أعد المحاولة لاحقاً"))
        }
        try {
            val arr = JSONArray(r.body)
            val names = LinkedHashSet<String>()
            for (i in 0 until arr.length()) {
                val o = arr.optJSONObject(i) ?: continue
                val nv = o.optString("name_value")
                nv.split("\n").forEach { raw ->
                    val n = raw.trim().removePrefix("*.").removePrefix("www.")
                    if (n.isNotBlank() && n.contains(d) && !n.startsWith("*") && !n.startsWith(".")) names.add(n)
                }
            }
            val sorted = names.sorted()
            val verified = java.util.Collections.synchronizedList(ArrayList<SubDomain>())
            val toCheck = sorted.take(verifyLimit)
            coroutineScope {
                val sem = Semaphore(8)
                toCheck.map { n ->
                    async(Dispatchers.IO) {
                        sem.withPermit {
                            val rec = Dns.query(n, 1)
                            verified.add(SubDomain(n, rec.isNotEmpty()))
                        }
                    }
                }.awaitAll()
            }
            val missing = sorted.drop(verifyLimit).map { SubDomain(it, false) }
            Result.success((verified.toList() + missing))
        } catch (e: Exception) {
            Result.failure(Exception("تعذر تحليل سجل الشهادات"))
        }
    }

// ════════════════════════════════════════════════════════════════
//  تحليل الاستجابة HTTP — أمان الرأسيات + البصمة التقنية
// ════════════════════════════════════════════════════════════════
data class HttpReport(
    val status: Int, val finalUrl: String, val server: String,
    val poweredBy: String, val protocol: String, val cipher: String,
    val headers: Map<String, String>,
    val present: List<String>, val missing: List<String>,
    val cookieFlags: List<String>, val score: Int
)

val SECURITY_HEADERS = listOf(
    "content-security-policy" to "CSP",
    "strict-transport-security" to "HSTS",
    "x-frame-options" to "X-Frame-Options",
    "x-content-type-options" to "X-Content-Type-Options",
    "referrer-policy" to "Referrer-Policy",
    "permissions-policy" to "Permissions-Policy",
    "cross-origin-opener-policy" to "COOP"
)

suspend fun httpAnalyze(url: String): Result<HttpReport> = withContext(Dispatchers.IO) {
    try {
        val u = if (url.startsWith("http")) url else "https://$url"
        val conn = (URL(u).openConnection() as HttpURLConnection).apply {
            requestMethod = "GET"
            connectTimeout = 12000
            readTimeout = 10000
            instanceFollowRedirects = true
            setRequestProperty("User-Agent", "Spectre/2.0 (Recon)")
            setRequestProperty("Accept", "text/html,*/*")
        }
        val status = conn.responseCode
        val finalUrl = conn.url.toString()
        val headerMap = HashMap<String, String>()
        conn.headerFields.forEach { (k, v) ->
            if (k != null && v.isNotEmpty()) headerMap[k.lowercase()] = v.joinToString(", ")
        }
        val present = SECURITY_HEADERS.filter { headerMap.containsKey(it.first) }.map { it.second }
        val missing = SECURITY_HEADERS.filterNot { headerMap.containsKey(it.first) }.map { it.second }
        val cookies = conn.headerFields["Set-Cookie"] ?: emptyList()
        val cookieFlags = ArrayList<String>()
        cookies.forEach { c ->
            val parts = c.split(";").map { it.trim().lowercase() }
            val name = c.substringBefore("=").trim()
            cookieFlags.add("$name: " + when {
                parts.contains("httponly") && parts.contains("secure") -> "HttpOnly+Secure"
                parts.contains("httponly") -> "HttpOnly"
                parts.contains("secure") -> "Secure"
                else -> "بدون حماية"
            })
        }
        val score = ((present.size * 100) / SECURITY_HEADERS.size)
        val tls = conn as? javax.net.ssl.HttpsURLConnection
        val protoLabel = if (tls != null) "TLS" else "HTTP"
        val cipher = tls?.cipherSuite?.take(40) ?: "—"
        Result.success(
            HttpReport(
                status, finalUrl,
                headerMap["server"] ?: "—",
                headerMap["x-powered-by"] ?: headerMap["x-aspnet-version"] ?: "—",
                protoLabel,
                cipher,
                headerMap, present, missing, cookieFlags, score
            )
        )
    } catch (e: Exception) {
        Result.failure(Exception("تعذر الاتصال بالوجهة — تحقق من الرابط"))
    }
}
