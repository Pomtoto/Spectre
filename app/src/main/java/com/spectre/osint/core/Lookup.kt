package com.spectre.osint.core

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.net.URLEncoder

// ════════════════════════════════════════════════════════════════
//  DNS — عبر Google DoH (مجاني، بدون مفاتيح)
// ════════════════════════════════════════════════════════════════
object Dns {
    data class Rec(val name: String, val type: String, val ttl: Long, val data: String)

    fun typeName(t: Int) = when (t) {
        1 -> "A"; 2 -> "NS"; 5 -> "CNAME"; 15 -> "MX"; 16 -> "TXT"; 28 -> "AAAA"; 43 -> "DS"
        else -> "TYPE$t"
    }

    suspend fun query(name: String, type: Int = 1): List<Rec> = withContext(Dispatchers.IO) {
        val r = Net.get("https://dns.google/resolve?name=${URLEncoder.encode(name, "UTF-8")}&type=$type")
        if (r.code != 200 || r.body == null) return@withContext emptyList()
        val res = ArrayList<Rec>()
        try {
            val j = JSONObject(r.body)
            val ans = j.optJSONArray("Answer") ?: JSONArray()
            for (i in 0 until ans.length()) {
                val a = ans.getJSONObject(i)
                res.add(Rec(a.optString("name"), typeName(a.optInt("type")), a.optLong("TTL"), a.optString("data")))
            }
        } catch (_: Exception) {}
        res
    }

    suspend fun resolveHost(host: String): String? = query(host, 1).firstOrNull()?.data?.trim()
}

// ════════════════════════════════════════════════════════════════
//  معلومات العناوين — عبر ipwho.is (مجاني، بدون مفاتيح)
// ════════════════════════════════════════════════════════════════
data class IpInfo(
    val ip: String, val type: String, val country: String, val countryCode: String,
    val region: String, val city: String, val postal: String, val lat: Double, val lon: Double,
    val isp: String, val org: String, val asn: String, val timezone: String, val flag: String,
    val vpn: Boolean, val proxy: Boolean, val tor: Boolean, val relay: Boolean, val hosting: Boolean
)

suspend fun ipLookup(query: String): Result<IpInfo> = withContext(Dispatchers.IO) {
    val q = query.trim()
    val target = if (q.matches(Regex("^\\d{1,3}(\\.\\d{1,3}){3}$"))) q else Dns.resolveHost(q)
    if (target == null) return@withContext Result.failure(Exception("تعذر تحويل الاسم إلى عنوان"))
    val r = Net.get("https://ipwho.is/$target")
    if (r.code != 200 || r.body == null) return@withContext Result.failure(Exception("فشل الاتصال بخدمة الاستعلام"))
    try {
        val j = JSONObject(r.body)
        if (!j.optBoolean("success", true)) return@withContext Result.failure(Exception(j.optString("message", "خطأ في الاستعلام")))
        val con = j.optJSONObject("connection") ?: JSONObject()
        val sec = j.optJSONObject("security") ?: JSONObject()
        val tz = j.optJSONObject("timezone") ?: JSONObject()
        val fl = j.optJSONObject("flag") ?: JSONObject()
        Result.success(
            IpInfo(
                j.optString("ip"), j.optString("type"), j.optString("country"), j.optString("country_code"),
                j.optString("region"), j.optString("city"), j.optString("postal"),
                j.optDouble("latitude"), j.optDouble("longitude"),
                con.optString("isp"), con.optString("org"), con.optString("asn"), tz.optString("id"), fl.optString("emoji"),
                sec.optBoolean("vpn"), sec.optBoolean("proxy"), sec.optBoolean("tor"), sec.optBoolean("relay"), sec.optBoolean("hosting")
            )
        )
    } catch (e: Exception) {
        Result.failure(Exception("بيانات غير صالحة: ${e.message}"))
    }
}

// ════════════════════════════════════════════════════════════════
//  سجلات النطاقات — RDAP (مجاني، بدون مفاتيح)
// ════════════════════════════════════════════════════════════════
data class WhoisData(
    val handle: String, val domain: String, val registrar: String, val emails: List<String>,
    val created: String, val updated: String, val expires: String, val status: List<String>,
    val nameservers: List<String>, val dnssec: Boolean
)

suspend fun whois(domain: String): Result<WhoisData> = withContext(Dispatchers.IO) {
    val d = domain.trim().lowercase().removePrefix("www.").substringBefore("/").substringBefore(":")
    if (!d.contains(".")) return@withContext Result.failure(Exception("أدخل نطاقاً صحيحاً مثل example.com"))
    val r = Net.get("https://rdap.org/domain/$d")
    if (r.code != 200 || r.body == null) return@withContext Result.failure(Exception("لا توجد بيانات RDAP لهذا النطاق"))
    try {
        val j = JSONObject(r.body)
        val events = j.optJSONArray("events") ?: JSONArray()
        fun ev(k: String): String {
            for (i in 0 until events.length()) {
                val e = events.getJSONObject(i)
                if (e.optString("eventAction") == k) return e.optString("eventDate").replace("T", " ").take(19)
            }
            return "—"
        }
        val registrar = StringBuilder()
        val emails = ArrayList<String>()
        val ents = j.optJSONArray("entities") ?: JSONArray()
        for (i in 0 until ents.length()) {
            val e = ents.getJSONObject(i)
            val roles = e.optJSONArray("roles")?.toString() ?: ""
            if (roles.contains("registrar") || roles.contains("registrant")) {
                val vc = e.optJSONArray("vcardArray")
                if (vc != null && vc.length() > 1) {
                    val card = vc.optJSONArray(1)
                    for (k in 0 until card.length()) {
                        val row = card.optJSONArray(k)
                        val field = row.optString(0)
                        when (field) {
                            "fn" -> if (registrar.isEmpty()) registrar.append(row.optString(3))
                            "email" -> row.optString(3).split(",").map { it.trim() }.filter { it.contains("@") }.forEach { if (emails.size < 5) emails.add(it) }
                        }
                    }
                }
            }
        }
        val nsArr = j.optJSONArray("nameservers") ?: JSONArray()
        val ns = (0 until nsArr.length()).map { nsArr.getJSONObject(it).optString("ldhName") }
        val stArr = j.optJSONArray("status") ?: JSONArray()
        val st = (0 until stArr.length()).map { stArr.optString(it) }
        Result.success(
            WhoisData(
                j.optString("handle"), j.optString("ldhName"), registrar.toString(), emails,
                ev("registration"), ev("last changed"), ev("expiration"), st, ns,
                j.optJSONObject("secureDNS")?.optBoolean("delegationSigned") == true
            )
        )
    } catch (e: Exception) {
        Result.failure(Exception("تعذر تحليل البيانات"))
    }
}
