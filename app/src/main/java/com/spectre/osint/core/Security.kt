package com.spectre.osint.core

import android.content.Context
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.net.Uri
import androidx.exifinterface.media.ExifInterface
import com.google.mlkit.vision.barcode.Barcode
import com.google.mlkit.vision.barcode.BarcodeScannerOptions
import com.google.mlkit.vision.barcode.BarcodeScanning
import com.google.mlkit.vision.common.InputImage
import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.resume
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.net.URL
import java.net.URLEncoder
import java.security.MessageDigest
import kotlin.math.log2
import kotlin.math.pow

// ════════════════════════════════════════════════════════════════
//  محلل كلمات المرور — قوة + تسريبات (HIBP k-anonymity، بدون مفاتيح)
// ════════════════════════════════════════════════════════════════
data class PwReport(
    val len: Int, val classes: List<String>, val bits: Double,
    val offline: String, val online: String,
    val hibpCount: Long, val score: Int // 0 ضعيفة | 1 متوسطة | 2 قوية
)

fun sha1Hex(s: String): String =
    MessageDigest.getInstance("SHA-1").digest(s.toByteArray()).joinToString("") { "%02x".format(it) }.uppercase()

fun humanizeSecs(s: Double): String = when {
    s < 1 -> "فوراً"
    s < 60 -> "${s.toInt()} ثانية"
    s < 3600 -> "${(s / 60).toInt()} دقيقة"
    s < 86400 -> "${(s / 3600).toInt()} ساعة"
    s < 31536000 -> "${(s / 86400).toInt()} يوم"
    s < 3.1536e10 -> "${(s / 31536000).toInt()} سنة"
    s < 3.1536e13 -> "${(s / 3.1536e10).toInt()} ألف سنة"
    s < 3.1536e16 -> "${(s / 3.1536e13).toInt()} مليون سنة"
    s < 3.1536e19 -> "${(s / 3.1536e16).toInt()} مليار سنة"
    else -> "أطول من عمر الكون"
}

fun analyzePassword(pw: String): PwReport {
    val lower = pw.any { it in 'a'..'z' }
    val upper = pw.any { it in 'A'..'Z' }
    val digit = pw.any { it in '0'..'9' }
    val sym = pw.any { !it.isLetterOrDigit() }
    var pool = 0
    if (lower) pool += 26
    if (upper) pool += 26
    if (digit) pool += 10
    if (sym) pool += 32
    val classes = buildList {
        if (lower) add("أحرف صغيرة")
        if (upper) add("أحرف كبيرة")
        if (digit) add("أرقام")
        if (sym) add("رموز")
    }
    val bits = if (pw.isEmpty()) 0.0 else pw.length * log2(pool.toDouble())
    val guesses = 2.0.pow(bits)
    val score = when { bits < 40 -> 0; bits < 60 -> 1; else -> 2 }
    return PwReport(
        pw.length, classes, bits,
        humanizeSecs(guesses / 1e10), humanizeSecs(guesses / 100.0),
        0, score
    )
}

suspend fun hibpPasswordCount(pw: String): Long = withContext(Dispatchers.IO) {
    try {
        val hash = sha1Hex(pw)
        val prefix = hash.take(5)
        val suffix = hash.drop(5)
        val r = Net.get("https://api.pwnedpasswords.com/range/$prefix", headers = mapOf("Add-Padding" to "true"))
        if (r.code != 200 || r.body == null) return@withContext 0L
        r.body.lineSequence().mapNotNull { line ->
            val parts = line.trim().split(":")
            if (parts.size == 2 && parts[0].equals(suffix, ignoreCase = true)) parts[1].toLongOrNull() else null
        }.firstOrNull() ?: 0L
    } catch (e: Exception) { 0L }
}

// ════════════════════════════════════════════════════════════════
//  كاشف التسريبات — HIBP v3 (يتطلب مفتاحاً مجانياً)
// ════════════════════════════════════════════════════════════════
data class BreachInfo(
    val title: String, val domain: String, val date: String,
    val count: Long, val classes: List<String>
)

sealed class BreachResult {
    data class Ok(val items: List<BreachInfo>) : BreachResult()
    object NoKey : BreachResult()
    object BadKey : BreachResult()
    data class Err(val msg: String) : BreachResult()
}

private val breachClassAr = mapOf(
    "Email addresses" to "عناوين البريد", "Passwords" to "كلمات المرور",
    "Usernames" to "أسماء المستخدمين", "Phone numbers" to "أرقام الهواتف",
    "IP addresses" to "عناوين IP", "Names" to "الأسماء",
    "Dates of birth" to "تواريخ الميلاد", "Addresses" to "العناوين",
    "Credit cards" to "بطاقات الائتمان", "Password hashes" to "تجزئة كلمات المرور",
    "Social media profiles" to "حسابات التواصل",
)

suspend fun checkBreaches(account: String, key: String): BreachResult = withContext(Dispatchers.IO) {
    if (key.isBlank()) return@withContext BreachResult.NoKey
    val r = Net.get(
        "https://api.haveibeenpwned.com/api/v3/breachedaccount/${URLEncoder.encode(account.trim(), "UTF-8")}?truncateResponse=false",
        headers = mapOf("hibp-api-key" to key.trim())
    )
    when {
        r.code == 401 -> BreachResult.BadKey
        r.code == 404 -> BreachResult.Ok(emptyList())
        r.code == 200 && r.body != null -> try {
            val arr = JSONArray(r.body)
            val items = (0 until arr.length()).map { i ->
                val o = arr.getJSONObject(i)
                val dc = o.optJSONArray("DataClasses") ?: JSONArray()
                BreachInfo(
                    o.optString("Title"), o.optString("Domain"), o.optString("BreachDate"),
                    o.optLong("PwnCount"),
                    (0 until dc.length()).map { k -> breachClassAr[dc.optString(k)] ?: dc.optString(k) }
                )
            }.sortedByDescending { it.count }
            BreachResult.Ok(items)
        } catch (e: Exception) { BreachResult.Err("تعذر تحليل النتائج") }
        else -> BreachResult.Err("فشل الاتصال بالخدمة (${r.code})")
    }
}

// ════════════════════════════════════════════════════════════════
//  محلل الصور — EXIF + عكس الإحداثيات إلى موقع
// ════════════════════════════════════════════════════════════════
data class ExifData(
    val width: String, val height: String, val make: String, val model: String,
    val software: String, val dateTaken: String,
    val lat: Double?, val lon: Double?,
    val gpsRawLat: String, val gpsRawLon: String,
    val altitude: String, val iso: String, val exposure: String, val fNumber: String, val focal: String
) {
    val hasGps: Boolean get() = lat != null && lon != null
}

fun readExif(context: Context, uri: Uri): ExifData? = try {
    val stream = context.contentResolver.openInputStream(uri) ?: return null
    val exif = ExifInterface(stream)
    val ll = FloatArray(2)
    val hasGps = exif.getLatLong(ll)
    val alt = try {
        val a = exif.getAttributeDouble(ExifInterface.TAG_GPS_ALTITUDE, -1.0)
        if (a < 0) "—" else {
            val ref = exif.getAttribute(ExifInterface.TAG_GPS_ALTITUDE_REF)
            "%.1f متر%s".format(a, if (ref == "1") " (تحت سطح البحر)" else "")
        }
    } catch (e: Exception) { "—" }
    ExifData(
        exif.getAttribute(ExifInterface.TAG_IMAGE_WIDTH) ?: "—",
        exif.getAttribute(ExifInterface.TAG_IMAGE_LENGTH) ?: "—",
        exif.getAttribute(ExifInterface.TAG_MAKE) ?: "—",
        exif.getAttribute(ExifInterface.TAG_MODEL) ?: "—",
        exif.getAttribute(ExifInterface.TAG_SOFTWARE) ?: "—",
        exif.getAttribute(ExifInterface.TAG_DATETIME_ORIGINAL) ?: "—",
        if (hasGps) ll[0].toDouble() else null,
        if (hasGps) ll[1].toDouble() else null,
        exif.getAttribute(ExifInterface.TAG_GPS_LATITUDE) ?: "—",
        exif.getAttribute(ExifInterface.TAG_GPS_LONGITUDE) ?: "—",
        alt,
        exif.getAttribute(ExifInterface.TAG_PHOTOGRAPHIC_SENSITIVITY) ?: "—",
        exif.getAttribute(ExifInterface.TAG_EXPOSURE_TIME) ?: "—",
        exif.getAttribute(ExifInterface.TAG_F_NUMBER) ?: "—",
        exif.getAttribute(ExifInterface.TAG_FOCAL_LENGTH) ?: "—"
    )
} catch (e: Exception) { null }

suspend fun reverseGeocode(lat: Double, lon: Double): String? = withContext(Dispatchers.IO) {
    val r = Net.get("https://nominatim.openstreetmap.org/reverse?format=jsonv2&lat=$lat&lon=$lon&accept-language=ar")
    if (r.code != 200 || r.body == null) null
    else try { JSONObject(r.body).optString("display_name").ifBlank { null } } catch (e: Exception) { null }
}

fun decodeScaled(context: Context, uri: Uri, maxDim: Int = 1280): Bitmap? = try {
    val opts = BitmapFactory.Options().apply { inJustDecodeBounds = true }
    context.contentResolver.openInputStream(uri)?.use { BitmapFactory.decodeStream(it, null, opts) }
    var sample = 1
    while (opts.outWidth / sample > maxDim || opts.outHeight / sample > maxDim) sample *= 2
    val opts2 = BitmapFactory.Options().apply { inSampleSize = sample }
    context.contentResolver.openInputStream(uri)?.use { BitmapFactory.decodeStream(it, null, opts2) }
} catch (e: Exception) { null }

// ════════════════════════════════════════════════════════════════
//  QR — توليد (ZXing) + فك (ML Kit)
// ════════════════════════════════════════════════════════════════
fun generateQr(text: String, size: Int = 768): Bitmap? = try {
    val hints = mapOf(EncodeHintType.CHARACTER_SET to "UTF-8", EncodeHintType.MARGIN to 1)
    val matrix = QRCodeWriter().encode(text, BarcodeFormat.QR_CODE, size, size, hints)
    val bmp = Bitmap.createBitmap(size, size, Bitmap.Config.ARGB_8888)
    for (x in 0 until size) for (y in 0 until size) {
        bmp.setPixel(x, y, if (matrix.get(x, y)) 0xFF000000.toInt() else 0xFFFFFFFF.toInt())
    }
    bmp
} catch (e: Exception) { null }

suspend fun decodeQr(context: Context, uri: Uri): List<String> = withContext(Dispatchers.IO) {
    val bmp = decodeScaled(context, uri, 1280) ?: return@withContext emptyList()
    val scanner = BarcodeScanning.getClient(
        BarcodeScannerOptions.Builder().setBarcodeFormats(Barcode.FORMAT_ALL_FORMATS).build()
    )
    suspendCancellableCoroutine { cont ->
        scanner.process(InputImage.fromBitmap(bmp, 0))
            .addOnSuccessListener { bars ->
                cont.resume(bars.map { it.rawValue ?: "" }.filter { it.isNotBlank() })
            }
            .addOnFailureListener { cont.resume(emptyList()) }
    }
}

// ════════════════════════════════════════════════════════════════
//  فاحص الروابط — سلسلة التحويل + الوجهة + المخاطر
// ════════════════════════════════════════════════════════════════
data class LinkReport(
    val chain: List<String>, val finalUrl: String, val host: String,
    val ip: String?, val geo: IpInfo?, val whois: WhoisData?,
    val flags: List<String>, val verdict: String, val verdictScore: Int // 0 خطر | 1 تحذير | 2 سليم
)

private val shorteners = listOf(
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "cutt.ly", "rb.gy", "tiny.cc",
    "is.gd", "buff.ly", "rebrand.ly", "s.id", "bl.ink", "lnkd.in", "shorturl.at", "t.ly"
)
private val riskyTlds = listOf(
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "work", "click", "link", "zip", "mov",
    "stream", "download", "racing", "loan", "win", "bid", "review", "party", "date",
    "gdn", "science", "fit", "rest", "cyou", "cam", "mobi", "info"
)

suspend fun analyzeLink(url: String): Result<LinkReport> = withContext(Dispatchers.IO) {
    try {
        val chain = Net.redirectChain(url.trim())
        val finalRaw = chain.lastOrNull()?.substringBefore("  →")?.trim() ?: url
        val parsed = try { URL(finalRaw) } catch (e: Exception) { URL("https://" + finalRaw) }
        val host = parsed.host.lowercase().removePrefix("www.")
        val flags = ArrayList<String>()
        var verdict = "لا توجد مؤشرات خطر واضحة"
        var score = 2

        if (host.matches(Regex("^\\d{1,3}(\\.\\d{1,3}){3}$"))) {
            flags.add("الرابط يشير مباشرة إلى عنوان IP — لا يظهر النطاق الحقيقي")
            if (score > 1) { verdict = "تحذير — رابط يخفي وجهته"; score = 1 }
        }
        if (shorteners.any { host.contains(it) }) {
            flags.add("خدمة اختصار روابط — الوجهة الحقيقية مخفية خلف الرابط")
            if (score > 1) { verdict = "تحذير — رابط مختصر"; score = 1 }
        }
        if (host.contains("xn--")) {
            flags.add("تشفير Punycode (xn--) — طريقة شائعة في نطاقات التصيد")
            if (score > 0) { verdict = "خطر محتمل"; score = 0 }
        }
        val tld = host.substringAfterLast('.', "")
        if (riskyTlds.contains(tld)) {
            flags.add("نطاق عالي الخطورة (.$tld)")
            if (score > 0) { verdict = "تحذير"; score = 1 }
        }
        if (chain.size > 1) flags.add("سلسلة تحتوي ${chain.size - 1} إعادة توجيه")
        if (!parsed.protocol.equals("https", true)) flags.add("الاتصال غير مشفر (HTTP)" + " — البيانات معرضة للاعتراض")
        else flags.add("الاتصال مشفر (HTTPS)")

        val dnsRec = Dns.query(host, 1)
        val ip = dnsRec.firstOrNull()?.data?.trim()
        val geo = ip?.let { runCatching { ipLookup(it).getOrNull() }.getOrNull() }
        val who = runCatching { whois(host).getOrNull() }.getOrNull()

        if (geo?.hosting == true && score == 2) {
            flags.add("الاستضافة على خوادم سحابية — قد يكون تصيداً مقنعاً")
            if (score > 1) { verdict = "تحذير"; score = 1 }
        }
        Result.success(LinkReport(chain, finalRaw, host, ip, geo, who, flags, verdict, score))
    } catch (e: Exception) {
        Result.failure(Exception("رابط غير صالح — أدخل رابطاً كاملاً يبدأ بـ http"))
    }
}
