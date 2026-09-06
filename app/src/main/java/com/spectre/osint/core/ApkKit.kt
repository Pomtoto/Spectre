package com.spectre.osint.core

import android.content.Context
import android.net.Uri
import java.io.File
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.zip.ZipFile
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

// ════════════════════════════════════════════════════════════════
//  محلل ملفات APK — يقرأ الحزمة مباشرة: الشهادة، الصلاحيات، المتتبعات
// ════════════════════════════════════════════════════════════════
data class ApkReport(
    val size: Long,
    val entries: Int,
    val dexCount: Int,
    val libs: List<String>,
    val permissions: List<String>,
    val trackers: List<String>,
    val certSubject: String, val certIssuer: String,
    val certFrom: String, val certTo: String, val certAlgo: String,
    val signedV1: Boolean,
    val totalUncompressed: Long
)

val DANGEROUS_PERMS = listOf(
    "SEND_SMS", "RECEIVE_SMS", "READ_SMS", "CALL_PHONE", "READ_CONTACTS",
    "WRITE_CONTACTS", "READ_CALL_LOG", "WRITE_CALL_LOG", "RECORD_AUDIO",
    "CAMERA", "ACCESS_FINE_LOCATION", "ACCESS_BACKGROUND_LOCATION",
    "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE", "QUERY_ALL_PACKAGES",
    "BIND_ACCESSIBILITY_SERVICE", "PACKAGE_USAGE_STATS", "SYSTEM_ALERT_WINDOW"
)

private val TRACKER_DOMAINS = listOf(
    "google-analytics", "firebase", "app-measurement", "admob", "doubleclick",
    "adjust.com", "branch.io", "amplitude", "mixpanel", "appsflyer", "facebook.com",
    "unity3d", "kochava", "tapjoy", "ironsource", "chartboost", "vungle",
    "applovin", "crashlytics", "sentry.io", "bugsnag", "onesignal", "fabric.io",
    "superawesome", "mopub", "inmobi", "startapp", "yandex.ru", "scoreloop",
    "tapresearch", "flurry", "matomo", "segment.io"
)

suspend fun analyzeApk(context: Context, uri: Uri): Result<ApkReport> = withContext(Dispatchers.IO) {
    try {
        val tmp = File(context.cacheDir, "spectre_${System.currentTimeMillis()}.apk")
        try {
            context.contentResolver.openInputStream(uri)?.use { ins ->
                tmp.outputStream().use { outs -> ins.copyTo(outs) }
            } ?: return@withContext Result.failure(Exception("تعذر قراءة الملف"))
        } catch (e: Exception) {
            return@withContext Result.failure(Exception("تعذر قراءة الملف"))
        }
        val size = tmp.length()
        ZipFile(tmp).use { zip ->
            val entries = zip.entries().toList()
            val dexCount = entries.count { it.name.startsWith("classes") && it.name.endsWith(".dex") }
            val libs = entries.filter { it.name.startsWith("lib/") }
                .map { it.name.split("/").getOrElse(1) { "?" } }.distinct().sorted()
            val totalUnc = entries.sumOf { it.size }

            // الشهادة
            val certEntry = entries.firstOrNull {
                it.name.uppercase().matches(Regex("META-INF/.*\\.(RSA|DSA|EC)$"))
            }
            var cert: X509Certificate? = null
            certEntry?.let { e ->
                try {
                    zip.getInputStream(e).use { ins ->
                        val cf = CertificateFactory.getInstance("X.509")
                        cert = cf.generateCertificates(ins).toList().firstOrNull() as? X509Certificate
                    }
                } catch (_: Exception) {}
            }

            // بيانات الديكس
            val dexParts = entries.filter { it.name.endsWith(".dex") }.take(4).mapNotNull { e ->
                try { zip.getInputStream(e).use { it.readBytes() } } catch (_: Exception) { null }
            }
            val perms = LinkedHashSet<String>()
            val trackers = LinkedHashSet<String>()
            for (d in dexParts) {
                val chunk = String(d, Charsets.ISO_8859_1)
                Regex("android\\.permission\\.[A-Z_]+").findAll(chunk).forEach { m ->
                    perms.add(m.value.removePrefix("android.permission."))
                }
                TRACKER_DOMAINS.forEach { t ->
                    if (chunk.contains(t, ignoreCase = true)) trackers.add(t)
                }
            }

            Result.success(
                ApkReport(
                    size = size,
                    entries = entries.size,
                    dexCount = dexCount,
                    libs = libs,
                    permissions = perms.sorted(),
                    trackers = trackers.sorted(),
                    certSubject = cert?.subjectX500Principal?.name?.let { cnOf(it) } ?: "غير موقعة (V1)",
                    certIssuer = cert?.issuerX500Principal?.name?.let { cnOf(it) } ?: "—",
                    certFrom = cert?.notBefore?.toString()?.take(10) ?: "—",
                    certTo = cert?.notAfter?.toString()?.take(10) ?: "—",
                    certAlgo = cert?.sigAlgName ?: "—",
                    signedV1 = certEntry != null,
                    totalUncompressed = totalUnc
                )
            )
        }.also { tmp.delete() }
    } catch (e: Exception) {
        Result.failure(Exception("الملف ليس حزمة APK صالحة"))
    }
}

private fun cnOf(dn: String): String =
    dn.split(",").firstOrNull { it.trim().startsWith("CN=") }?.trim()?.removePrefix("CN=") ?: dn.take(60)

// ════════════════════════════════════════════════════════════════
//  فاحص الملفات العام — التوقيع السحري + البصمة + النصوص
// ════════════════════════════════════════════════════════════════
data class FileReport(
    val size: Long,
    val detected: String,
    val matchesExt: Boolean,
    val md5: String, val sha1: String, val sha256: String,
    val strings: List<String>
)

fun snuffType(bytes: ByteArray): String = when {
    bytes.size >= 8 && bytes[0] == 0x89.toByte() && bytes[1] == 0x50.toByte() && bytes[2] == 0x4E.toByte() -> "PNG — صورة"
    bytes.size >= 3 && bytes[0] == 0xFF.toByte() && bytes[1] == 0xD8.toByte() -> "JPEG — صورة"
    bytes.size >= 8 && bytes[0] == 0x47.toByte() && bytes[1] == 0x49.toByte() && bytes[2] == 0x46.toByte() -> "GIF — صورة"
    bytes.size >= 5 && String(bytes, 0, 5) == "%PDF-" -> "PDF — مستند"
    bytes.size >= 4 && String(bytes, 0, 4) == "PK\u0003\u0004" -> "ZIP/APK — حزمة مضغوطة"
    bytes.size >= 4 && bytes[0] == 0x7F.toByte() && bytes[1] == 0x45.toByte() && bytes[2] == 0x4C.toByte() -> "ELF — ملف قابل للتنفيذ"
    bytes.size >= 2 && bytes[0] == 0x4D.toByte() && bytes[1] == 0x5A.toByte() -> "PE — ملف Windows"
    bytes.size >= 4 && bytes[0] == 0x1F.toByte() && bytes[1] == 0x8B.toByte() -> "GZIP — أرشيف مضغوط"
    bytes.size >= 4 && String(bytes, 0, 4) == "Rar!" -> "RAR — أرشيف مضغوط"
    bytes.size >= 6 && String(bytes, 0, 6) == "SQLite" -> "SQLite — قاعدة بيانات"
    bytes.size >= 2 && bytes[0] == 0x42.toByte() && bytes[1] == 0x5A.toByte() -> "BZIP2 — أرشيف مضغوط"
    bytes.size >= 4 && bytes[0] == 0x25.toByte() && bytes[1] == 0x21.toByte() -> "الأرشيف الكامل"
    bytes.size >= 3 && bytes[0] == 0xEF.toByte() && bytes[1] == 0xBB.toByte() && bytes[2] == 0xBF.toByte() -> "نص UTF-8"
    else -> "نص / غير معروف"
}

private fun hexOf(b: ByteArray) = b.joinToString("") { "%02x".format(it) }

suspend fun analyzeFile(context: Context, uri: Uri, name: String?): Result<FileReport> =
    withContext(Dispatchers.IO) {
        try {
            val bytes = context.contentResolver.openInputStream(uri)?.use { it.readBytes() }
                ?: return@withContext Result.failure(Exception("تعذر قراءة الملف"))
            val ext = name?.substringAfterLast('.', "")?.lowercase() ?: ""
            val detected = snuffType(bytes)
            val matches = when (detected) {
                "PNG — صورة" -> ext == "png"
                "JPEG — صورة" -> ext in listOf("jpg", "jpeg")
                "GIF — صورة" -> ext == "gif"
                "PDF — مستند" -> ext == "pdf"
                else -> true
            }
            val strings = ArrayList<String>()
            val sb = StringBuilder()
            for (b in bytes.take(2_000_000)) {
                val c = b.toInt().toChar()
                if (c.code in 32..126) {
                    sb.append(c)
                    if (sb.length > 4096) { sb.setLength(0) }
                } else {
                    if (sb.length >= 6) strings.add(sb.toString())
                    sb.setLength(0)
                }
            }
            Result.success(
                FileReport(
                    size = bytes.size.toLong(),
                    detected = detected,
                    matchesExt = matches,
                    md5 = hexOf(MessageDigest.getInstance("MD5").digest(bytes)),
                    sha1 = hexOf(MessageDigest.getInstance("SHA-1").digest(bytes)),
                    sha256 = hexOf(MessageDigest.getInstance("SHA-256").digest(bytes)),
                    strings = strings.distinct().take(25).sortedBy { it.length }
                )
            )
        } catch (e: Exception) {
            Result.failure(Exception("تعذر تحليل الملف"))
        }
    }
