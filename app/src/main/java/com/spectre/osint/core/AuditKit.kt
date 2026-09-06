package com.spectre.osint.core

import android.content.Context
import android.os.Build
import android.provider.Settings
import java.io.File
import java.security.MessageDigest

// ════════════════════════════════════════════════════════════════
//  فحص أمان الجهاز — حالة الحماية العامة
// ════════════════════════════════════════════════════════════════
data class AuditCheck(val title: String, val value: String, val good: Boolean, val actionable: Boolean)

fun auditDevice(context: Context): Pair<List<AuditCheck>, Int> {
    val cr = context.contentResolver
    val list = ArrayList<AuditCheck>()

    // الجذر
    val suPaths = listOf(
        "/system/xbin/su", "/system/bin/su", "/sbin/su", "/system/app/Superuser.apk",
        "/system/app/Magisk.apk", "/data/adb/magisk", "/system/bin/magisk"
    )
    val rooted = suPaths.any { File(it).exists() }
    list.add(AuditCheck("حالة الجذر (Root)", if (rooted) "تم رصد SU/Magisk" else "غير موجود", !rooted, true))

    // تصحيح أخطاء ADB
    val adb = try { Settings.Global.getInt(cr, "adb_enabled", 0) == 1 } catch (e: Exception) { false }
    list.add(AuditCheck("تصحيح أخطاء USB", if (adb) "مفعّل — كشف كامل للجهاز عبر ADB" else "معطّل", !adb, true))

    // وضع المطور
    val dev = try { Settings.Global.getInt(cr, "development_settings_enabled", 0) == 1 } catch (e: Exception) { false }
    list.add(AuditCheck("وضع المطور", if (dev) "مفعّل" else "معطّل", !dev, false))

    // الموقع الوهمي
    val mock = try { Settings.Secure.getInt(cr, "mock_location", 0) == 1 } catch (e: Exception) { false }
    list.add(AuditCheck("الموقع الوهمي", if (mock) "مفعّل — يمكن تزوير موقعك" else "معطّل", !mock, true))

    // قفل الشاشة
    val km = context.getSystemService(Context.KEYGUARD_SERVICE) as android.app.KeyguardManager
    val secure = try { km.isDeviceSecure } catch (e: Exception) { false }
    list.add(AuditCheck("قفل الشاشة", if (secure) "مفعّل (PIN/بصمة/نمط)" else "بدون قفل — جهازك مكشوف", secure, true))

    // التشفير
    val enc = try {
        val dpm = context.getSystemService(Context.DEVICE_POLICY_SERVICE) as android.app.admin.DevicePolicyManager
        dpm.isDeviceEncryptionActive
    } catch (e: Exception) { null }
    list.add(AuditCheck("تشفير التخزين", when (enc) {
        true -> "مفعّل"
        false -> "غير مفعّل — البيانات متاحة بالقراءة المباشرة"
        null -> "لا يمكن التحقق"
    }, enc != false, enc != null))

    // مصادر غير معروفة
    try {
        val pm = context.packageManager
        @Suppress("DEPRECATION")
        val unknown = pm.canRequestPackageInstalls()
        list.add(AuditCheck(
            "التثبيت من مصادر خارجية",
            if (unknown) "مسموح — خطر تثبيت تطبيقات ملوثة" else "مقيد",
            !unknown, true
        ))
    } catch (e: Exception) {
        list.add(AuditCheck("التثبيت من مصادر خارجية", "لا يمكن التحقق", true, false))
    }

    // رقعة الأمان
    val patch = try { Build.VERSION.SECURITY_PATCH } catch (e: Exception) { "غير معروف" }
    list.add(AuditCheck("رقعة الأمان", patch, patch != "غير معروف", false))

    // الإصدار
    list.add(AuditCheck("إصدار النظام", "Android ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT})", true, false))

    val actionable = list.filter { it.actionable }
    val score = if (actionable.isEmpty()) 100 else (actionable.count { it.good } * 100) / actionable.size
    return list to score
}

// ════════════════════════════════════════════════════════════════
//  مختبر الترميز — Hash / Base64 / Hex / URL / XOR
// ════════════════════════════════════════════════════════════════
object Crypter {
    fun hexOf(b: ByteArray) = b.joinToString("") { "%02x".format(it) }

    fun hash(algo: String, s: String): String = try {
        hexOf(MessageDigest.getInstance(algo).digest(s.toByteArray(Charsets.UTF_8)))
    } catch (e: Exception) { "" }

    fun md5(s: String) = hash("MD5", s)
    fun sha1(s: String) = hash("SHA-1", s)
    fun sha256(s: String) = hash("SHA-256", s)
    fun sha512(s: String) = hash("SHA-512", s)

    fun b64e(s: String) = android.util.Base64.encodeToString(s.toByteArray(Charsets.UTF_8), android.util.Base64.NO_WRAP)
    fun b64d(s: String): String = try {
        String(android.util.Base64.decode(s.trim(), android.util.Base64.DEFAULT), Charsets.UTF_8)
    } catch (e: Exception) { "قيمة Base64 غير صالحة" }

    fun hexE(s: String) = hexOf(s.toByteArray(Charsets.UTF_8))
    fun hexD(s: String): String = try {
        val clean = s.trim().replace(" ", "")
        String(clean.chunked(2).map { it.toInt(16).toByte() }.toByteArray(), Charsets.UTF_8)
    } catch (e: Exception) { "قيمة Hex غير صالحة" }

    fun urlE(s: String) = java.net.URLEncoder.encode(s, "UTF-8")
    fun urlD(s: String): String = try {
        java.net.URLDecoder.decode(s.trim(), "UTF-8")
    } catch (e: Exception) { "قيمة غير صالحة" }

    fun rot13(s: String) = s.map { c ->
        when {
            c in 'a'..'z' -> 'a' + (c - 'a' + 13) % 26
            c in 'A'..'Z' -> 'A' + (c - 'A' + 13) % 26
            else -> c
        }
    }.joinToString("")

    fun xor(s: String, key: String): String {
        if (key.isEmpty()) return "أدخل مفتاحاً"
        val k = key.toByteArray(Charsets.UTF_8)
        val out = s.toByteArray(Charsets.UTF_8).mapIndexed { i, b -> (b.toInt() xor k[i % k.size].toInt()).toByte() }.toByteArray()
        return try { String(out, Charsets.UTF_8) } catch (e: Exception) { hexOf(out) }
    }

    fun generatePassword(len: Int = 18): String {
        val chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#%&*"
        return (1..len).map { chars.random() }.joinToString("")
    }
}
