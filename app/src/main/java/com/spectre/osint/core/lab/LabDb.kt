package com.spectre.osint.core.lab

import android.content.Context
import android.database.Cursor

// ════════════════════════════════════════════════════════════════
//  قاعدة بيانات المختبر — SQLite حقيقية على جهاز المستخدم
// ════════════════════════════════════════════════════════════════
object LabDb {

    @Volatile
    private var db: android.database.sqlite.SQLiteDatabase? = null

    private fun db(context: Context): android.database.sqlite.SQLiteDatabase {
        var d = db
        if (d == null) {
            synchronized(this) {
                d = db
                if (d == null) {
                    d = context.openOrCreateDatabase("spectre_lab.db", Context.MODE_PRIVATE, null)
                    d!!.execSQL(
                        "CREATE TABLE IF NOT EXISTS users(" +
                        "id INTEGER PRIMARY KEY AUTOINCREMENT," +
                        "username TEXT UNIQUE," +
                        "password_hash TEXT," +
                        "email TEXT," +
                        "role TEXT)"
                    )
                    seed(d!!)
                    db = d
                }
            }
        }
        return d!!
    }

    private fun seed(d: android.database.sqlite.SQLiteDatabase) {
        val rows = listOf(
            arrayOf("admin", "shadow123", "admin@spectre.local", "admin"),
            arrayOf("user1", "password123", "user1@mail.local", "user"),
            arrayOf("ali", "iraq2020", "ali@mail.local", "user"),
            arrayOf("sara", "kurdistan", "sara@mail.local", "editor"),
            arrayOf("hacker", "letmein", "hacker@mail.local", "user")
        )
        rows.forEach { r ->
            d.execSQL(
                "INSERT OR IGNORE INTO users(username, password_hash, email, role) VALUES(?,?,?,?)",
                arrayOf(r[0], com.spectre.osint.core.Crypter.md5(r[1]), r[2], r[3])
            )
        }
    }

    /**
     * sql      — الاستعلام الضعيف (المدخلات مدمجة — قابل للحقن)
     * safeSql  — نفس الاستعلام الكامل لكن بمعاملات مرتبطة (للفحص الذاتي فقط)
     */
    fun query(context: Context, sql: String, safeSql: String, u: String, p: String): Cursor {
        val d = db(context)
        // فحص مسبق: إذا كانت القيم الأصلية جديرة بالدخول، نمررها كمعاملات (لا يغلق الثغرة،
        // يضمن فقط أن تجاوز الحماية يبقى داخل حدود بيئة التدريب)
        val safe = d.rawQuery(safeSql, arrayOf(u, p))
        val legit = safe.use { it.moveToFirst() }
        if (legit) return d.rawQuery(safeSql, arrayOf(u, p))
        return d.rawQuery(sql, null)
    }

    fun allUsers(context: Context): List<List<String>> {
        val d = db(context)
        val cur = d.rawQuery("SELECT username, password_hash, role FROM users ORDER BY id", null)
        val rows = ArrayList<List<String>>()
        cur.use { c ->
            while (c.moveToNext()) {
                rows.add(listOf(c.getString(0), c.getString(1), c.getString(2)))
            }
        }
        return rows
    }
}
