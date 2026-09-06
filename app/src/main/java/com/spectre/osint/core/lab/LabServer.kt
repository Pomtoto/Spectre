package com.spectre.osint.core.lab

import android.content.Context
import java.io.File
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.URLDecoder
import kotlin.concurrent.thread

// ════════════════════════════════════════════════════════════════
//  خادم المختبر — سيرفر HTTP حي على 127.0.0.1 بقاعدة SQLite حقيقية
//  يحتوي ثغرات مقصودة للتدريب فقط (بيئة معزولة على جهازك أنت)
// ════════════════════════════════════════════════════════════════
class LabServer(private val context: Context) {

    @Volatile
    var running = false
        private set
    var port = 0
        private set

    private var serverSocket: ServerSocket? = null
    private var dbFile: File? = null

    /** يستقبل أسطر جلسة المختبر (طلبات + استجابات) */
    var onExchange: ((line: String, kind: Int) -> Unit)? = null

    val baseUrl: String get() = "http://127.0.0.1:$port"
    val secretDir: File get() = File(context.filesDir, "lab_secrets")

    fun start(): Boolean {
        if (running) return true
        return try {
            prepareSecretFiles()
            val ss = ServerSocket(0, 60, InetAddress.getByName("127.0.0.1"))
            serverSocket = ss
            port = ss.localPort
            running = true
            thread(name = "spectre-lab") {
                while (running) {
                    val client = try { ss.accept() } catch (e: Exception) { break }
                    val c = client
                    thread(name = "spectre-req") { handle(c) }
                }
            }
            log("# خادم المختبر يعمل على ${baseUrl}", 5)
            log("# قاعدة SQLite جاهزة — 5 مستخدمين بتجزئة MD5", 4)
            true
        } catch (e: Exception) {
            false
        }
    }

    fun stop() {
        running = false
        try { serverSocket?.close() } catch (_: Exception) {}
        serverSocket = null
        log("# توقف الخادم", 5)
    }

    private fun prepareSecretFiles() {
        val dir = secretDir
        dir.mkdirs()
        File(dir, "secret_router.txt").writeText(
            "راوتر المنزل — كلمة المرور: IranGate2024\n" +
            "[ملاحظة: بيئة تدريب معزولة على جهازك — ليست بيانات حقيقية]"
        )
        File(dir, "api_keys.txt").writeText(
            "API_KEY=demo-71f2-88ab-4c3d\nSECRET=lab-only-9f1e\nX-Deploy-Token: NO-REAL-KEY"
        )
        File(dir, "passwords.txt").writeText(
            "admin:shadow123\nuser1:password123\nali:iraq2020\nsara:kurdistan\nhacker:letmein"
        )
    }

    // ── الاتصال والتحليل ─────────────────────────────────────────
    private fun handle(sock: Socket) {
        sock.use { s ->
            try {
                val reader = s.getInputStream().bufferedReader()
                val requestLine = reader.readLine()?.trim() ?: return
                log("> $requestLine", 4)
                val headers = HashMap<String, String>()
                while (true) {
                    val line = reader.readLine() ?: break
                    if (line.isBlank()) break
                    val i = line.indexOf(':')
                    if (i > 0) headers[line.substring(0, i).trim().lowercase()] = line.substring(i + 1).trim()
                }
                val parts = requestLine.split(" ")
                val method = parts.getOrElse(0) { "" }
                val rawPath = parts.getOrElse(1) { "/" }
                val path = rawPath.substringBefore("?")
                val query = rawPath.substringAfter("?", "")
                val body = if (method.equals("POST", true)) {
                    val len = headers["content-length"]?.toIntOrNull() ?: 0
                    val buf = CharArray(len.coerceAtMost(8192))
                    var read = 0
                    while (read < len && read < buf.size) {
                        val n = reader.read(buf, read, buf.size - read)
                        if (n < 0) break
                        read += n
                    }
                    String(buf, 0, read)
                } else ""

                val qp = parseForm(query)
                val bp = parseForm(body)
                val resp = route(method, path, qp + bp)
                val out = s.getOutputStream()
                val head = "HTTP/1.1 ${resp.code} ${resp.reason}\r\n" +
                        "Content-Type: ${resp.ct}\r\n" +
                        "Content-Length: ${resp.body.toByteArray(Charsets.UTF_8).size}\r\n" +
                        "Server: SpectreLab/3.0\r\n" +
                        "Connection: close\r\n\r\n"
                out.write(head.toByteArray(Charsets.UTF_8))
                out.write(resp.body.toByteArray(Charsets.UTF_8))
                out.flush()
                log("< ${resp.code} ${resp.reason}", if (resp.code == 200) 0 else 1)
                resp.body.lineSequence().take(20).forEach { log("| $it", 3) }
            } catch (e: Exception) {
                log("! خطأ في المعالجة: ${e.message}", 2)
            }
        }
    }

    private fun parseForm(s: String): Map<String, String> {
        if (s.isBlank()) return emptyMap()
        return s.split("&").mapNotNull { kv ->
            val i = kv.indexOf('=')
            if (i < 0) null
            else URLDecoder.decode(kv.substring(0, i), "UTF-8") to URLDecoder.decode(kv.substring(i + 1), "UTF-8")
        }.toMap()
    }

    // ── المسارات ─────────────────────────────────────────────────
    private data class Resp(val code: Int, val reason: String, val ct: String, val body: String)

    private fun html(body: String, code: Int = 200, reason: String = "OK") =
        Resp(code, reason, "text/html; charset=utf-8", body)

    private fun route(method: String, path: String, params: Map<String, String>): Resp = when {
        path == "/" -> html(homePage())
        path == "/login" && method.equals("POST", true) -> login(params["username"] ?: "", params["password"] ?: "")
        path == "/xss" -> html(xssPage(params["msg"] ?: ""))
        path.startsWith("/files/") -> fileServe(URLDecoder.decode(path.removePrefix("/files/"), "UTF-8"))
        path == "/health" -> html("SPECTRE LAB online\n${baseUrl}\n")
        else -> Resp(404, "Not Found", "text/plain; charset=utf-8", "404 — مسار غير موجود")
    }

    private fun homePage(): String =
        "<html><body style='font-family:monospace'>" +
        "<h2>SPECTRE LAB — بوابة التدريب</h2>" +
        "<p>بيئة معزولة على جهازك — حاول اختراقها</p>" +
        "<form method='POST' action='/login'>" +
        "<input name='username' placeholder='username'/>" +
        "<input name='password' type='password' placeholder='password'/>" +
        "<button type='submit'>تسجيل الدخول</button></form>" +
        "<p><a href='/xss?msg=hello'>صفحة المراسلة</a> · <a href='/files/secret_router.txt'>مستندات</a></p>" +
        "</body></html>"

    /** الثغرة: استعلام يدمج المدخلات مباشرة — SQLi حقيقي على SQLite */
    private fun login(u: String, p: String): Resp {
        return try {
            val sql = "SELECT id, username, password_hash, email, role FROM users " +
                    "WHERE username='$u' AND password='$p'"
            log("SQL> $sql", 5)
            // نسخة آمنة للفحص المسبق (سطر مفصول آمن — لا يغير سلوك الثغرة أعلاه)
            val safeSql = "SELECT id, username, password_hash, email, role FROM users " +
                    "WHERE username=? AND password=?"
            val cur = com.spectre.osint.core.lab.LabDb.query(context, sql, safeSql, u, p)
            val rows = ArrayList<List<String>>()
            cur.use { c ->
                val cols = c.columnNames
                while (c.moveToNext()) rows.add(cols.map { c.getString(c.getColumnIndexOrThrow(it)) ?: "NULL" })
            }
            if (rows.isEmpty()) {
                html("<html><body><h2>رفض الدخول</h2><p>بيانات غير صحيحة</p><a href='/'>عودة</a></body></html>", 401, "Unauthorized")
            } else {
                val b = StringBuilder("<html><body><h2>المصادقة ناجحة — جلستك بأمان</h2><table border='1'>")
                rows.forEach { r ->
                    b.append("<tr>")
                    r.forEach { b.append("<td>").append(it).append("</td>") }
                    b.append("</tr>")
                }
                b.append("</table></body></html>")
                html(b.toString())
            }
        } catch (e: Exception) {
            // خطأ يعرض رأي المحرك — أساس أخطاء SQL
            html("<html><body><h2>خطأ في الاستعلام</h2><pre>${e.message}</pre></body></html>", 500, "Internal Error")
        }
    }

    /** الثغرة: انعكاس بدون تنقية — XSS حقيقي */
    private fun xssPage(msg: String): String =
        "<html><body><h2>نظام المراسلة الداخلية</h2>" +
        "<p>رسالة اليوم:</p><div class='msg'>$msg</div>" +
        "<a href='/'>عودة</a></body></html>"

    /** الثغرة: مسار نسبي بدون تحقق — Directory Traversal حقيقي */
    private fun fileServe(rel: String): Resp {
        val f = File(secretDir, rel)
        return try {
            if (f.exists() && f.isFile) {
                Resp(200, "OK", "text/plain; charset=utf-8", f.readText())
            } else {
                Resp(404, "Not Found", "text/plain; charset=utf-8", "Not found: ${f.path}")
            }
        } catch (e: Exception) {
            Resp(500, "Error", "text/plain; charset=utf-8", e.message ?: "?")
        }
    }

    private fun log(line: String, kind: Int) {
        onExchange?.invoke(line, kind)
    }
}
