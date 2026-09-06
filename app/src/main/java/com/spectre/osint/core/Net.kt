package com.spectre.osint.core

import java.net.HttpURLConnection
import java.net.URL

// ════════════════════════════════════════════════════════════════
//  الشبكة
// ════════════════════════════════════════════════════════════════
data class HttpR(val code: Int, val body: String?)

object Net {
    fun get(
        url: String,
        headers: Map<String, String> = emptyMap(),
        connectTimeoutMs: Int = 15000,
        readTimeoutMs: Int = 20000
    ): HttpR {
        val conn = (URL(url).openConnection() as HttpURLConnection).apply {
            requestMethod = "GET"
            connectTimeout = connectTimeoutMs
            readTimeout = readTimeoutMs
            instanceFollowRedirects = true
            setRequestProperty("User-Agent", "Spectre/2.0 (Android; OSINT)")
            setRequestProperty("Accept", "application/json,text/plain,*/*")
            headers.forEach { (k, v) -> setRequestProperty(k, v) }
        }
        return try {
            val code = conn.responseCode
            val stream = if (code in 200..299) conn.inputStream else conn.errorStream
            val body = stream?.bufferedReader()?.use { it.readText() }
            HttpR(code, body)
        } catch (e: Exception) {
            HttpR(-1, null)
        } finally {
            conn.disconnect()
        }
    }

    /** يتبع سلسلة إعادة التوجيه حتى الوجهة النهائية */
    fun redirectChain(url: String, max: Int = 12): List<String> {
        val out = mutableListOf<String>()
        var current = url
        var hops = 0
        while (hops < max) {
            val conn = (URL(current).openConnection() as HttpURLConnection).apply {
                instanceFollowRedirects = false
                connectTimeout = 8000
                readTimeout = 8000
                setRequestProperty("User-Agent", "Spectre/2.0")
                setRequestProperty("Accept", "*/*")
            }
            try {
                val code = conn.responseCode
                val loc = conn.getHeaderField("Location")
                if (code in 300..399 && !loc.isNullOrBlank()) {
                    val next = if (loc.startsWith("http://") || loc.startsWith("https://")) loc
                    else URL(URL(current), loc).toString()
                    out.add("$current  →  [$code]")
                    current = next
                    hops++
                } else {
                    out.add("$current  →  [$code]")
                    return out
                }
            } catch (e: Exception) {
                out.add("$current  ..  تعذر الوصول")
                return out
            } finally {
                conn.disconnect()
            }
        }
        return out
    }
}
