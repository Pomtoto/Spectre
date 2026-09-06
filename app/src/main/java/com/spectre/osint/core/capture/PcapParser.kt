package com.spectre.osint.core.capture

import kotlin.math.min

// ════════════════════════════════════════════════════════════════
//  محلل ملفات التقاط PCAP — هل يتفكك مثل tshark؟ نعم، على الجهاز.
//  يدعم: Ethernet / Raw-IP / Loopback / Linux SLL
//  يستخرج: TCP/UDP, HTTP, DNS, SNI/TLS, تدفقات الاتصالات، أعلى المتحدثين
// ════════════════════════════════════════════════════════════════

data class Flow(
    val key: String,
    val srcIp: String, val srcPort: Int,
    val dstIp: String, val dstPort: Int,
    val proto: String,
    var packets: Int = 0,
    var bytes: Long = 0,
    var httpMethod: String? = null,
    var httpHost: String? = null,
    var httpPath: String? = null,
    var httpStatus: String? = null,
    var dnsName: String? = null,
    var dnsType: String? = null,
    var sni: String? = null
) {
    val service: String get() = SERVICE_MAP[dstPort] ?: if (dstPort == srcPort) "" else ""
}

val SERVICE_MAP = mapOf(
    20 to "FTP-Data", 21 to "FTP", 22 to "SSH", 23 to "Telnet", 25 to "SMTP",
    53 to "DNS", 80 to "HTTP", 110 to "POP3", 143 to "IMAP", 443 to "HTTPS",
    445 to "SMB", 465 to "SMTPS", 587 to "SMTP", 993 to "IMAPS", 995 to "POP3S",
    1080 to "SOCKS", 1433 to "MSSQL", 1521 to "Oracle", 1723 to "PPTP",
    3306 to "MySQL", 3389 to "RDP", 5432 to "PostgreSQL", 5900 to "VNC",
    6379 to "Redis", 8080 to "HTTP-Alt", 8443 to "HTTPS-Alt", 8888 to "HTTP-Alt",
    9090 to "Prometheus", 9200 to "Elasticsearch", 27017 to "MongoDB"
)

data class PcapStats(
    val packets: Int,
    val bytes: Long,
    val durationMs: Long,
    val linkType: String,
    val protoCount: Map<String, Int>,
    val flows: List<Flow>,
    val dnsNames: List<String>,
    val httpRequests: List<String>,
    val snis: List<String>,
    val topTalkers: List<Pair<String, Long>>,
    val errors: List<String>
)

private const val MAX_PACKETS = 250_000
private const val MAX_FLOWS = 400

fun parsePcap(fileBytes: ByteArray): Result<PcapStats> {
    return try {
        val r = PcapReader(fileBytes)
        val stats = r.parse()
        Result.success(stats)
    } catch (e: Exception) {
        Result.failure(Exception("ملف غير صالح أو تالف: ${e.message?.take(80)}"))
    }
}

private class PcapReader(private val b: ByteArray) {

    private var pos = 0
    private var little = true
    private var linkType = 0
    private var snaplen = 65535

    private val flows = LinkedHashMap<String, Flow>()
    private val dnsNames = ArrayList<String>()
    private val httpReq = ArrayList<String>()
    private val snis = ArrayList<String>()
    private val protoCount = HashMap<String, Int>()
    private val talkers = HashMap<String, Long>()
    private val errors = ArrayList<String>()
    private var totalBytes = 0L
    private var firstTs = 0L
    private var lastTs = 0L

    fun parse(): PcapStats {
        if (b.size < 24) throw Exception("رأس الملف ناقص")
        // اكتشاف نهاية البايتات
        little = when {
            b[0] == 0xD4.toByte() && b[1] == 0xC3.toByte() -> true
            b[0] == 0xA1.toByte() && b[1] == 0xB2.toByte() -> false
            b[0] == 0x4D.toByte() && b[1] == 0x3C.toByte() -> true  // nanosec LE
            b[0] == 0xA1.toByte() && b[1] == 0xA1.toByte() -> false // nanosec BE (4D 3C B2 A1 actually)
            else -> throw Exception("توقيع غير معروف")
        }
        // nanosec BE هو 4D 3C B2 A1 — نعالجه
        if (b[0] == 0x4D.toByte() && b[1] == 0x3C.toByte() && b[2] == 0xB2.toByte() && b[3] == 0xA1.toByte()) {
            little = false
        }
        val major = u16(4); val minor = u16(6)
        snaplen = u32(16).toInt().coerceIn(64, 16_777_216)
        linkType = u32(20).toInt()
        pos = 24
        var count = 0
        while (pos + 16 <= b.size && count < MAX_PACKETS) {
            val tsSec = u32(pos)
            val tsFrac = u32(pos + 4)
            val incl = u32(pos + 8).toInt().coerceIn(0, snaplen)
            val orig = u32(pos + 12).toInt()
            pos += 16
            if (pos + incl > b.size) { errors.add("سجل مبتور عند البايت ${b.size - pos} — تقطعت القراءة"); break }
            val tsMs = tsSec * 1000L + tsFrac / 1000L
            if (firstTs == 0L) firstTs = tsMs
            lastTs = tsMs
            try { parsePacket(b, pos, incl) } catch (_: Exception) {}
            pos += incl
            count++
        }
        if (count >= MAX_PACKETS) errors.add("اقتصر التفكيك على ${MAX_PACKETS.toString()} حزمة")
        val fl = flows.values.toList().sortedByDescending { it.bytes }.take(MAX_FLOWS)
        return PcapStats(
            count, totalBytes, (lastTs - firstTs).coerceAtLeast(0),
            linkName(linkType), protoCount, fl,
            dnsNames.distinct().take(80), httpReq.distinct().take(120),
            snis.distinct().take(60),
            talkers.entries.sortedByDescending { it.value }.take(15).map { it.key to it.value },
            errors
        )
    }

    // ── أدوات القراءة ──
    private fun u16(o: Int) = if (little)
        (b[o].toInt() and 0xFF) or ((b[o + 1].toInt() and 0xFF) shl 8)
    else ((b[o].toInt() and 0xFF) shl 8) or (b[o + 1].toInt() and 0xFF)

    private fun u32(o: Int): Long {
        if (little) {
            return (b[o].toLong() and 0xFF) or ((b[o + 1].toLong() and 0xFF) shl 8) or
                    ((b[o + 2].toLong() and 0xFF) shl 16) or ((b[o + 3].toLong() and 0xFF) shl 24)
        }
        return ((b[o].toLong() and 0xFF) shl 24) or ((b[o + 1].toLong() and 0xFF) shl 16) or
                ((b[o + 2].toLong() and 0xFF) shl 8) or (b[o + 3].toLong() and 0xFF)
    }

    private fun linkName(lt: Int) = when (lt) {
        1 -> "Ethernet"
        101, 229 -> "Raw IP"
        0, 24 -> "Loopback/Null"
        113, 276 -> "Linux SLL/SLL2"
        else -> "Linktype $lt"
    }

    private fun payloadStart(): Int {
        return when (linkType) {
            1 -> 14                       // Ethernet
            101, 229 -> 0                 // Raw IP
            0 -> if (b.size > pos + 4 && b[pos + 4].toInt() ushr 4 == 4) { pos += 4; 4 } else 4
            113 -> 16                     // SLL
            276 -> 20                     // SLL2
            else -> -1
        }
    }

    // ── تفكيك الحزمة ──
    private fun parsePacket(p: ByteArray, off: Int, len: Int) {
        var o = off
        var l = len
        if (linkType == 1) {
            if (l < 14) return
            val etype = u16(o + 12)
            o += 14; l -= 14
            // 802.1Q
            if (etype == 0x8100 || etype == 0x88A8) {
                if (l < 4) return
                val vt = u16(o + 2)
                o += 4; l -= 4
                if (vt == 0x0800) parseIp4(p, o, l) else if (vt == 0x86DD) parseIp6(p, o, l)
                return
            }
            when (etype) {
                0x0800 -> parseIp4(p, o, l)
                0x86DD -> parseIp6(p, o, l)
                0x0806 -> parseArp(p, o, l)
                else -> { protoCount["غير معروف"] = (protoCount["غير معروف"] ?: 0) + 1 }
            }
            return
        }
        if (linkType == 0) {
            o += 4; l -= 4
            if (l < 0) return
            val v = p[o].toInt() ushr 4
            if (v == 4) parseIp4(p, o, l) else if (v == 6) parseIp6(p, o, l)
            return
        }
        if (linkType == 113 || linkType == 276) { o += payloadStart(); l -= payloadStart(); if (l <= 0) return }
        if (linkType == 101 || linkType == 229) { /* raw */ }
        val v = if (l > 0) p[o].toInt() ushr 4 else 0
        if (v == 4) parseIp4(p, o, l) else if (v == 6) parseIp6(p, o, l)
    }

    private fun parseArp(p: ByteArray, off: Int, len: Int) {
        if (len < 28) return
        protoCount["ARP"] = (protoCount["ARP"] ?: 0) + 1
        val spa = byteIp(p, off + 14)
        val tpa = byteIp(p, off + 24)
        talkers[spa] = (talkers[spa] ?: 0) + 1
        talkers[tpa] = (talkers[tpa] ?: 0) + 1
    }

    private fun parseIp4(p: ByteArray, off: Int, len: Int) {
        if (len < 20) return
        val ihl = (p[off].toInt() and 0xF) * 4
        if (ihl < 20 || len < ihl) return
        val total = u16(off + 2)
        val proto = p[off + 9].toInt() and 0xFF
        val frag = u16(off + 6)
        if ((frag and 0x1FFF) != 0) return // شظايا — نتجاوزها
        val src = byteIp(p, off + 12)
        val dst = byteIp(p, off + 16)
        val payload = off + ihl
        val payLen = min(total - ihl, len - ihl).coerceAtLeast(0)
        totalBytes += len
        when (proto) {
            6 -> parseTcp(p, payload, payLen, src, dst)
            17 -> parseUdp(p, payload, payLen, src, dst)
            1 -> protoCount["ICMP"] = (protoCount["ICMP"] ?: 0) + 1
            2 -> protoCount["IGMP"] = (protoCount["IGMP"] ?: 0) + 1
            else -> protoCount["IP/$proto"] = (protoCount["IP/$proto"] ?: 0) + 1
        }
    }

    private fun parseIp6(p: ByteArray, off: Int, len: Int) {
        if (len < 40) return
        val nh = p[off + 6].toInt() and 0xFF
        val src = ip6Str(p, off + 8)
        val dst = ip6Str(p, off + 24)
        var hdr = nh
        var o = off + 40
        var l = len - 40
        var guard = 0
        while (hdr in listOf(0, 43, 44, 60, 51) && guard < 4 && l >= 8) {
            val next = p[o].toInt() and 0xFF
            if (hdr == 44) { o += 8; l -= 8 } // fragment
            else { val ext = ((p[o + 1].toInt() and 0xFF) + 1) * 8; o += ext; l -= ext }
            hdr = next
            guard++
        }
        totalBytes += len
        when (hdr) {
            6 -> parseTcp(p, o, l, src, dst)
            17 -> parseUdp(p, o, l, src, dst)
            58 -> protoCount["ICMPv6"] = (protoCount["ICMPv6"] ?: 0) + 1
            else -> protoCount["IP6/$hdr"] = (protoCount["IP6/$hdr"] ?: 0) + 1
        }
    }

    private fun parseTcp(p: ByteArray, off: Int, len: Int, src: String, dst: String) {
        if (len < 20) return
        val sp = u16(off); val dp = u16(off + 2)
        val hdrLen = ((p[off + 12].toInt() and 0xF0) shr 4) * 4
        if (hdrLen < 20 || len < hdrLen) return
        protoCount["TCP"] = (protoCount["TCP"] ?: 0) + 1
        val payload = off + hdrLen
        val payLen = len - hdrLen
        val flow = flowFor(src, sp, dst, dp, "TCP")
        flow.packets++; flow.bytes += payLen
        talkers[src] = (talkers[src] ?: 0) + payLen
        talkers[dst] = (talkers[dst] ?: 0) + payLen
        if (payLen > 0) {
            analyzeTcpPayload(p, payload, payLen, flow, sp, dp)
        }
    }

    private fun parseUdp(p: ByteArray, off: Int, len: Int, src: String, dst: String) {
        if (len < 8) return
        val sp = u16(off); val dp = u16(off + 2)
        protoCount["UDP"] = (protoCount["UDP"] ?: 0) + 1
        val flow = flowFor(src, sp, dst, dp, "UDP")
        flow.packets++; flow.bytes += (len - 8).coerceAtLeast(0)
        talkers[src] = (talkers[src] ?: 0) + ((len - 8).coerceAtLeast(0))
        talkers[dst] = (talkers[dst] ?: 0) + ((len - 8).coerceAtLeast(0))
        if ((sp == 53 || dp == 53) && len > 12) parseDns(p, off + 8, len - 8, flow)
    }

    // ── تدفق ثنائي الاتجاه ──
    private fun flowFor(a: String, pa: Int, b: String, pb: Int, proto: String): Flow {
        val s1: String; val p1: Int; val s2: String; val p2: Int
        if (a < b) { s1 = a; p1 = pa; s2 = b; p2 = pb }
        else if (a == b) {
            if (pa <= pb) { s1 = a; p1 = pa; s2 = b; p2 = pb }
            else { s1 = a; p1 = pb; s2 = b; p2 = pa }
        } else { s1 = b; p1 = pb; s2 = a; p2 = pa }
        val key = "$s1:$p1⇄$s2:$p2/$proto"
        return flows.getOrPut(key) { Flow(key, s1, p1, s2, p2, proto) }
    }

    private fun analyzeTcpPayload(p: ByteArray, off: Int, len: Int, f: Flow, sp: Int, dp: Int) {
        // HTTP
        if (dp == 80 || dp == 8080 || dp == 8000 || dp == 8888 || sp == 80 || sp == 8080) {
            val head = ascii(p, off, min(len, 900))
            if (f.httpMethod == null && (head.startsWith("GET ") || head.startsWith("POST ") || head.startsWith("HEAD ") ||
                        head.startsWith("PUT ") || head.startsWith("OPTIONS ") || head.startsWith("DELETE ") ||
                        head.startsWith("PATCH ") || head.startsWith("CONNECT "))
            ) {
                val m = head.substringBefore(" ")
                val path = head.substringAfter(" ").substringBefore(" ")
                val host = Regex("(?i)Host:\\s*([^\\r\\n]+)").find(head)?.groupValues?.get(1)?.trim()
                f.httpMethod = m; f.httpPath = path.take(120); f.httpHost = host
                httpReq.add("$m ${host ?: ""}$path")
            }
            if (f.httpStatus == null && head.startsWith("HTTP/1.")) {
                f.httpStatus = head.substringBefore("\r\n").take(80)
            }
        }
        // TLS SNI
        if (len >= 5 && (p[off].toInt() and 0xFF) == 0x16 && (p[off + 1].toInt() and 0xFF) == 0x03 && f.sni == null) {
            val name = parseSni(p, off, len)
            if (name != null) { f.sni = name; snis.add(name) }
        }
    }

    private fun parseSni(p: ByteArray, off: Int, len: Int): String? {
        return try {
            if (len < 43) return null
            // client hello: record(5)+version(2)+random(32)+sidLen...
            var o = off + 5 + 2 + 32
            val sidLen = p[o].toInt() and 0xFF; o += 1 + sidLen
            val csLen = u16(o); o += 2 + csLen
            val compLen = p[o].toInt() and 0xFF; o += 1 + compLen
            if (o + 2 > off + len) return null
            val extTotal = u16(o); o += 2
            val extEnd = min(o + extTotal, off + len)
            while (o + 4 <= extEnd) {
                val type = u16(o); val eLen = u16(o + 2); o += 4
                if (type == 0x0000 && eLen >= 5 && o + eLen <= extEnd) {
                    // SNI: listLen(2) type(1)=0 nameLen(2) name
                    val l2 = u16(o)
                    var oo = o + 2
                    val nEnd = min(oo + l2, o + eLen)
                    while (oo + 3 <= nEnd) {
                        val nt = p[oo].toInt() and 0xFF
                        val nl = u16(oo + 1)
                        oo += 3
                        if (nt == 0 && nl > 0 && oo + nl <= nEnd) {
                            return ascii(p, oo, nl)
                        }
                        oo += nl
                    }
                }
                o += eLen
            }
            null
        } catch (e: Exception) { null }
    }

    private fun parseDns(p: ByteArray, off: Int, len: Int, f: Flow) {
        return try {
            if (len < 12) return
            val qd = u16At(p, off + 4)
            if (qd < 1 || qd > 60) return
            var o = off + 12
            val name = StringBuilder()
            var guard = 0
            while (guard < 20) {
                val l = p[o].toInt() and 0xFF
                if (l == 0) { o++; break }
                if (l > 63 || o + 1 + l > off + len) return
                if (name.isNotEmpty()) name.append('.')
                name.append(ascii(p, o + 1, l))
                o += 1 + l
                guard++
            }
            if (o + 4 > off + len) return
            val t = u16At(p, o)
            val tName = when (t) {
                1 -> "A"; 2 -> "NS"; 5 -> "CNAME"; 6 -> "SOA"; 15 -> "MX"; 16 -> "TXT"
                28 -> "AAAA"; 33 -> "SRV"; 43 -> "DS"; 48 -> "DNSKEY"; 255 -> "ANY"
                else -> "TYPE$t"
            }
            val qname = name.toString()
            if (qname.isNotBlank()) {
                if (f.dnsName == null) { f.dnsName = qname; f.dnsType = tName }
                dnsNames.add("$qname ($tName)")
            }
            Unit
        } catch (e: Exception) {}
    }

    // ── أدوات فرعية ──
    private fun byteIp(p: ByteArray, o: Int) =
        "${p[o].toInt() and 0xFF}.${p[o + 1].toInt() and 0xFF}.${p[o + 2].toInt() and 0xFF}.${p[o + 3].toInt() and 0xFF}"

    private fun ip6Str(p: ByteArray, o: Int): String {
        val sb = StringBuilder()
        for (i in 0 until 8) {
            if (i > 0) sb.append(':')
            sb.append(String.format("%04x", u16At(p, o + i * 2)))
        }
        return sb.toString()
    }

    private fun u16At(p: ByteArray, o: Int) =
        ((p[o].toInt() and 0xFF) shl 8) or (p[o + 1].toInt() and 0xFF)

    private fun ascii(p: ByteArray, o: Int, l: Int): String {
        val sb = StringBuilder(l)
        var end = min(o + l, p.size)
        for (i in o until end) {
            val c = p[i].toInt() and 0xFF
            sb.append(if (c in 32..126) c.toChar() else ' ')
        }
        return sb.toString()
    }
}
