package com.spectre.osint.core

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.withContext
import java.net.InetSocketAddress
import java.net.Socket

// ════════════════════════════════════════════════════════════════
//  ماسح المنافذ + فحص الأجهزة الحية — TCP Connect (بدون روت)
// ════════════════════════════════════════════════════════════════

val COMMON_PORTS = listOf(
    21, 22, 23, 25, 53, 80, 110, 111, 123, 135, 139, 143, 161, 389, 443, 445,
    465, 514, 587, 631, 636, 993, 995, 1080, 1194, 1433, 1521, 1723, 1883, 2049,
    2181, 2375, 3000, 3128, 3268, 3306, 3389, 4369, 4443, 5000, 5001, 5432,
    5555, 5672, 5900, 5984, 6000, 6379, 6443, 7001, 7070, 8000, 8008, 8009,
    8080, 8081, 8088, 8090, 8161, 8443, 8500, 8888, 9000, 9001, 9042, 9090,
    9100, 9200, 9300, 9443, 10000, 11211, 15672, 16379, 27017, 28017, 50000
)

val SERVICE_NAMES = mapOf(
    21 to "FTP", 22 to "SSH", 23 to "Telnet", 25 to "SMTP", 53 to "DNS",
    80 to "HTTP", 110 to "POP3", 111 to "RPC", 123 to "NTP", 135 to "MSRPC",
    139 to "NetBIOS", 143 to "IMAP", 161 to "SNMP", 389 to "LDAP", 443 to "HTTPS",
    445 to "SMB", 465 to "SMTPS", 514 to "Syslog", 587 to "SMTP", 631 to "IPP",
    636 to "LDAPS", 993 to "IMAPS", 995 to "POP3S", 1080 to "SOCKS", 1194 to "OpenVPN",
    1433 to "MSSQL", 1521 to "Oracle", 1723 to "PPTP", 1883 to "MQTT", 2049 to "NFS",
    2181 to "ZooKeeper", 2375 to "Docker", 3000 to "Grafana", 3128 to "Squid",
    3306 to "MySQL", 3389 to "RDP", 4443 to "HTTPS-Alt", 5000 to "HTTP-Alt",
    5432 to "PostgreSQL", 5555 to "ADB", 5672 to "AMQP", 5900 to "VNC", 5984 to "CouchDB",
    6379 to "Redis", 6443 to "K8s API", 7001 to "WebLogic", 8080 to "HTTP-Proxy",
    8443 to "HTTPS-Alt", 8888 to "HTTP-Alt", 9000 to "SonarQube", 9042 to "Cassandra",
    9090 to "Prometheus", 9200 to "Elasticsearch", 9300 to "ES-Transport",
    10000 to "Webmin", 11211 to "Memcached", 15672 to "RabbitMQ", 27017 to "MongoDB",
    28017 to "MongoDB-Http", 50000 to "SAP"
)

data class PortHit(val port: Int, val service: String, val banner: String)

private fun grabBanner(host: String, port: Int, timeoutMs: Int): String = try {
    Socket().use { s ->
        s.connect(InetSocketAddress(host, port), timeoutMs)
        s.soTimeout = 900
        val probe = if (port == 80 || port == 8080 || port == 8000 || port == 8888 || port == 5000 || port == 3000 || port == 8443)
            "HEAD / HTTP/1.0\r\nHost: $host\r\n\r\n".toByteArray()
        else ByteArray(0)
        if (probe.isNotEmpty()) s.getOutputStream().write(probe)
        val buf = ByteArray(220)
        val n = try { s.getInputStream().read(buf) } catch (e: Exception) { -1 }
        if (n > 0) {
            String(buf, 0, n).replace(Regex("[\\x00-\\x08\\x0B\\x0C\\x0E-\\x1F]"), " ").trim().take(160)
        } else ""
    }
} catch (e: Exception) { "" }

/** فحص الأجهزة الحية في نطاق — مثل 192.168.1.1-254 */
suspend fun aliveScan(
    base: String,
    concurrency: Int = 40,
    portProbe: List<Int> = listOf(22, 80, 443, 8080),
    timeoutMs: Int = 700
): List<String> = withContext(Dispatchers.IO) {
    val alive = java.util.Collections.synchronizedList(ArrayList<String>())
    coroutineScope {
        val sem = Semaphore(concurrency)
        (1..254).map { i ->
            async(Dispatchers.IO) {
                sem.withPermit {
                    val host = "$base.$i"
                    var up = false
                    for (p in portProbe) {
                        if (up) break
                        up = try {
                            Socket().use { s ->
                                s.connect(InetSocketAddress(host, p), timeoutMs)
                                true
                            }
                        } catch (e: Exception) { false }
                    }
                    if (up) alive.add(host)
                }
            }
        }.awaitAll()
    }
    alive.toList().sortedBy { it.substringAfterLast('.').toInt() }
}

/** فحص منافذ استهداف واحد */
suspend fun portScan(
    host: String,
    ports: List<Int> = COMMON_PORTS,
    concurrency: Int = 30,
    timeoutMs: Int = 1200,
    onProgress: (done: Int, total: Int) -> Unit = { _, _ -> }
): Pair<Int, List<PortHit>> = withContext(Dispatchers.IO) {
    val hits = java.util.Collections.synchronizedList(ArrayList<PortHit>())
    val counter = java.util.concurrent.atomic.AtomicInteger(0)
    coroutineScope {
        val sem = Semaphore(concurrency)
        ports.map { p ->
            async(Dispatchers.IO) {
                sem.withPermit {
                    val open = try {
                        Socket().use { s ->
                            s.connect(InetSocketAddress(host, p), timeoutMs)
                            true
                        }
                    } catch (e: Exception) { false }
                    if (open) {
                        val banner = if (p in listOf(21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 8080, 8443, 3306, 3389, 5900, 6379))
                            grabBanner(host, p, timeoutMs) else ""
                        hits.add(PortHit(p, SERVICE_NAMES[p] ?: "غير معروف", banner))
                    }
                    onProgress(counter.incrementAndGet(), ports.size)
                }
            }
        }.awaitAll()
    }
    ports.size to hits.toList().sortedBy { it.port }
}
