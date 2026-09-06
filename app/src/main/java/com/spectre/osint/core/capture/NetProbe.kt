package com.spectre.osint.core.capture

import android.content.Context
import android.net.wifi.WifiManager
import java.io.File
import java.net.Inet4Address
import java.net.NetworkInterface

// ════════════════════════════════════════════════════════════════
//  أدوات الشبكة المحلية — بدون روت
//  الواجهة، البوابة، جدول ARP، نقاط الوصول Wi-Fi
// ════════════════════════════════════════════════════════════════

data class IfaceInfo(val ip: String?, val gateway: String?, val netmask: String?, val dns: String?)

fun localInterfaceIp(): String? {
    return try {
        NetworkInterface.getNetworkInterfaces().toList()
            .firstOrNull { !it.isLoopback && it.isUp && it.name.matches(Regex("wlan|eth|ap|rmnet|ccmni")) }
            ?.inetAddresses?.toList()?.firstOrNull { it is Inet4Address }?.hostAddress
    } catch (e: Exception) { null }
}

fun localNetInfo(context: Context): IfaceInfo {
    var ip = localInterfaceIp()
    var gw: String? = null
    var mask: String? = null
    var dns: String? = null
    // DHCP معلومات من Wireless
    try {
        val wm = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
        val d = wm.dhcpInfo
        if (d.ipAddress != 0) {
            val i = d.ipAddress.toLong() and 0xFFFFFFFFL
            ip = "${(i shr 24) and 0xFF}.${(i shr 16) and 0xFF}.${(i shr 8) and 0xFF}.${i and 0xFF}"
        }
        if (d.gateway != 0) {
            val g = d.gateway.toLong() and 0xFFFFFFFFL
            gw = "${(g shr 24) and 0xFF}.${(g shr 16) and 0xFF}.${(g shr 8) and 0xFF}.${g and 0xFF}"
        }
        if (d.netmask != 0) {
            val m = d.netmask.toLong() and 0xFFFFFFFFL
            mask = "${(m shr 24) and 0xFF}.${(m shr 16) and 0xFF}.${(m shr 8) and 0xFF}.${m and 0xFF}"
        }
        dns = d.dns1?.let {
            val x = d.dns1.toLong() and 0xFFFFFFFFL
            "${(x shr 24) and 0xFF}.${(x shr 16) and 0xFF}.${(x shr 8) and 0xFF}.${x and 0xFF}"
        }
    } catch (_: Exception) {}
    // البوابة من /proc/net/route إن وُجدت
    if (gw == null) {
        try {
            val lines = File("/proc/net/route").readLines().drop(1)
            lines.firstOrNull { it.trim().split(Regex("\\s+")).getOrNull(1)?.toLong(16) == 1L }
                ?.let {
                    val iface = it.trim().split(Regex("\\s+"))[0]
                    val gwHex = it.trim().split(Regex("\\s+"))[2]
                    if (gwHex.length == 8) {
                        gw = listOf(3, 2, 1, 0).joinToString(".") { idx ->
                            gwHex.substring(idx * 2, idx * 2 + 2).toInt(16).toString()
                        }
                    }
                }
        } catch (_: Exception) {}
    }
    return IfaceInfo(ip, gw, mask, dns)
}

// ── ARP ──────────────────────────────────────────────────────────
data class ArpRow(val ip: String, val mac: String, val device: String, val complete: Boolean)

fun readArpTable(): List<ArpRow> {
    return try {
        val rows = ArrayList<ArpRow>()
        File("/proc/net/arp").readLines().drop(1).forEach { line ->
            val p = line.trim().split(Regex("\\s+"))
            if (p.size >= 6) {
                val ip = p[0]
                val flags = p[2].toIntOrNull() ?: 0
                val mac = p[3]
                if (ip.matches(Regex("^\\d{1,3}(\\.\\d{1,3}){3}$")) && mac.matches(Regex("^[0-9A-Fa-f:]{17}$"))) {
                    rows.add(ArpRow(ip, mac.uppercase(), p[5], flags and 0x2 != 0))
                }
            }
        }
        // ترتيب: المستجيبون أولاً ثم بالمحلي
        rows.sortedWith(compareByDescending<ArpRow> { it.complete }.thenBy { it.ip.split(".").last().toIntOrNull() ?: 0 })
    } catch (e: Exception) { emptyList() }
}

// ── مورّد MAC (قائمة تقديرية للمورّدين الشائعين) ───────────────
private val OUI = listOf(
    "000393" to "Apple", "000A27" to "Apple", "000A95" to "Apple", "001B63" to "Apple",
    "001EC2" to "Apple", "002332" to "Apple", "002500" to "Apple", "002608" to "Apple",
    "0026BB" to "Apple", "040CCE" to "Apple", "041E64" to "Apple", "044BED" to "Apple",
    "080069" to "Apple", "0C3E9F" to "Apple", "109ADD" to "Apple", "14109F" to "Apple",
    "3CD92B" to "Apple", "A45E60" to "Apple", "ACBC32" to "Apple", "F01898" to "Apple",
    "001EDF" to "Samsung", "002681" to "Samsung", "0026BE" to "Samsung", "0050F2" to "Samsung",
    "08978D" to "Samsung", "0C71F9" to "Samsung", "F82FA8" to "Samsung", "2846EB" to "Samsung",
    "8C3A77" to "Samsung", "6C5CDB" to "Samsung", "502EC5" to "Samsung", "A469D4" to "Samsung",
    "286C07" to "Xiaomi", "64BC0C" to "Xiaomi", "640980" to "Xiaomi", "784F43" to "Xiaomi",
    "8CBE9A" to "Xiaomi", "F066A0" to "Xiaomi", "C87B5B" to "Xiaomi", "DC4432" to "Xiaomi",
    "00E0FC" to "Huawei", "0025F6" to "Huawei", "48DB50" to "Huawei", "54A2D5" to "Huawei",
    "A4C7F1" to "Huawei", "BC98FF" to "Huawei", "DC0A34" to "Huawei", "E8E0B7" to "Huawei",
    "50C7BF" to "TP-Link", "50C702" to "TP-Link", "F4F26D" to "TP-Link", "60E36B" to "TP-Link",
    "A4B1C1" to "TP-Link", "B0F02B" to "TP-Link", "14CF92" to "TP-Link", "D8DCF7" to "TP-Link",
    "00150B" to "Cisco", "005066" to "Cisco", "000E8B" to "Cisco", "18EF10" to "Cisco",
    "082E5F" to "Cisco", "30F7C5" to "Cisco", "64AE0C" to "Cisco", "10C640" to "Hikvision",
    "44162F" to "Hikvision", "90A9D5" to "Hikvision", "0024E4" to "Hikvision", "B4480A" to "Hikvision",
    "00231D" to "Netgear", "00B049" to "Netgear", "A93A32" to "Netgear", "205654" to "Netgear",
    "9CC3A6" to "Netgear", "DC25F5" to "Netgear", "00C0CA" to "Intel", "001CB0" to "Intel",
    "3C9A47" to "Intel", "545AF4" to "Intel", "E0677A" to "ESP (IoT)", "5C220B" to "ESP (IoT)",
    "8ACB0F" to "ESP (IoT)", "24A4A2" to "ESP (IoT)", "00D0F5" to "Netgear", "0026D4" to "D-Link",
    "783B60" to "D-Link", "58B229" to "D-Link", "AC1F6B" to "D-Link", "F0F5BD" to "D-Link",
    "000C5D" to "Sony", "A0E591" to "Sony", "5860BA" to "Sony", "04B155" to "LG",
    "00B6B9" to "LG", "604B59" to "LG", "A88AB8" to "LG", "5416A8" to "Nokia",
    "001BFC" to "Asus", "00F8D5" to "Asus", "107EC7" to "Asus", "2C4DBA" to "Asus",
    "AC220B" to "Ubiquiti", "78E36B" to "Ubiquiti", "D0F2C8" to "Ubiquiti", "A0A18D" to "Ubiquiti",
    "000C0D" to "Ubiquiti", "045713" to "Amazon", "28B0D4" to "Amazon", "4CB503" to "Amazon",
    "88F5A6" to "Google", "A4BBC0" to "Google", "E4DC27" to "Google", "0000F7" to "Google Nest"
)

fun vendorOf(mac: String): String {
    val clean = mac.replace(":", "").replace("-", "").uppercase().take(6)
    if (clean.length < 6) return "غير معروف"
    for (i in 0 until OUI.size step 2) {
        if (i + 1 < OUI.size && OUI[i] == clean) return OUI[i + 1]
    }
    return "غير معروف"
}

// ── Wi-Fi ────────────────────────────────────────────────────────
data class WifiRow(
    val ssid: String, val bssid: String, val freq: Int,
    val rssi: Int, val channel: Int, val security: String
)

fun channelOf(freq: Int): Int = when {
    freq in 2412..2484 -> (freq - 2407) / 5
    freq in 5000..5999 -> (freq - 5000) / 5
    else -> 0
}

fun securityOf(caps: String): String = when {
    caps.contains("WPA3") -> "WPA3"
    caps.contains("WPA2") -> "WPA2"
    caps.contains("WPA") -> "WPA"
    caps.contains("WEP") -> "WEP"
    else -> "مفتوحة"
}

fun scanWifi(context: Context): List<WifiRow> {
    return try {
        val wm = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
        val scanOk = try { wm.startScan() } catch (e: Exception) { false }
        val res = wm.scanResults ?: emptyList()
        res.map { r ->
            WifiRow(
                r.ssid.ifBlank { "(مخفي)" }, r.bssid.uppercase(), r.frequency,
                r.level, channelOf(r.frequency), securityOf(r.capabilities)
            )
        }.sortedByDescending { it.rssi }
    } catch (e: Exception) { emptyList() }
}
