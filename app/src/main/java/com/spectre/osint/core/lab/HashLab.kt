package com.spectre.osint.core.lab

import android.content.Context
import com.spectre.osint.core.Crypter
import java.io.File
import java.security.MessageDigest

// ════════════════════════════════════════════════════════════════
//  كسر التجزئة الحقيقي — قاموس مدمج + لواحق رقمية
// ════════════════════════════════════════════════════════════════
object HashLab {

    val wordlist: List<String> = listOf(
        "123456", "password", "123456789", "12345678", "qwerty", "abc123", "111111",
        "123123", "123321", "000000", "654321", "666666", "888888", "admin", "root",
        "toor", "letmein", "welcome", "monkey", "dragon", "shadow", "superman",
        "iloveyou", "princess", "football", "baseball", "master", "sunshine",
        "whatever", "trustno1", "hunter2", "killer", "batman", "soccer", "pokemon",
        "jordan", "tigger", "charlie", "starwars", "computer", "freedom", "hello",
        "love", "secret", "passw0rd", "p@ssw0rd", "admin123", "password123",
        "qwerty123", "1q2w3e4r", "zaq12wsx", "shadow123", "user1", "hacker",
        "iraq", "baghdad", "duhok", "kurdistan", "kurd", "peshmerga", "erbil",
        "sulaymaniyah", "mosul", "basra", "najaf", "karbala", "amman", "cairo",
        "ali", "hasan", "mohammed", "ahmed", "hussein", "sara", "zainab", "fatima",
        "omar", "osama", "mustafa", "yasser", "abdullah", "khaled", "marwan",
        "iraq2020", "iraq2021", "iraq2022", "iraq2023", "iraq2024", "iraq2025",
        "kurd2020", "kurd2021", "kurdistan2020", "duhok2020", "duhok2021",
        "963", "964", "0770", "0750", "0771", "0772", "0780", "abc", "abcd",
        "pass", "test", "guest", "login", "info", "admin1", "administrator",
        "root123", "toor123", "letmein1", "welcome1", "monkey1", "dragon1",
        "shadow1", "superman1", "iloveyou1", "batman1", "football1",
        "p@ssword", "p@ssw0rd1", "secret123", "hacker123", "hackme",
        "5hadow", "sh4dow", "54hadow", "spectre", "spectre1", "spectre123",
        "qwertyuiop", "asdfghjkl", "zxcvbnm", "zaq1xsw2", "1qaz2wsx", "q1w2e3r4",
        "1234567890", "0123456789", "112233", "121212", "131313", "151515",
        "7777777", "999999", "a123456", "aa123456", "abc123456", "abcd1234",
        "pass1234", "test1234", "demo1234", "guest123", "temp1234", "default",
        "changeme", "password1", "password!", "qwerty123!", "letmein!", "admin!",
        "root!", "root1234", "toor1234", "shadow123!", "kurd1", "kurd2",
        "iraq1", "iraq2", "iraq3", "baghdad1", "duhok1", "erbil1", "mosul1",
        "kirkuk", "kirkuk1", "slemani", "dahuk", "dohuk", "peshmerga1",
        "azadi", "azadi1", "eyni", "helebce", "halabja", "zakho", "ameadi",
        "akre", "zaxo", "nikel", "mame", "rozha", "roj", "rojava", "shengal",
        "kobani", "afrin", "tilkif", "alkosh", "badinan", "soran", "rawanduz",
        "halabja1", "rawanduz1", "soran1", "sharazur", "pirmam", "prizi",
        "khamis", "barzani", "talabani", "mustafa", "masoud", "barham",
        "nechirvan", "massoud", "mam", "baba", "gorran", "turkmen", "yazidi",
        "kurdish", "kurdi", "kurdish1", "kermasor", "mamosta", "perwer",
        "ciwan", "dilovan", "ayan", "ayan1", "ahmad", "ahmadi", "kadhim",
        "jafar", "hadi", "halim", "salim", "karim", "resul", "raman", "moshi"
    ).distinct()

    val suffixBases = listOf(
        "admin", "ali", "sara", "iraq", "kurd", "duhok", "shadow", "user1",
        "hacker", "erbil", "baghdad", "ahmed", "omar", "mustafa", "karim", "raz"
    )

    fun crack(hash: String, algo: String = "MD5"): Pair<String?, Int> {
        val h = hash.trim().lowercase()
        val n = if (algo == "MD5") 32 else 40
        if (h.length != n || h.any { it !in "0123456789abcdef" }) return null to 0
        var tries = 0
        fun check(w: String): Boolean {
            tries++
            val dh = if (algo == "MD5") Crypter.md5(w) else Crypter.sha1(w)
            return dh.equals(h, ignoreCase = true)
        }
        wordlist.forEach { if (check(it)) return it to tries }
        for (base in suffixBases) {
            for (d in 0..9) { val w = "$base$d"; if (check(w)) return w to tries }
            for (y in listOf("2020", "2021", "2022", "2023", "2024", "2025", "19", "97", "88")) {
                val w = "$base$y"; if (check(w)) return w to tries
            }
        }
        return null to tries
    }
}
