package com.spectre.osint

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.BackHandler
import androidx.activity.compose.setContent
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import com.spectre.osint.ui.home.HomeScreen
import com.spectre.osint.ui.theme.SpectreTheme
import com.spectre.osint.ui.tools.*

sealed class Screen {
    data object Home : Screen()
    data object Exif : Screen()
    data object Password : Screen()
    data object Ip : Screen()
    data object Qr : Screen()
    data object Breach : Screen()
    data object Whois : Screen()
    data object Link : Screen()
    data object Port : Screen()
    data object SubEnum : Screen()
    data object Http : Screen()
    data object Apk : Screen()
    data object File : Screen()
    data object Crypto : Screen()
    data object Device : Screen()
}

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            SpectreTheme {
                var screen by remember { mutableStateOf<Screen>(Screen.Home) }
                BackHandler(enabled = screen != Screen.Home) { screen = Screen.Home }
                when (screen) {
                    Screen.Home -> HomeScreen(onOpen = { screen = it })
                    Screen.Exif -> ExifScreen(onBack = { screen = Screen.Home })
                    Screen.Password -> PasswordScreen(onBack = { screen = Screen.Home })
                    Screen.Ip -> IpScreen(onBack = { screen = Screen.Home })
                    Screen.Qr -> QrScreen(onBack = { screen = Screen.Home })
                    Screen.Breach -> BreachScreen(onBack = { screen = Screen.Home })
                    Screen.Whois -> WhoisScreen(onBack = { screen = Screen.Home })
                    Screen.Link -> LinkScreen(onBack = { screen = Screen.Home })
                    Screen.Port -> PortScreen(onBack = { screen = Screen.Home })
                    Screen.SubEnum -> SubEnumScreen(onBack = { screen = Screen.Home })
                    Screen.Http -> HttpScreen(onBack = { screen = Screen.Home })
                    Screen.Apk -> ApkScreen(onBack = { screen = Screen.Home })
                    Screen.File -> FileScreen(onBack = { screen = Screen.Home })
                    Screen.Crypto -> CryptoScreen(onBack = { screen = Screen.Home })
                    Screen.Device -> DeviceAuditScreen(onBack = { screen = Screen.Home })
                }
            }
        }
    }
}
