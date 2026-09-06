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
                }
            }
        }
    }
}
