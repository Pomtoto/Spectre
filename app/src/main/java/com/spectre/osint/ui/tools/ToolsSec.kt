package com.spectre.osint.ui.tools

import android.content.Context
import android.graphics.Bitmap
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.PickVisualMediaRequest
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CameraAlt
import androidx.compose.material.icons.filled.Email
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.QrCode
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.material3.TextField
import androidx.compose.material3.TextFieldDefaults
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.spectre.osint.core.*
import com.spectre.osint.ui.*
import com.spectre.osint.ui.theme.*
import kotlinx.coroutines.launch

// ════════════════════════════════════════════════════════════════
//  قارئ وتوليد QR
// ════════════════════════════════════════════════════════════════
@Composable
fun QrScreen(onBack: () -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var mode by remember { mutableStateOf(0) } // 0 توليد | 1 فك
    var text by remember { mutableStateOf("") }
    var qr by remember { mutableStateOf<Bitmap?>(null) }
    var decoded by remember { mutableStateOf<List<String>>(emptyList()) }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }

    val picker = rememberLauncherForActivityResult(ActivityResultContracts.PickVisualMedia()) { u ->
        if (u != null) {
            decoded = emptyList(); error = null; busy = true
            scope.launch {
                val d = decodeQr(context, u)
                decoded = if (d.isNullOrBlank()) emptyList() else listOf(d)
                busy = false
                if (decoded.isEmpty()) error = "لم يُعثر على رمز واضح في الصورة"
            }
        }
    }

    ToolScaffold("QR MODULE", "توليد وفك رموز QR", onBack) { pad ->
        Column(
            Modifier.padding(pad).padding(16.dp).verticalScroll(rememberScrollState())
        ) {
            // مبدّل الوضع
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                ModeChip("توليد رمز", mode == 0) { mode = 0 }
                ModeChip("فك رمز", mode == 1) { mode = 1 }
            }
            Spacer(Modifier.height(14.dp))

            if (mode == 0) {
                TextField(
                    value = text,
                    onValueChange = { text = it },
                    modifier = Modifier.fillMaxWidth(),
                    minLines = 2,
                    colors = TextFieldDefaults.colors(
                        focusedContainerColor = Surface2,
                        unfocusedContainerColor = Surface2,
                        focusedIndicatorColor = Neon,
                        unfocusedIndicatorColor = Border,
                        cursorColor = Neon,
                        focusedTextColor = TextHi,
                        unfocusedTextColor = TextHi
                    ),
                    textStyle = androidx.compose.ui.text.TextStyle(color = TextHi, fontSize = 14.sp),
                    placeholder = { Text("نص، رابط، رقم …", color = TextDim) },
                    shape = RoundedCornerShape(10.dp)
                )
                Spacer(Modifier.height(10.dp))
                ActionButton("توليد الرمز", Icons.Filled.QrCode, enabled = text.isNotBlank()) {
                    qr = generateQr(text, 768)
                }
                qr?.let { bmp ->
                    Spacer(Modifier.height(16.dp))
                    Box(
                        Modifier.fillMaxWidth().padding(12.dp)
                            .clip(RoundedCornerShape(16.dp))
                            .background(androidx.compose.ui.graphics.Color.White)
                            .padding(4.dp),
                        contentAlignment = Alignment.Center
                    ) {
                        Image(bmp.asImageBitmap(), "QR", modifier = Modifier.size(220.dp))
                    }
                    Spacer(Modifier.height(8.dp))
                    Text(
                        "يمكن مسح الرمز بأي تطبيق كاميرا أو قارئ",
                        color = TextDim, fontSize = 11.5.sp, fontFamily = TajawalFamily
                    )
                }
            } else {
                ActionButton("اختيار صورة تحتوي رمزاً", Icons.Filled.CameraAlt) {
                    picker.launch(PickVisualMediaRequest(ActivityResultContracts.PickVisualMedia.ImageOnly))
                }
                if (busy) { Spacer(Modifier.height(16.dp)); ScanningBar("جارٍ قراءة الرمز") }
                error?.let {
                    Spacer(Modifier.height(14.dp))
                    Text(it, color = Red, fontSize = 13.sp, fontFamily = TajawalFamily)
                }
                if (decoded.isNotEmpty()) {
                    ResultCard("محتوى الرمز", Neon) {
                        decoded.forEach { d ->
                            CopyRow("القيمة", d, Cyan)
                        }
                    }
                } else if (!busy) {
                    EmptyHint("الصق صورة فيها QR لفكّه", "يدعم QR وBarcode بجميع الصيغ الشائعة")
                }
            }
            Spacer(Modifier.height(24.dp))
        }
    }
}

@Composable
private fun ModeChip(label: String, selected: Boolean, onClick: () -> Unit) {
    Box(
        Modifier
            .clip(RoundedCornerShape(10.dp))
            .background(if (selected) Neon.copy(alpha = 0.14f) else Surface)
            .border(1.dp, if (selected) Neon.copy(alpha = 0.7f) else Border, RoundedCornerShape(10.dp))
            .clickableNoRipple(onClick)
            .padding(horizontal = 16.dp, vertical = 8.dp)
    ) {
        Text(label, color = if (selected) Neon else TextDim, fontSize = 12.5.sp, fontWeight = FontWeight.Bold, fontFamily = TajawalFamily)
    }
}
