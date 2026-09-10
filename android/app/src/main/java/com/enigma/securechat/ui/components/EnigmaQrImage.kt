package com.enigma.securechat.ui.components

import android.graphics.Color
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.size
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import com.enigma.securechat.qr.QrCodeGenerator

@Composable
fun EnigmaQrImage(
    content: String,
    modifier: Modifier = Modifier,
    size: Dp = 220.dp,
) {
    val bitmap = remember(content) {
        QrCodeGenerator.generate(
            content = content,
            sizePx = 512,
            foreground = Color.BLACK,
            background = Color.WHITE,
        )
    }
    Image(
        bitmap = bitmap.asImageBitmap(),
        contentDescription = null,
        modifier = modifier.size(size),
    )
}
