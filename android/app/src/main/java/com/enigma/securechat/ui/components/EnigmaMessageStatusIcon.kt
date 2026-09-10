package com.enigma.securechat.ui.components

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import com.enigma.securechat.domain.model.MessageStatus

@Composable
fun EnigmaMessageStatusIcon(status: MessageStatus?) {
    val text = when (status) {
        MessageStatus.QUEUED -> "..."
        MessageStatus.SENDING -> "..."
        MessageStatus.RECEIVING -> "..."
        MessageStatus.SENT -> "S"
        MessageStatus.DELIVERED -> "D"
        MessageStatus.READ -> "R"
        MessageStatus.FAILED -> "!"
        null -> ""
    }
    val color: Color = when (status) {
        MessageStatus.READ -> MaterialTheme.colorScheme.primary
        MessageStatus.FAILED -> MaterialTheme.colorScheme.error
        else -> MaterialTheme.colorScheme.onSurfaceVariant
    }
    Text(text = text, color = color, style = MaterialTheme.typography.labelMedium)
}
