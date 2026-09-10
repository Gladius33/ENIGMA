package com.enigma.securechat.ui.screens

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.enigma.securechat.R
import com.enigma.securechat.data.db.ContactDeviceTrustState
import com.enigma.securechat.data.repository.MessageAttachment
import com.enigma.securechat.data.repository.MessagePayload
import com.enigma.securechat.domain.model.ChatMessage
import com.enigma.securechat.domain.model.Contact
import com.enigma.securechat.domain.model.MessageDirection
import com.enigma.securechat.domain.model.MessagePeerIdentityState
import com.enigma.securechat.domain.model.MessageStatus
import com.enigma.securechat.domain.model.MessageTransport
import com.enigma.securechat.domain.model.displayMessage
import com.enigma.securechat.ui.components.EnigmaAvatar
import com.enigma.securechat.ui.components.EnigmaMessageStatusIcon
import com.enigma.securechat.ui.i18n.localizedString
import com.enigma.securechat.ui.viewmodel.ConversationViewModel

@Composable
fun ConversationScreen(contact: Contact, viewModel: ConversationViewModel, language: String, onBack: () -> Unit) {
    val messages by viewModel.messages.collectAsState()
    val state by viewModel.state.collectAsState()
    val context = LocalContext.current
    val fr = language != "en"
    var input by remember { mutableStateOf("") }
    var pendingDownload by remember { mutableStateOf<MessageAttachment?>(null) }
    val hasFailedMessages = messages.any { it.direction == MessageDirection.OUTBOUND && it.status == MessageStatus.FAILED }

    val pickAttachment = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) {
            viewModel.sendAttachment(context.contentResolver, uri, input)
            input = ""
        }
    }
    val saveAttachment = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("*/*")) { uri ->
        val attachment = pendingDownload
        pendingDownload = null
        if (uri != null && attachment != null) viewModel.downloadAttachment(context.contentResolver, uri, attachment)
    }

    LaunchedEffect(contact.userId) { viewModel.loadSafetyNumber(); viewModel.syncPending() }
    LaunchedEffect(messages.size) { if (messages.isNotEmpty()) viewModel.markRead() }

    Column(Modifier.fillMaxSize().padding(16.dp)) {
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            OutlinedButton(onClick = onBack) { Text(localizedString(R.string.back_button, language)) }
            Spacer(Modifier.width(10.dp)); EnigmaAvatar(label = contact.displayName, size = 44.dp); Spacer(Modifier.width(10.dp))
            Column(Modifier.weight(1f)) {
                Text(contact.displayName, style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
                Text(localizedString(R.string.conversation_e2ee, language), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.tertiary)
                Text(
                    if (fr) "Transport mesuré localement sur chaque message" else "Transport measured locally for each message",
                    style = MaterialTheme.typography.labelSmall,
                )
            }
        }
        state.error?.let { Spacer(Modifier.height(8.dp)); Text(it.displayMessage(fr), color = MaterialTheme.colorScheme.error) }
        if (state.attachmentTransferInProgress) {
            Spacer(Modifier.height(8.dp))
            Text(if (fr) "Transfert chiffré en cours…" else "Encrypted transfer in progress…", style = MaterialTheme.typography.bodySmall)
        }
        if (hasFailedMessages) {
            Spacer(Modifier.height(8.dp)); OutlinedButton(onClick = viewModel::retryFailedMessages) { Text(localizedString(R.string.conversation_retry_failed, language)) }
        }
        state.safetyNumber?.let {
            Spacer(Modifier.height(8.dp)); Text(localizedString(R.string.conversation_safety_number, language, it), style = MaterialTheme.typography.bodySmall)
            Text(
                localizedString(
                    if (state.safetyVerified) R.string.conversation_safety_verified
                    else if (state.safetyTrustState == ContactDeviceTrustState.CHANGED) R.string.conversation_safety_changed
                    else if (state.safetyTrustState == ContactDeviceTrustState.BLOCKED) R.string.conversation_safety_blocked
                    else R.string.conversation_safety_unverified,
                    language,
                ),
                style = MaterialTheme.typography.bodySmall,
                color = if (state.safetyVerified) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.error,
            )
            if (!state.safetyVerified) { Spacer(Modifier.height(4.dp)); OutlinedButton(onClick = viewModel::verifySafetyNumber) { Text(localizedString(R.string.conversation_verify_safety_number, language)) } }
        }
        LazyColumn(Modifier.weight(1f).fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            items(messages, key = { it.id }) { message ->
                MessageBubble(message, viewModel.displayPayload(message), language) { attachment ->
                    pendingDownload = attachment
                    saveAttachment.launch(attachment.fileName ?: "enigma-attachment")
                }
            }
        }
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            OutlinedButton(onClick = { pickAttachment.launch(arrayOf("*/*")) }, enabled = !state.attachmentTransferInProgress) {
                Text(localizedString(R.string.conversation_attachment, language))
            }
            Spacer(Modifier.width(8.dp))
            OutlinedTextField(value = input, onValueChange = { input = it }, modifier = Modifier.weight(1f), singleLine = true, label = { Text(localizedString(R.string.conversation_message_label, language)) })
            Spacer(Modifier.width(8.dp))
            Button(onClick = { viewModel.send(input); input = "" }, enabled = input.isNotBlank() && !state.attachmentTransferInProgress, modifier = Modifier.padding(start = 8.dp)) {
                Text(localizedString(R.string.conversation_send, language))
            }
        }
    }
}

@Composable
private fun MessageBubble(message: ChatMessage, payload: MessagePayload, language: String, onSaveAttachment: (MessageAttachment) -> Unit) {
    val outbound = message.direction == MessageDirection.OUTBOUND
    val contentColor = if (outbound) MaterialTheme.colorScheme.onPrimary else MaterialTheme.colorScheme.onSurfaceVariant
    Row(Modifier.fillMaxWidth(), horizontalArrangement = if (outbound) Arrangement.End else Arrangement.Start) {
        Surface(
            modifier = Modifier.widthIn(max = 300.dp),
            color = if (outbound) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.surfaceVariant,
            shape = MaterialTheme.shapes.large,
        ) {
            Column(Modifier.padding(horizontal = 14.dp, vertical = 10.dp)) {
                if (payload.body.isNotBlank()) {
                    Text(payload.body, color = contentColor)
                }
                payload.attachments.forEach { attachment ->
                    if (payload.body.isNotBlank()) Spacer(Modifier.height(6.dp))
                    OutlinedButton(onClick = { onSaveAttachment(attachment) }) {
                        Text(attachment.fileName ?: localizedString(R.string.conversation_attachment, language))
                    }
                    Text(
                        if (language == "en") "${attachment.descriptor.sizeBytes} encrypted bytes" else "${attachment.descriptor.sizeBytes} octets chiffrés",
                        style = MaterialTheme.typography.labelSmall,
                        color = contentColor,
                    )
                }
                messageTransportEvidence(message, language)?.let { evidence ->
                    Spacer(Modifier.height(5.dp))
                    Text(
                        evidence,
                        style = MaterialTheme.typography.labelSmall,
                        fontWeight = FontWeight.Medium,
                        color = contentColor.copy(alpha = 0.82f),
                    )
                }
                Spacer(Modifier.height(4.dp))
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(localizedMessageStatus(message.status, language), style = MaterialTheme.typography.labelSmall, color = contentColor)
                    Spacer(Modifier.width(6.dp)); EnigmaMessageStatusIcon(message.status)
                }
            }
        }
    }
}

private fun messageTransportEvidence(message: ChatMessage, language: String): String? {
    if (
        message.status == MessageStatus.QUEUED ||
        message.status == MessageStatus.SENDING ||
        message.status == MessageStatus.RECEIVING ||
        message.status == MessageStatus.FAILED
    ) {
        return null
    }
    val fr = language != "en"
    val transport = when (message.transport) {
        MessageTransport.P2P_DIRECT -> if (fr) "P2P direct" else "Direct P2P"
        MessageTransport.P2P_TURN -> if (fr) "P2P via TURN" else "P2P via TURN"
        MessageTransport.RELAY -> if (fr) "Relais" else "Relay"
    }
    val identity = when (message.peerIdentityState) {
        MessagePeerIdentityState.VERIFIED -> if (fr) "appareil vérifié" else "verified device"
        MessagePeerIdentityState.UNVERIFIED -> if (fr) "identité non vérifiée" else "unverified identity"
        MessagePeerIdentityState.CHANGED -> if (fr) "clé d’identité modifiée" else "identity key changed"
        MessagePeerIdentityState.UNKNOWN -> if (fr) "identité inconnue" else "unknown identity"
    }
    return "$transport · $identity"
}

@Composable
private fun localizedMessageStatus(status: MessageStatus, language: String): String {
    if (status == MessageStatus.RECEIVING) {
        return if (language == "en") "receiving" else "réception"
    }
    val resId = when (status) {
        MessageStatus.QUEUED -> R.string.message_status_queued
        MessageStatus.SENDING -> R.string.message_status_sending
        MessageStatus.RECEIVING -> error("handled above")
        MessageStatus.SENT -> R.string.message_status_sent
        MessageStatus.DELIVERED -> R.string.message_status_delivered
        MessageStatus.READ -> R.string.message_status_read
        MessageStatus.FAILED -> R.string.message_status_failed
    }
    return localizedString(resId, language)
}
