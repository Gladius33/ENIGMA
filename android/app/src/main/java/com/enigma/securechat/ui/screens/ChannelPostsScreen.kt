package com.enigma.securechat.ui.screens

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import com.enigma.securechat.data.db.ChannelEntity
import com.enigma.securechat.data.repository.MessageAttachment
import com.enigma.securechat.ui.viewmodel.ChannelsViewModel

@Composable
fun ChannelPostsScreen(channel: ChannelEntity, viewModel: ChannelsViewModel, onBack: () -> Unit) {
    val posts by viewModel.posts(channel.id).collectAsState(initial = emptyList())
    val state by viewModel.state.collectAsState()
    val audience by viewModel.audience.collectAsState()
    val context = LocalContext.current
    var body by remember(channel.id) { mutableStateOf("") }
    var pendingDownload by remember(channel.id) { mutableStateOf<MessageAttachment?>(null) }

    val pickAttachment = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) {
            viewModel.publishAttachment(context.contentResolver, channel.id, uri, body)
            body = ""
        }
    }
    val saveAttachment = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("*/*")) { uri ->
        val attachment = pendingDownload
        pendingDownload = null
        if (uri != null && attachment != null) {
            viewModel.downloadAttachment(context.contentResolver, uri, attachment)
        }
    }

    LaunchedEffect(channel.id) { viewModel.syncPosts(channel.id) }
    Column(Modifier.fillMaxSize().padding(16.dp)) {
        Row(Modifier.fillMaxWidth()) {
            Text(channel.title, style = MaterialTheme.typography.headlineSmall, modifier = Modifier.weight(1f))
            OutlinedButton(onClick = onBack) { Text("Retour") }
        }
        state.error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
        if (state.attachmentTransferInProgress) {
            Text("Transfert chiffré en cours…", style = MaterialTheme.typography.bodySmall)
        }
        if (audience.isNotEmpty()) {
            Text(
                text = audience.joinToString { "${it.publicId} (${it.role})" },
                style = MaterialTheme.typography.bodySmall,
            )
        }
        Spacer(Modifier.height(12.dp))
        Row(Modifier.fillMaxWidth()) {
            OutlinedButton(
                onClick = { pickAttachment.launch(arrayOf("*/*")) },
                enabled = !state.attachmentTransferInProgress,
            ) {
                Text("Pièce jointe")
            }
            OutlinedTextField(
                value = body,
                onValueChange = { body = it },
                modifier = Modifier.weight(1f).padding(start = 8.dp),
                label = { Text("Post") },
            )
            Button(
                onClick = {
                    viewModel.publish(channel.id, body)
                    body = ""
                },
                enabled = body.isNotBlank() && !state.attachmentTransferInProgress,
                modifier = Modifier.padding(start = 8.dp),
            ) {
                Text("Publier")
            }
        }
        LazyColumn {
            items(posts, key = { it.id }) { post ->
                val payload = viewModel.postPayload(post)
                Column(Modifier.fillMaxWidth().padding(vertical = 10.dp)) {
                    if (payload.body.isNotBlank()) {
                        Text(payload.body)
                    }
                    payload.attachments.forEach { attachment ->
                        OutlinedButton(
                            onClick = {
                                pendingDownload = attachment
                                saveAttachment.launch(attachment.fileName ?: "enigma-attachment")
                            },
                        ) {
                            Text(attachment.fileName ?: "Pièce jointe")
                        }
                        Text(
                            "${attachment.descriptor.sizeBytes} octets chiffrés",
                            style = MaterialTheme.typography.bodySmall,
                        )
                    }
                    if (payload.body.isBlank() && payload.attachments.isEmpty()) {
                        Text("Payload E2EE indisponible")
                    }
                    Text(post.createdAt, style = MaterialTheme.typography.bodySmall)
                }
                HorizontalDivider()
            }
        }
    }
}
