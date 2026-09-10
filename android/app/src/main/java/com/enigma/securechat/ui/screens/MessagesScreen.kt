package com.enigma.securechat.ui.screens

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Button
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.enigma.securechat.R
import com.enigma.securechat.domain.model.Contact
import com.enigma.securechat.ui.components.EnigmaAvatar
import com.enigma.securechat.ui.components.EnigmaBrandLogo
import com.enigma.securechat.ui.components.EnigmaEmptyState
import com.enigma.securechat.ui.components.EnigmaSearchBar
import com.enigma.securechat.ui.i18n.localizedString
import com.enigma.securechat.ui.viewmodel.ContactsViewModel

@Composable
fun MessagesScreen(
    viewModel: ContactsViewModel,
    language: String,
    onOpen: (Contact) -> Unit,
) {
    val contacts by viewModel.contacts.collectAsState()
    var query by remember { mutableStateOf("") }
    var createMenuOpen by remember { mutableStateOf(false) }
    var qrImportVisible by remember { mutableStateOf(false) }
    var qrInput by remember { mutableStateOf("") }
    val filtered = remember(contacts, query) {
        contacts.filter {
            query.isBlank() ||
                it.displayName.contains(query, ignoreCase = true) ||
                it.publicId.contains(query, ignoreCase = true)
        }
    }

    Scaffold(
        floatingActionButton = {
            Box {
                FloatingActionButton(onClick = { createMenuOpen = true }) {
                    Text("+", style = MaterialTheme.typography.headlineSmall)
                }
                DropdownMenu(
                    expanded = createMenuOpen,
                    onDismissRequest = { createMenuOpen = false },
                ) {
                    createActions(language).forEach { action ->
                        DropdownMenuItem(
                            text = { Text(action.label) },
                            onClick = {
                                createMenuOpen = false
                                qrImportVisible = true
                            },
                        )
                    }
                }
            }
        },
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(horizontal = 16.dp, vertical = 12.dp),
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                EnigmaBrandLogo(size = 44.dp)
                Spacer(Modifier.width(12.dp))
                Column {
                    Text(
                        text = localizedString(R.string.messages_title, language),
                        style = MaterialTheme.typography.headlineSmall,
                        fontWeight = FontWeight.Bold,
                    )
                    Text(
                        text = localizedString(R.string.conversation_e2ee, language),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.tertiary,
                    )
                }
            }
            Spacer(Modifier.height(14.dp))
            EnigmaSearchBar(
                value = query,
                onValueChange = { query = it },
                placeholder = localizedString(R.string.messages_search, language),
            )
            Spacer(Modifier.height(12.dp))
            if (qrImportVisible) {
                Spacer(Modifier.height(8.dp))
                OutlinedTextField(
                    value = qrInput,
                    onValueChange = { qrInput = it },
                    modifier = Modifier.fillMaxWidth(),
                    label = { Text(localizedString(R.string.messages_scan_qr, language)) },
                    minLines = 2,
                )
                Spacer(Modifier.height(6.dp))
                Button(
                    onClick = {
                        viewModel.importContactQr(qrInput)
                        qrInput = ""
                    },
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text(localizedString(R.string.contacts_add, language))
                }
            }
            Spacer(Modifier.height(8.dp))
            if (filtered.isEmpty()) {
                EnigmaEmptyState(
                    title = localizedString(R.string.messages_empty_title, language),
                    body = localizedString(R.string.messages_empty_body, language),
                    modifier = Modifier.weight(1f),
                )
            } else {
                LazyColumn(modifier = Modifier.weight(1f)) {
                    items(filtered, key = { it.userId }) { contact ->
                        ConversationListItem(contact = contact, language = language, onOpen = onOpen)
                        HorizontalDivider()
                    }
                }
            }
        }
    }
}

@Composable
private fun ConversationListItem(
    contact: Contact,
    language: String,
    onOpen: (Contact) -> Unit,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .height(76.dp)
            .clickable { onOpen(contact) }
            .padding(vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        EnigmaAvatar(label = contact.displayName, size = 52.dp)
        Spacer(Modifier.width(12.dp))
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = contact.displayName,
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.SemiBold,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            Text(
                text = localizedString(R.string.messages_last_encrypted, language),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
        }
        Text(
            text = contact.publicId,
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
            modifier = Modifier.size(width = 72.dp, height = 24.dp),
        )
    }
}

private data class CreateAction(
    val label: String,
)

@Composable
private fun createActions(language: String): List<CreateAction> = listOf(
    CreateAction(localizedString(R.string.messages_scan_qr, language)),
)
