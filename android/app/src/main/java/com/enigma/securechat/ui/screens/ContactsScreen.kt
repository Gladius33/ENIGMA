package com.enigma.securechat.ui.screens

import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.AssistChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.foundation.rememberScrollState
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.enigma.securechat.R
import com.enigma.securechat.domain.model.Contact
import com.enigma.securechat.domain.model.displayMessage
import com.enigma.securechat.ui.components.EnigmaAvatar
import com.enigma.securechat.ui.components.EnigmaBrandLogo
import com.enigma.securechat.ui.components.EnigmaEmptyState
import com.enigma.securechat.ui.components.EnigmaQrImage
import com.enigma.securechat.ui.components.EnigmaSearchBar
import com.enigma.securechat.ui.i18n.localizedString
import com.enigma.securechat.ui.viewmodel.ContactsViewModel

@Composable
fun ContactsScreen(
    viewModel: ContactsViewModel,
    language: String,
    onOpen: (Contact) -> Unit,
) {
    val contacts by viewModel.contacts.collectAsState()
    val state by viewModel.state.collectAsState()
    val activeContext by viewModel.activeBubbleContext.collectAsState()
    val identityQr by viewModel.identityQr.collectAsState()
    val fr = language != "en"
    var publicId by remember { mutableStateOf("") }
    var query by remember { mutableStateOf("") }
    var qrInput by remember { mutableStateOf("") }
    val showGlobalContacts = activeContext?.showGlobalContacts != false
    val filtered = remember(contacts, query) {
        contacts.filter {
            query.isBlank() ||
                it.displayName.contains(query, ignoreCase = true) ||
                it.publicId.contains(query, ignoreCase = true)
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 16.dp, vertical = 12.dp),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            EnigmaBrandLogo(size = 44.dp)
            Spacer(Modifier.width(12.dp))
            Column {
                Text(
                    localizedString(R.string.contacts_title, language),
                    style = MaterialTheme.typography.headlineSmall,
                    fontWeight = FontWeight.Bold,
                )
                Text(
                    localizedString(R.string.contacts_stable_mode, language),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.tertiary,
                )
            }
        }
        Spacer(Modifier.height(14.dp))
        EnigmaSearchBar(
            value = query,
            onValueChange = { query = it },
            placeholder = localizedString(R.string.contacts_search, language),
        )
        Spacer(Modifier.height(10.dp))
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .horizontalScroll(rememberScrollState()),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            AssistChip(
                onClick = { viewModel.importContactQr(qrInput) },
                label = { Text(localizedString(R.string.contacts_scan_qr, language)) },
            )
            AssistChip(
                onClick = viewModel::showIdentityQr,
                label = { Text(localizedString(R.string.contacts_share_qr, language)) },
            )
        }
        identityQr?.let { qr ->
            Spacer(Modifier.height(12.dp))
            EnigmaQrImage(content = qr.uri)
            Spacer(Modifier.height(4.dp))
            Text(qr.uri, style = MaterialTheme.typography.bodySmall)
        }
        Spacer(Modifier.height(8.dp))
        OutlinedTextField(
            value = qrInput,
            onValueChange = { qrInput = it },
            modifier = Modifier.fillMaxWidth(),
            label = { Text(localizedString(R.string.contacts_scan_qr, language)) },
            minLines = 2,
        )
        Spacer(Modifier.height(16.dp))
        if (showGlobalContacts) {
            Row(Modifier.fillMaxWidth()) {
                OutlinedTextField(
                    value = publicId,
                    onValueChange = { publicId = it },
                    modifier = Modifier.weight(1f),
                    label = { Text(localizedString(R.string.handle_label, language)) },
                    singleLine = true,
                )
                Button(
                    onClick = {
                        viewModel.addContact(publicId)
                        publicId = ""
                    },
                    modifier = Modifier.padding(start = 8.dp),
                ) {
                    Text(localizedString(R.string.contacts_add, language))
                }
            }
        }
        state.error?.let {
            Spacer(Modifier.height(8.dp))
            Text(it.displayMessage(fr), color = MaterialTheme.colorScheme.error)
        }
        Spacer(Modifier.height(16.dp))
        if (filtered.isEmpty() && !showGlobalContacts) {
            EnigmaEmptyState(
                title = "Private Isolated",
                body = "Contacts globaux masqués pour cette bulle.",
                modifier = Modifier.weight(1f),
            )
        } else if (filtered.isEmpty()) {
            EnigmaEmptyState(
                title = localizedString(R.string.contacts_title, language),
                body = localizedString(R.string.messages_empty_body, language),
                modifier = Modifier.weight(1f),
            )
        } else {
            LazyColumn(modifier = Modifier.weight(1f)) {
                items(filtered, key = { it.userId }) { contact ->
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable { onOpen(contact) }
                            .padding(vertical = 12.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        EnigmaAvatar(label = contact.displayName)
                        Spacer(Modifier.width(12.dp))
                        Column(
                            modifier = Modifier.weight(1f),
                        ) {
                            Text(contact.displayName, fontWeight = FontWeight.SemiBold)
                            Text(contact.publicId, style = MaterialTheme.typography.bodySmall)
                        }
                        OutlinedButton(onClick = { onOpen(contact) }) {
                            Text(localizedString(R.string.tab_messages, language))
                        }
                    }
                    HorizontalDivider()
                }
            }
        }
    }
}
