package com.enigma.securechat.ui.screens

import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
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
import androidx.compose.foundation.rememberScrollState
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.getValue
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import com.enigma.securechat.R
import com.enigma.securechat.data.db.BubbleEntity
import com.enigma.securechat.data.db.BubbleMode
import com.enigma.securechat.data.repository.ActiveBubbleContext
import com.enigma.securechat.data.repository.RelayPrivateSessionStatus
import com.enigma.securechat.qr.BubbleInviteQrPayload
import com.enigma.securechat.qr.EnigmaQrPayloads
import com.enigma.securechat.ui.components.EnigmaAvatar
import com.enigma.securechat.ui.components.EnigmaBrandLogo
import com.enigma.securechat.ui.components.EnigmaQrImage
import com.enigma.securechat.ui.components.EnigmaSearchBar
import com.enigma.securechat.ui.i18n.localizedString
import com.enigma.securechat.ui.viewmodel.BubbleRelayTestStatus
import com.enigma.securechat.ui.viewmodel.BubbleViewModel

@Composable
fun BubblesScreen(viewModel: BubbleViewModel, language: String) {
    val state by viewModel.state.collectAsState()
    val error by viewModel.error.collectAsState()
    var query by remember { mutableStateOf("") }
    var fallbackAllowed by remember { mutableStateOf(true) }
    var bubbleQrInput by remember { mutableStateOf("") }
    var relayQrInput by remember { mutableStateOf("") }
    var relayName by remember { mutableStateOf("") }
    var relayUrl by remember { mutableStateOf("") }
    var relayPublicId by remember { mutableStateOf("") }
    var relayPassword by remember { mutableStateOf("") }
    var relayDeviceName by remember { mutableStateOf("Android") }
    LaunchedEffect(viewModel) { viewModel.load() }
    val bubbles = state.bubbles.filter {
        it.mode != BubbleMode.ORGANIZATION.name &&
            (query.isBlank() || it.name.contains(query, ignoreCase = true))
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 16.dp, vertical = 12.dp),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            EnigmaBrandLogo(size = 44.dp)
            Spacer(Modifier.width(12.dp))
            Text(
                text = localizedString(R.string.bubbles_title, language),
                style = MaterialTheme.typography.headlineSmall,
                fontWeight = FontWeight.Bold,
            )
        }
        Spacer(Modifier.height(14.dp))
        EnigmaSearchBar(
            value = query,
            onValueChange = { query = it },
            placeholder = localizedString(R.string.bubbles_search, language),
        )
        Spacer(Modifier.height(12.dp))
        state.activeContext?.let {
            BubbleDetail(
                context = it,
                customRelays = state.customRelays,
                fallbackAllowed = fallbackAllowed,
                onFallbackAllowedChange = { fallbackAllowed = it },
                bubbleQrInput = bubbleQrInput,
                onBubbleQrInputChange = { bubbleQrInput = it },
                relayQrInput = relayQrInput,
                onRelayQrInputChange = { relayQrInput = it },
                relayName = relayName,
                relayUrl = relayUrl,
                onRelayNameChange = { relayName = it },
                onRelayUrlChange = { relayUrl = it },
                relayTestStatus = state.relayTestStatus,
                relaySessionStatus = state.relaySessionStatus,
                relayPublicId = relayPublicId,
                relayPassword = relayPassword,
                relayDeviceName = relayDeviceName,
                onRelayPublicIdChange = { relayPublicId = it },
                onRelayPasswordChange = { relayPassword = it },
                onRelayDeviceNameChange = { relayDeviceName = it },
                onAttachRelay = { relayId -> viewModel.attachRelayToActiveBubble(relayId, fallbackAllowed) },
                onImportRelayQr = {
                    viewModel.importRelayQrToActiveBubble(relayQrInput, fallbackAllowed)
                    relayQrInput = ""
                },
                onAddAndAttachRelay = {
                    viewModel.addAndAttachRelayToActiveBubble(relayName, relayUrl, fallbackAllowed)
                    relayName = ""
                    relayUrl = ""
                },
                onUseOfficial = viewModel::useOfficialRelayForActiveBubble,
                onTestRelay = viewModel::testActiveRelay,
                onSignInPrivateRelay = {
                    viewModel.signInActivePrivateRelay(relayPublicId, relayPassword, relayDeviceName)
                    relayPassword = ""
                },
                onSignOutPrivateRelay = viewModel::signOutActivePrivateRelay,
                onCreateConnected = viewModel::createPrivateConnectedBubble,
                onCreateIsolated = viewModel::createPrivateIsolatedBubble,
                onSync = viewModel::syncRemote,
                onImportBubbleQr = {
                    viewModel.importBubbleInviteQr(bubbleQrInput)
                    bubbleQrInput = ""
                },
                language = language,
            )
            HorizontalDivider(Modifier.padding(vertical = 12.dp))
        }
        error?.let {
            Text(it.message, color = MaterialTheme.colorScheme.error)
            Spacer(Modifier.height(8.dp))
        }
        LazyColumn {
            items(bubbles, key = { it.id }) { bubble ->
                BubbleItem(
                    bubble = bubble,
                    onClick = { viewModel.activateBubble(bubble.id) },
                )
                HorizontalDivider()
            }
        }
    }
}

@Composable
private fun BubbleItem(
    bubble: BubbleEntity,
    onClick: () -> Unit,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        EnigmaAvatar(label = bubble.name, size = 50.dp)
        Spacer(Modifier.width(12.dp))
        Column(modifier = Modifier.weight(1f)) {
            Text(bubble.name, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
            Text(
                bubble.description.orEmpty(),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        Text(
            text = bubble.indexPolicy.displayEnum(),
            style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(start = 8.dp),
        )
    }
}

@Composable
private fun BubbleDetail(
    context: ActiveBubbleContext,
    customRelays: List<com.enigma.securechat.data.repository.RelayProfile>,
    fallbackAllowed: Boolean,
    onFallbackAllowedChange: (Boolean) -> Unit,
    bubbleQrInput: String,
    onBubbleQrInputChange: (String) -> Unit,
    relayQrInput: String,
    onRelayQrInputChange: (String) -> Unit,
    relayName: String,
    relayUrl: String,
    onRelayNameChange: (String) -> Unit,
    onRelayUrlChange: (String) -> Unit,
    relayTestStatus: BubbleRelayTestStatus?,
    relaySessionStatus: RelayPrivateSessionStatus?,
    relayPublicId: String,
    relayPassword: String,
    relayDeviceName: String,
    onRelayPublicIdChange: (String) -> Unit,
    onRelayPasswordChange: (String) -> Unit,
    onRelayDeviceNameChange: (String) -> Unit,
    onAttachRelay: (String) -> Unit,
    onImportRelayQr: () -> Unit,
    onAddAndAttachRelay: () -> Unit,
    onUseOfficial: () -> Unit,
    onTestRelay: () -> Unit,
    onSignInPrivateRelay: () -> Unit,
    onSignOutPrivateRelay: () -> Unit,
    onCreateConnected: () -> Unit,
    onCreateIsolated: () -> Unit,
    onSync: () -> Unit,
    onImportBubbleQr: () -> Unit,
    language: String,
) {
    val bubble = context.bubble
    val isolated = bubble.mode == BubbleMode.PRIVATE_ISOLATED.name
    val missingPrivateRelay = isolated && context.primaryRelay == null
    val bubbleQr = remember(bubble.id, bubble.name, bubble.mode, context.primaryRelay?.url) {
        EnigmaQrPayloads.bubbleInvite(
            BubbleInviteQrPayload(
                bubble_id = bubble.id,
                bubble_name = bubble.name,
                mode = bubble.mode,
                relay_hint = context.primaryRelay?.url,
                signature = null,
            ),
        )
    }
    Column {
        Text(bubble.name, style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
        Text(
            bubble.description.orEmpty(),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(Modifier.height(8.dp))
        Text("Mode : ${bubble.mode.displayEnum()}", style = MaterialTheme.typography.bodyMedium)
        Text(
            "Relais actif : ${context.primaryRelay?.name ?: "Relais privé requis"}",
            style = MaterialTheme.typography.bodyMedium,
        )
        Text(
            "Fallback officiel : ${if (!isolated && context.relayPolicy.fallbackOfficialAllowed) "oui" else "non"}",
            style = MaterialTheme.typography.bodyMedium,
        )
        Text("Indexation : ${bubble.indexPolicy.displayEnum()}", style = MaterialTheme.typography.bodyMedium)
        Text("Visibilité : ${bubble.visibility.displayEnum()}", style = MaterialTheme.typography.bodyMedium)
        Text(
            "Contacts globaux : ${if (context.showGlobalContacts) "oui" else "non"}",
            style = MaterialTheme.typography.bodyMedium,
        )
        if (missingPrivateRelay) {
            Spacer(Modifier.height(6.dp))
            Text(
                "Bulle isolée bloquée : attache un relais privé avant tout accès réseau.",
                color = MaterialTheme.colorScheme.error,
                style = MaterialTheme.typography.bodyMedium,
            )
        }
        Spacer(Modifier.height(8.dp))
        EnigmaQrImage(content = bubbleQr.uri)
        Spacer(Modifier.height(8.dp))
        Row(verticalAlignment = Alignment.CenterVertically) {
            Checkbox(
                checked = !isolated && fallbackAllowed,
                onCheckedChange = onFallbackAllowedChange,
                enabled = !isolated,
            )
            Text(
                if (isolated) {
                    "Fallback officiel interdit pour Private Isolated"
                } else {
                    "Autoriser fallback officiel pour cette bulle"
                },
            )
        }
        customRelays.forEach { relay ->
            OutlinedButton(
                onClick = { onAttachRelay(relay.id) },
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text("Attacher ${relay.name}")
            }
            Spacer(Modifier.height(4.dp))
        }
        OutlinedTextField(
            value = relayName,
            onValueChange = onRelayNameChange,
            modifier = Modifier.fillMaxWidth(),
            label = { Text("Nom du relais privé") },
            singleLine = true,
        )
        Spacer(Modifier.height(4.dp))
        OutlinedTextField(
            value = relayUrl,
            onValueChange = onRelayUrlChange,
            modifier = Modifier.fillMaxWidth(),
            label = { Text("URL du relais privé") },
            singleLine = true,
        )
        Spacer(Modifier.height(4.dp))
        Button(
            onClick = onAddAndAttachRelay,
            enabled = relayUrl.isNotBlank(),
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text("Ajouter et attacher à cette bulle")
        }
        Spacer(Modifier.height(8.dp))
        OutlinedTextField(
            value = relayQrInput,
            onValueChange = onRelayQrInputChange,
            modifier = Modifier.fillMaxWidth(),
            label = { Text("QR relais à attacher") },
            minLines = 2,
        )
        Spacer(Modifier.height(4.dp))
        Button(
            onClick = onImportRelayQr,
            enabled = relayQrInput.isNotBlank(),
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text("Importer QR relais et attacher")
        }
        Spacer(Modifier.height(4.dp))
        if (!isolated) {
            OutlinedButton(onClick = onUseOfficial, modifier = Modifier.fillMaxWidth()) {
                Text("Revenir au relais officiel")
            }
        }
        OutlinedButton(onClick = onTestRelay, modifier = Modifier.fillMaxWidth()) {
            Text("Tester le relais actif")
        }
        RelayTestStatusText(relayTestStatus)
        if (context.primaryRelay?.isOfficial == false) {
            Spacer(Modifier.height(8.dp))
            Text(
                "Session relais privé",
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.SemiBold,
            )
            if (relaySessionStatus != null) {
                Text(
                    "Connecté : ${relaySessionStatus.publicId} - device ${relaySessionStatus.deviceId.take(8)}...",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.primary,
                )
            } else {
                Text(
                    "Connexion au relais privé requise avant messages/groupes/canaux/appels.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error,
                )
            }
            OutlinedTextField(
                value = relayPublicId,
                onValueChange = onRelayPublicIdChange,
                modifier = Modifier.fillMaxWidth(),
                label = { Text("Identifiant public relais privé") },
                singleLine = true,
            )
            Spacer(Modifier.height(4.dp))
            OutlinedTextField(
                value = relayPassword,
                onValueChange = onRelayPasswordChange,
                modifier = Modifier.fillMaxWidth(),
                label = { Text("Mot de passe relais privé") },
                singleLine = true,
                visualTransformation = PasswordVisualTransformation(),
            )
            Spacer(Modifier.height(4.dp))
            OutlinedTextField(
                value = relayDeviceName,
                onValueChange = onRelayDeviceNameChange,
                modifier = Modifier.fillMaxWidth(),
                label = { Text("Nom appareil sur ce relais") },
                singleLine = true,
            )
            Spacer(Modifier.height(4.dp))
            Row(Modifier.fillMaxWidth()) {
                Button(
                    onClick = onSignInPrivateRelay,
                    enabled = relayPublicId.isNotBlank() && relayPassword.isNotBlank(),
                    modifier = Modifier.weight(1f),
                ) {
                    Text("Connecter")
                }
                Spacer(Modifier.width(8.dp))
                OutlinedButton(
                    onClick = onSignOutPrivateRelay,
                    modifier = Modifier.weight(1f),
                ) {
                    Text("Déconnecter")
                }
            }
        }
        Spacer(Modifier.height(8.dp))
        Row(Modifier.fillMaxWidth()) {
            OutlinedButton(onClick = onCreateConnected, modifier = Modifier.weight(1f)) {
                Text("Private Connected")
            }
            Spacer(Modifier.width(8.dp))
            OutlinedButton(onClick = onCreateIsolated, modifier = Modifier.weight(1f)) {
                Text("Private Isolated")
            }
        }
        Spacer(Modifier.height(8.dp))
        OutlinedTextField(
            value = bubbleQrInput,
            onValueChange = onBubbleQrInputChange,
            modifier = Modifier.fillMaxWidth(),
            label = { Text("QR invitation bulle") },
            minLines = 2,
        )
        Spacer(Modifier.height(6.dp))
        Button(onClick = onImportBubbleQr, modifier = Modifier.fillMaxWidth()) {
            Text("Importer QR bulle")
        }
        Spacer(Modifier.height(6.dp))
        OutlinedButton(onClick = onSync, modifier = Modifier.fillMaxWidth()) {
            Text("Synchroniser avec le backend")
        }
        Spacer(Modifier.height(8.dp))
        val sections = listOf(
            R.string.bubbles_section_conversations,
            R.string.bubbles_section_channels,
            R.string.bubbles_section_services,
            R.string.bubbles_section_members,
            R.string.bubbles_section_relays,
            R.string.bubbles_section_security,
            R.string.bubbles_section_indexing,
        )
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .horizontalScroll(rememberScrollState()),
        ) {
            sections.forEach { section ->
                Text(
                    text = localizedString(section, language),
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(end = 8.dp),
                )
            }
        }
        Spacer(Modifier.height(8.dp))
        Button(onClick = onCreateConnected) {
            Text(localizedString(R.string.bubbles_create, language))
        }
    }
}

@Composable
private fun RelayTestStatusText(status: BubbleRelayTestStatus?) {
    when (status) {
        BubbleRelayTestStatus.Checking -> Text(
            "Vérification du relais en cours",
            style = MaterialTheme.typography.bodySmall,
        )
        is BubbleRelayTestStatus.Reachable -> Text(
            "Relais joignable : ${status.status} - ${status.name} ${status.version}",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.primary,
        )
        null -> Unit
    }
}

private fun String.displayEnum(): String =
    lowercase().split('_').joinToString(" ") { part ->
        part.replaceFirstChar { it.uppercase() }
    }
