package com.enigma.securechat.ui.screens

import android.Manifest
import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.provider.Settings
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.Composable
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
import androidx.core.content.ContextCompat
import androidx.core.content.FileProvider
import com.enigma.securechat.BuildConfig
import com.enigma.securechat.R
import com.enigma.securechat.domain.model.displayMessage
import com.enigma.securechat.ui.components.EnigmaBrandLogo
import com.enigma.securechat.ui.components.EnigmaQrImage
import com.enigma.securechat.ui.i18n.localizedString
import com.enigma.securechat.ui.i18n.localizedText
import com.enigma.securechat.ui.viewmodel.SettingsCryptoStatus
import com.enigma.securechat.ui.viewmodel.SettingsServerStatus
import com.enigma.securechat.ui.viewmodel.SettingsUpdateStatus
import com.enigma.securechat.ui.viewmodel.SettingsViewModel
import java.io.File

@Composable
fun SettingsScreen(
    viewModel: SettingsViewModel,
    onBack: () -> Unit,
    onDeleted: () -> Unit,
) {
    val context = LocalContext.current
    val activeEndpointDebug by viewModel.activeEndpointDebug.collectAsState()
    val relays by viewModel.relays.collectAsState()
    val customRelays by viewModel.customRelays.collectAsState()
    val defaultRelayId by viewModel.defaultRelayId.collectAsState()
    val relayQr by viewModel.relayQr.collectAsState()
    val state by viewModel.state.collectAsState()
    val language by viewModel.language.collectAsState()
    val session by viewModel.session.collectAsState()
    val fr = language != "en"
    var customRelayName by remember { mutableStateOf("") }
    var customRelayUrl by remember { mutableStateOf("") }
    var relayQrInput by remember { mutableStateOf("") }
    var deleteConfirmation by remember { mutableStateOf("") }
    var notificationsGranted by remember { mutableStateOf(context.notificationsGranted()) }
    val notificationPermissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { granted ->
        notificationsGranted = granted
    }
    LaunchedEffect(state.deleted) {
        if (state.deleted) onDeleted()
    }
    LaunchedEffect(language) {
        viewModel.loadCryptoStatus()
    }
    LaunchedEffect(viewModel) {
        viewModel.loadRelays()
        viewModel.loadBusiness()
    }
    Column(
        Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(24.dp),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            EnigmaBrandLogo(size = 64.dp)
            Spacer(Modifier.width(14.dp))
            Column {
                Text(
                    localizedString(R.string.profile_title, language),
                    style = MaterialTheme.typography.headlineMedium,
                    fontWeight = FontWeight.Bold,
                )
                Text(localizedString(R.string.profile_about, language), style = MaterialTheme.typography.bodyMedium)
            }
        }
        session?.let {
            Spacer(Modifier.height(12.dp))
            Text(localizedString(R.string.settings_identity, language, it.publicId))
        }
        Spacer(Modifier.height(8.dp))
        Text(localizedString(R.string.settings_app_version, language, viewModel.appVersion))
        state.support?.takeIf { it.supportEnabled }?.let { support ->
            Spacer(Modifier.height(16.dp))
            Text(localizedString(R.string.support_title, language), style = MaterialTheme.typography.titleMedium)
            Text(localizedString(R.string.support_description, language), style = MaterialTheme.typography.bodySmall)
            support.donationUrl(language)?.takeIf { support.donationsEnabled }?.let { url ->
                Button(onClick = { context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url))) }, modifier = Modifier.fillMaxWidth()) { Text(localizedString(R.string.donate_button, language)) }
            }
            support.premiumUrl(language)?.takeIf { support.premiumEnabled }?.let { url ->
                OutlinedButton(onClick = { context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url))) }, modifier = Modifier.fillMaxWidth()) { Text(localizedString(R.string.premium_button, language)) }
            }
        }
        state.plan?.let { plan ->
            Text(localizedString(R.string.current_plan, language, plan.planName))
            state.usage?.let { usage -> Text(localizedString(R.string.storage_usage, language, usage.storageVerifiedBytes + usage.storagePendingBytes, usage.storageQuotaBytes)) }
            Text(localizedString(R.string.max_attachment_size, language, plan.maxAttachmentBytes))
        }
        state.announcements.forEach { announcement ->
            Spacer(Modifier.height(12.dp)); Text(localizedString(R.string.official_message, language), fontWeight = FontWeight.Bold)
            Text(announcement.title, fontWeight = FontWeight.SemiBold); Text(announcement.body)
            announcement.ctaUrl?.let { url -> OutlinedButton(onClick={ context.startActivity(Intent(Intent.ACTION_VIEW,Uri.parse(url))) }) { Text(announcement.ctaLabel ?: localizedString(R.string.open_link, language)) } }
            Row { OutlinedButton(onClick={viewModel.readAnnouncement(announcement.id)}){Text(localizedString(R.string.mark_read,language))}; OutlinedButton(onClick={viewModel.dismissAnnouncement(announcement.id)}){Text(localizedString(R.string.dismiss,language))} }
        }
        Spacer(Modifier.height(16.dp))
        Text(localizedString(R.string.profile_security, language), style = MaterialTheme.typography.titleMedium)
        Spacer(Modifier.height(6.dp))
        Text(localizedString(R.string.settings_crypto_compare, language), style = MaterialTheme.typography.bodySmall)
        Spacer(Modifier.height(16.dp))
        Text(localizedString(R.string.language_title, language), style = MaterialTheme.typography.titleMedium)
        Spacer(Modifier.height(8.dp))
        OutlinedButton(onClick = { viewModel.saveLanguage("fr") }, modifier = Modifier.fillMaxWidth()) {
            Text(
                localizedString(
                    if (language == "fr") R.string.language_french_selected else R.string.language_french,
                    language,
                ),
            )
        }
        Spacer(Modifier.height(8.dp))
        OutlinedButton(onClick = { viewModel.saveLanguage("en") }, modifier = Modifier.fillMaxWidth()) {
            Text(
                localizedString(
                    if (language == "en") R.string.language_english_selected else R.string.language_english,
                    language,
                ),
            )
        }
        Spacer(Modifier.height(16.dp))
        Text(localizedString(R.string.settings_network_relays, language), style = MaterialTheme.typography.titleMedium)
        Spacer(Modifier.height(8.dp))
        Text(localizedString(R.string.settings_official_relay_name, language), fontWeight = FontWeight.SemiBold)
        Text(localizedString(R.string.settings_relay_connected, language))
        Text(localizedString(R.string.settings_relay_verified, language))
        Text(localizedString(R.string.settings_relay_region_auto, language))
        if (BuildConfig.DEBUG) {
            Spacer(Modifier.height(4.dp))
            Text(
                localizedString(R.string.settings_debug_active_endpoint, language, activeEndpointDebug),
                style = MaterialTheme.typography.bodySmall,
            )
        }
        val activeRelay = relays.firstOrNull { it.id == defaultRelayId } ?: relays.firstOrNull { it.isOfficial }
        Spacer(Modifier.height(8.dp))
        OutlinedButton(
            onClick = { activeRelay?.let(viewModel::showRelayQr) },
            enabled = activeRelay != null,
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text("Afficher QR relais actif")
        }
        relayQr?.let { qr ->
            Spacer(Modifier.height(8.dp))
            EnigmaQrImage(content = qr.uri)
            Spacer(Modifier.height(4.dp))
            Text(qr.uri, style = MaterialTheme.typography.bodySmall)
        }
        Spacer(Modifier.height(8.dp))
        Button(onClick = viewModel::useOfficialRelay, modifier = Modifier.fillMaxWidth()) {
            Text(localizedString(R.string.settings_use_official_relay, language))
        }
        Spacer(Modifier.height(12.dp))
        Text(localizedString(R.string.settings_custom_relays, language), style = MaterialTheme.typography.titleSmall)
        if (customRelays.isEmpty()) {
            Text(localizedString(R.string.settings_custom_relays_empty, language))
        } else {
            Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                customRelays.forEach { relay ->
                    Text("${relay.name} - ${relay.type.name}")
                    OutlinedButton(onClick = { viewModel.showRelayQr(relay) }, modifier = Modifier.fillMaxWidth()) {
                        Text("QR ${relay.name}")
                    }
                }
            }
        }
        Spacer(Modifier.height(8.dp))
        OutlinedTextField(
            value = customRelayName,
            onValueChange = { customRelayName = it },
            modifier = Modifier.fillMaxWidth(),
            label = { Text(localizedString(R.string.settings_custom_relay_name, language)) },
            singleLine = true,
        )
        Spacer(Modifier.height(8.dp))
        OutlinedTextField(
            value = customRelayUrl,
            onValueChange = { customRelayUrl = it },
            modifier = Modifier.fillMaxWidth(),
            label = { Text(localizedString(R.string.settings_custom_relay_url, language)) },
            singleLine = true,
        )
        Spacer(Modifier.height(8.dp))
        Button(
            onClick = { viewModel.addCustomRelay(customRelayName, customRelayUrl) },
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text(localizedString(R.string.settings_add_custom_relay, language))
        }
        Spacer(Modifier.height(8.dp))
        OutlinedTextField(
            value = relayQrInput,
            onValueChange = { relayQrInput = it },
            modifier = Modifier.fillMaxWidth(),
            label = { Text(localizedString(R.string.settings_scan_relay_qr, language)) },
            minLines = 2,
        )
        Spacer(Modifier.height(8.dp))
        OutlinedButton(
            onClick = {
                viewModel.importRelayQr(relayQrInput)
                relayQrInput = ""
            },
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text(localizedString(R.string.settings_scan_relay_qr, language))
        }
        Spacer(Modifier.height(8.dp))
        OutlinedButton(onClick = viewModel::useOfficialRelay, modifier = Modifier.fillMaxWidth()) {
            Text(localizedString(R.string.settings_return_official_relay, language))
        }
        Spacer(Modifier.height(12.dp))
        OutlinedButton(onClick = viewModel::checkServerStatus, modifier = Modifier.fillMaxWidth()) {
            Text(localizedString(R.string.settings_test_relay, language))
        }
        state.serverStatus?.let {
            Spacer(Modifier.height(8.dp))
            Text(settingsServerStatusText(it, language))
        }
        state.cryptoStatus?.let {
            Spacer(Modifier.height(16.dp))
            Text(localizedString(R.string.settings_crypto, language), style = MaterialTheme.typography.titleMedium)
            Spacer(Modifier.height(8.dp))
            Text(settingsCryptoStatusText(it, language))
            Spacer(Modifier.height(4.dp))
            Text(localizedString(R.string.settings_crypto_compare, language))
        }
        Spacer(Modifier.height(16.dp))
        Text(localizedString(R.string.profile_appearance, language), style = MaterialTheme.typography.titleMedium)
        Spacer(Modifier.height(4.dp))
        Text(localizedString(R.string.tab_profile, language), style = MaterialTheme.typography.bodySmall)
        Spacer(Modifier.height(16.dp))
        Text(localizedString(R.string.settings_notifications, language), style = MaterialTheme.typography.titleMedium)
        Spacer(Modifier.height(8.dp))
        Text(
            if (notificationsGranted) {
                localizedString(R.string.settings_notifications_allowed, language)
            } else {
                localizedString(R.string.settings_notifications_denied, language)
            },
        )
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU && !notificationsGranted) {
            Spacer(Modifier.height(8.dp))
            OutlinedButton(
                onClick = {
                    notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
                },
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(localizedString(R.string.settings_allow_notifications, language))
            }
        }
        Spacer(Modifier.height(12.dp))
        OutlinedButton(onClick = viewModel::checkUpdates, modifier = Modifier.fillMaxWidth()) {
            Text(localizedString(R.string.settings_check_apk_update, language))
        }
        state.updateStatus?.takeIf { it.isVisibleUpdateBanner() }?.let {
            Spacer(Modifier.height(8.dp))
            Text(settingsUpdateStatusText(it, language))
        }
        if (state.canDownloadSideloadUpdate) {
            Spacer(Modifier.height(8.dp))
            OutlinedButton(onClick = viewModel::downloadVerifiedUpdate, modifier = Modifier.fillMaxWidth()) {
                Text(localizedString(R.string.settings_download_verify_apk, language))
            }
        }
        state.verifiedApkPath?.let { apkPath ->
            Spacer(Modifier.height(8.dp))
            OutlinedButton(
                onClick = { openVerifiedApkInstaller(context, apkPath, language) },
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(localizedString(R.string.settings_open_android_installer, language))
            }
        }
        state.error?.let {
            Spacer(Modifier.height(8.dp))
            Text(it.displayMessage(fr), color = MaterialTheme.colorScheme.error)
        }
        Spacer(Modifier.height(16.dp))
        Text(localizedString(R.string.profile_data_storage, language), style = MaterialTheme.typography.titleMedium)
        Spacer(Modifier.height(4.dp))
        Text(localizedString(R.string.profile_bubbles_relays, language), style = MaterialTheme.typography.bodySmall)
        if (session != null) {
            Spacer(Modifier.height(24.dp))
            Text(
                localizedString(R.string.settings_delete_warning, language),
                color = MaterialTheme.colorScheme.error,
            )
            Spacer(Modifier.height(8.dp))
            OutlinedTextField(
                value = deleteConfirmation,
                onValueChange = { deleteConfirmation = it },
                modifier = Modifier.fillMaxWidth(),
                label = { Text(localizedString(R.string.settings_delete_label, language)) },
                singleLine = true,
            )
            Spacer(Modifier.height(8.dp))
            OutlinedButton(
                onClick = { viewModel.deleteAccount(deleteConfirmation) },
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(localizedString(R.string.settings_delete_account, language))
            }
        }
        Spacer(Modifier.height(12.dp))
        OutlinedButton(onClick = onBack, modifier = Modifier.fillMaxWidth()) {
            Text(localizedString(R.string.back_button, language))
        }
    }
}

private fun SettingsUpdateStatus.isVisibleUpdateBanner(): Boolean =
    this is SettingsUpdateStatus.Available ||
        this is SettingsUpdateStatus.ApkVerified

@Composable
private fun settingsServerStatusText(status: SettingsServerStatus, language: String): String =
    when (status) {
        SettingsServerStatus.Checking -> localizedString(R.string.settings_server_checking, language)
        is SettingsServerStatus.Reachable -> localizedString(
            R.string.settings_server_reachable,
            language,
            status.status,
            status.name,
            status.version,
        )
    }

@Composable
private fun settingsCryptoStatusText(status: SettingsCryptoStatus, language: String): String =
    when (status) {
        is SettingsCryptoStatus.Active -> localizedString(
            R.string.settings_crypto_active,
            language,
            status.fingerprint,
        )
        SettingsCryptoStatus.Unavailable -> localizedString(R.string.settings_crypto_unavailable, language)
    }

@Composable
private fun settingsUpdateStatusText(status: SettingsUpdateStatus, language: String): String =
    when (status) {
        SettingsUpdateStatus.Checking -> localizedString(R.string.settings_update_checking, language)
        SettingsUpdateStatus.NoVerifiedUpdateToDownload -> localizedString(
            R.string.settings_update_no_verified_download,
            language,
        )
        SettingsUpdateStatus.ExternalApkNotOffered -> localizedString(
            R.string.settings_update_external_not_offered,
            language,
        )
        SettingsUpdateStatus.Downloading -> localizedString(R.string.settings_update_downloading, language)
        SettingsUpdateStatus.DeletingAccount -> localizedString(R.string.settings_delete_in_progress, language)
        is SettingsUpdateStatus.ApkVerified -> localizedString(
            R.string.settings_update_apk_verified,
            language,
            status.fileName,
            status.sizeBytes,
            localizedString(
                if (status.signatureVerified) {
                    R.string.settings_update_signature_verified
                } else {
                    R.string.settings_update_signature_not_configured
                },
                language,
            ),
        )
        is SettingsUpdateStatus.Available -> settingsAvailableUpdateText(status, language)
    }

@Composable
private fun settingsAvailableUpdateText(status: SettingsUpdateStatus.Available, language: String): String {
    val release = status.release
    val lines = mutableListOf(
        localizedString(
            R.string.settings_update_install_source,
            language,
            settingsInstallSourceLabel(status.installSource, language),
        ),
        localizedString(
            R.string.settings_update_release_summary,
            language,
            release.latestVersionName,
            release.latestVersionCode,
            if (language == "en") release.releaseNotesEn else release.releaseNotesFr,
        ),
        localizedString(
            if (release.mandatory) {
                R.string.settings_update_mandatory
            } else {
                R.string.settings_update_optional
            },
            language,
        ),
        localizedString(R.string.settings_update_expected_sha256, language, release.sha256),
        localizedString(
            R.string.settings_update_manifest_signature,
            language,
            localizedString(
                if (release.hasSignature) {
                    R.string.settings_update_signature_present
                } else {
                    R.string.settings_update_signature_missing
                },
                language,
            ),
        ),
    )
    if (release.hasSignature && !status.signatureVerifierConfigured) {
        lines += localizedString(R.string.settings_update_signature_key_missing, language)
    }
    lines += localizedString(R.string.settings_update_automatic_install_no, language)
    if (status.installSource == com.enigma.securechat.data.repository.InstallSource.PLAY_STORE) {
        lines += localizedString(R.string.settings_update_play_store_no_external, language)
    }
    return lines.joinToString("\n")
}

@Composable
private fun settingsInstallSourceLabel(
    source: com.enigma.securechat.data.repository.InstallSource,
    language: String,
): String =
    localizedString(
        when (source) {
            com.enigma.securechat.data.repository.InstallSource.PLAY_STORE ->
                R.string.settings_install_source_play_store
            com.enigma.securechat.data.repository.InstallSource.FDROID ->
                R.string.settings_install_source_fdroid
            com.enigma.securechat.data.repository.InstallSource.OFFICIAL_WEBSITE ->
                R.string.settings_install_source_official_website
            com.enigma.securechat.data.repository.InstallSource.GITHUB_BUILD ->
                R.string.settings_install_source_github_build
            com.enigma.securechat.data.repository.InstallSource.SIDELOAD ->
                R.string.settings_install_source_sideload
            com.enigma.securechat.data.repository.InstallSource.UNKNOWN ->
                R.string.settings_install_source_unknown
        },
        language,
    )

private fun android.content.Context.notificationsGranted(): Boolean =
    Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU ||
        ContextCompat.checkSelfPermission(
            this,
            Manifest.permission.POST_NOTIFICATIONS,
        ) == PackageManager.PERMISSION_GRANTED

private fun openVerifiedApkInstaller(context: Context, apkPath: String, language: String) {
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O &&
        !context.packageManager.canRequestPackageInstalls()
    ) {
        runCatching {
            context.startActivity(
                Intent(
                    Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES,
                    Uri.parse("package:${context.packageName}"),
                ).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
            )
        }.onFailure {
            Toast.makeText(
                context,
                localizedText(context, R.string.settings_allow_install_source, language),
                Toast.LENGTH_LONG,
            ).show()
        }
        return
    }

    val apkFile = File(apkPath)
    if (!apkFile.exists()) {
        Toast.makeText(
            context,
            localizedText(context, R.string.settings_verified_apk_missing, language),
            Toast.LENGTH_LONG,
        ).show()
        return
    }

    val uri = FileProvider.getUriForFile(
        context,
        "${context.packageName}.fileprovider",
        apkFile,
    )
    val installIntent = Intent(Intent.ACTION_VIEW)
        .setDataAndType(uri, "application/vnd.android.package-archive")
        .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_ACTIVITY_NEW_TASK)
    try {
        context.startActivity(installIntent)
    } catch (_: ActivityNotFoundException) {
        Toast.makeText(
            context,
            localizedText(context, R.string.settings_no_apk_installer, language),
            Toast.LENGTH_LONG,
        ).show()
    }
}
