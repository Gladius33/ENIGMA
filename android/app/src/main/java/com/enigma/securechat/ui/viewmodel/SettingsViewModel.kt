package com.enigma.securechat.ui.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.enigma.securechat.BuildConfig
import com.enigma.securechat.crypto.CryptoEngine
import com.enigma.securechat.crypto.SafetyNumber
import com.enigma.securechat.data.repository.AndroidReleaseInfo
import com.enigma.securechat.data.repository.AndroidUpdateStatus
import com.enigma.securechat.data.repository.IdentityRepository
import com.enigma.securechat.data.repository.InstallSource
import com.enigma.securechat.data.repository.RelayProfile
import com.enigma.securechat.data.repository.RelayRepository
import com.enigma.securechat.data.repository.ServerStatusRepository
import com.enigma.securechat.data.repository.UpdateRepository
import com.enigma.securechat.data.repository.allowsInternalUpdater
import com.enigma.securechat.domain.model.AppResult
import com.enigma.securechat.domain.model.UserSession
import com.enigma.securechat.domain.model.UserVisibleError
import com.enigma.securechat.network.ActiveRelayEndpoint
import com.enigma.securechat.network.ChatApiService
import com.enigma.securechat.network.dto.PlanDto
import com.enigma.securechat.network.dto.SupportConfigDto
import com.enigma.securechat.network.dto.UsageDto
import com.enigma.securechat.network.dto.OfficialAnnouncementDto
import com.enigma.securechat.network.OfficialRelayResolver
import com.enigma.securechat.qr.EnigmaQrCode
import com.enigma.securechat.qr.EnigmaQrPayloads
import com.enigma.securechat.qr.ParsedEnigmaQrPayload
import com.enigma.securechat.qr.RelayQrPayload
import com.enigma.securechat.storage.SecureSessionStore
import com.enigma.securechat.storage.ServerSettingsStore
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch

data class SettingsUiState(
    val serverStatus: SettingsServerStatus? = null,
    val updateStatus: SettingsUpdateStatus? = null,
    val availableRelease: AndroidReleaseInfo? = null,
    val canDownloadSideloadUpdate: Boolean = false,
    val verifiedApkPath: String? = null,
    val cryptoStatus: SettingsCryptoStatus? = null,
    val error: UserVisibleError? = null,
    val deleted: Boolean = false,
    val plan: PlanDto? = null,
    val usage: UsageDto? = null,
    val support: SupportConfigDto? = null,
    val announcements: List<OfficialAnnouncementDto> = emptyList(),
)

sealed interface SettingsServerStatus {
    data object Checking : SettingsServerStatus
    data class Reachable(val status: String, val name: String, val version: String) : SettingsServerStatus
}

sealed interface SettingsCryptoStatus {
    data class Active(val fingerprint: String) : SettingsCryptoStatus
    data object Unavailable : SettingsCryptoStatus
}

sealed interface SettingsUpdateStatus {
    data object Checking : SettingsUpdateStatus
    data class Available(
        val installSource: InstallSource,
        val release: AndroidReleaseInfo,
        val signatureVerifierConfigured: Boolean,
    ) : SettingsUpdateStatus
    data object NoVerifiedUpdateToDownload : SettingsUpdateStatus
    data object ExternalApkNotOffered : SettingsUpdateStatus
    data object Downloading : SettingsUpdateStatus
    data class ApkVerified(
        val fileName: String,
        val sizeBytes: Long,
        val signatureVerified: Boolean,
    ) : SettingsUpdateStatus
    data object DeletingAccount : SettingsUpdateStatus
}

class SettingsViewModel(
    private val serverSettingsStore: ServerSettingsStore,
    private val serverStatusRepository: ServerStatusRepository,
    private val updateRepository: UpdateRepository,
    private val relayRepository: RelayRepository,
    private val identityRepository: IdentityRepository,
    private val sessionStore: SecureSessionStore,
    private val cryptoEngine: CryptoEngine,
    activeRelayEndpoint: StateFlow<ActiveRelayEndpoint>,
    private val api: ChatApiService,
) : ViewModel() {
    val activeEndpointDebug: StateFlow<String> = activeRelayEndpoint
        .map { it.displayBaseUrl }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), activeRelayEndpoint.value.displayBaseUrl)
    val language: StateFlow<String> = serverSettingsStore.language
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), "fr")
    val session: StateFlow<UserSession?> = sessionStore.session
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), null)
    val customRelays: StateFlow<List<RelayProfile>> = relayRepository.customRelays
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyList())
    val relays: StateFlow<List<RelayProfile>> = relayRepository.relays
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyList())
    val defaultRelayId: StateFlow<String> = relayRepository.defaultRelayId
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), OfficialRelayResolver.OFFICIAL_RELAY_ID)

    private val _state = MutableStateFlow(SettingsUiState())
    val state: StateFlow<SettingsUiState> = _state.asStateFlow()
    private val _relayQr = MutableStateFlow<EnigmaQrCode?>(null)
    val relayQr: StateFlow<EnigmaQrCode?> = _relayQr.asStateFlow()
    val appVersion: String = "${BuildConfig.VERSION_NAME} (${BuildConfig.VERSION_CODE})"

    fun loadRelays() {
        viewModelScope.launch { relayRepository.ensureDefaults() }
    }

    fun loadBusiness() { viewModelScope.launch {
        val support = runCatching { api.supportConfig() }.getOrNull()
        val plan = if (session.value != null) runCatching { api.myPlan() }.getOrNull() else null
        val usage = if (session.value != null) runCatching { api.myUsage() }.getOrNull() else null
        val announcements = if (session.value != null) runCatching { api.officialAnnouncements().announcements }.getOrDefault(emptyList()) else emptyList()
        _state.value = _state.value.copy(support=support, plan=plan, usage=usage, announcements=announcements)
    } }
    fun readAnnouncement(id:String) { viewModelScope.launch { runCatching { api.readOfficialAnnouncement(id) }; loadBusiness() } }
    fun dismissAnnouncement(id:String) { viewModelScope.launch { runCatching { api.dismissOfficialAnnouncement(id) }; loadBusiness() } }

    fun saveLanguage(value: String) {
        viewModelScope.launch { serverSettingsStore.saveLanguage(value) }
    }

    fun addCustomRelay(name: String, url: String) {
        viewModelScope.launch {
            runCatching {
                relayRepository.addCustomRelay(name, url)
            }.onSuccess {
                _state.value = _state.value.copy(error = null)
            }.onFailure {
                _state.value = _state.value.copy(
                    error = UserVisibleError(
                        message = "Invalid relay URL",
                        errorCode = "RELAY_URL_MISSING_SCHEME",
                    ),
                )
            }
        }
    }

    fun useOfficialRelay() {
        viewModelScope.launch {
            relayRepository.useOfficialRelay()
            _state.value = _state.value.copy(error = null)
        }
    }

    fun showRelayQr(relay: RelayProfile) {
        _relayQr.value = EnigmaQrPayloads.relay(
            RelayQrPayload(
                name = relay.name,
                url = relay.url,
                public_key = relay.publicKey,
                signature = null,
            ),
        )
    }

    fun importRelayQr(input: String) {
        viewModelScope.launch {
            val payload = EnigmaQrPayloads.parse(input) as? ParsedEnigmaQrPayload.Relay
            if (payload == null) {
                _state.value = _state.value.copy(error = UserVisibleError("QR relais invalide"))
                return@launch
            }
            addCustomRelay(payload.payload.name, payload.payload.url)
        }
    }

    fun loadCryptoStatus() {
        viewModelScope.launch {
            _state.value = _state.value.copy(
                cryptoStatus = runCatching {
                    val fingerprint = SafetyNumber.localFingerprint(
                        cryptoEngine.ensureIdentity().identityPublicKey,
                    )
                    SettingsCryptoStatus.Active(fingerprint)
                }.getOrElse {
                    SettingsCryptoStatus.Unavailable
                },
            )
        }
    }

    fun checkServerStatus() {
        viewModelScope.launch {
            _state.value = _state.value.copy(
                serverStatus = SettingsServerStatus.Checking,
                error = null,
            )
            _state.value = when (val result = serverStatusRepository.check()) {
                is AppResult.Ok -> _state.value.copy(
                    serverStatus = SettingsServerStatus.Reachable(
                        status = result.value.status,
                        name = result.value.name,
                        version = result.value.version,
                    ),
                    error = null,
                )

                is AppResult.Err -> _state.value.copy(error = result.error)
            }
        }
    }

    fun checkUpdates() {
        viewModelScope.launch {
            _state.value = _state.value.copy(
                updateStatus = SettingsUpdateStatus.Checking,
                error = null,
            )
            _state.value = when (val result = updateRepository.checkAndroidRelease()) {
                is AppResult.Ok -> _state.value.copy(
                    updateStatus = result.value.toUiStatus(),
                    availableRelease = result.value.release,
                    canDownloadSideloadUpdate = result.value.canOfferInternalDownload(),
                    verifiedApkPath = null,
                    error = null,
                )

                is AppResult.Err -> {
                    if (result.error.errorCode == "RELEASE_NOT_CONFIGURED") {
                        _state.value.copy(updateStatus = null, error = null)
                    } else {
                        _state.value.copy(error = result.error)
                    }
                }
            }
        }
    }

    fun downloadVerifiedUpdate() {
        viewModelScope.launch {
            val release = state.value.availableRelease ?: run {
                _state.value = _state.value.copy(
                    updateStatus = SettingsUpdateStatus.NoVerifiedUpdateToDownload,
                )
                return@launch
            }
            if (!state.value.canDownloadSideloadUpdate) {
                _state.value = _state.value.copy(
                    updateStatus = SettingsUpdateStatus.ExternalApkNotOffered,
                )
                return@launch
            }
            _state.value = _state.value.copy(
                updateStatus = SettingsUpdateStatus.Downloading,
                error = null,
            )
            _state.value = when (val result = updateRepository.downloadAndVerify(release)) {
                is AppResult.Ok -> _state.value.copy(
                    updateStatus = SettingsUpdateStatus.ApkVerified(
                        fileName = result.value.file.name,
                        sizeBytes = result.value.sizeBytes,
                        signatureVerified = result.value.signatureVerified,
                    ),
                    verifiedApkPath = result.value.file.absolutePath,
                    error = null,
                )

                is AppResult.Err -> _state.value.copy(error = result.error)
            }
        }
    }

    fun deleteAccount(confirmText: String) {
        viewModelScope.launch {
            if (confirmText != "SUPPRIMER" && confirmText != "DELETE") {
                _state.value = _state.value.copy(
                    error = UserVisibleError(
                        message = "Delete confirmation mismatch",
                        errorCode = "DELETE_CONFIRMATION_MISMATCH",
                    ),
                )
                return@launch
            }
            _state.value = _state.value.copy(
                updateStatus = SettingsUpdateStatus.DeletingAccount,
                error = null,
            )
            _state.value = when (val result = identityRepository.deleteMe()) {
                is AppResult.Ok -> _state.value.copy(deleted = true)
                is AppResult.Err -> _state.value.copy(error = result.error)
            }
        }
    }

    private fun AndroidUpdateStatus.canOfferInternalDownload(): Boolean {
        val candidate = release ?: return false
        if (!installSource.allowsInternalUpdater()) return false
        return when (installSource) {
            InstallSource.SIDELOAD,
            InstallSource.UNKNOWN -> candidate.hasSignature && signatureVerifierConfigured
            InstallSource.OFFICIAL_WEBSITE,
            InstallSource.GITHUB_BUILD -> candidate.hasSignature != true || signatureVerifierConfigured
            InstallSource.PLAY_STORE,
            InstallSource.FDROID -> false
        }
    }

    private fun AndroidUpdateStatus.toUiStatus(): SettingsUpdateStatus? =
        release?.let {
            SettingsUpdateStatus.Available(
                installSource = installSource,
                release = it,
                signatureVerifierConfigured = signatureVerifierConfigured,
            )
        }
}
