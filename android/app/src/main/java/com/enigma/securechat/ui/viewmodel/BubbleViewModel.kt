package com.enigma.securechat.ui.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.enigma.securechat.data.db.BubbleEntity
import com.enigma.securechat.data.db.BubbleIndexPolicy
import com.enigma.securechat.data.db.BubbleJoinPolicy
import com.enigma.securechat.data.db.BubbleMode
import com.enigma.securechat.data.db.BubbleRelayEntity
import com.enigma.securechat.data.db.BubbleVisibility
import com.enigma.securechat.data.repository.ActiveBubbleContext
import com.enigma.securechat.data.repository.BubbleRepository
import com.enigma.securechat.data.repository.RelayPrivateSessionStatus
import com.enigma.securechat.data.repository.RelayProfile
import com.enigma.securechat.data.repository.RelayRepository
import com.enigma.securechat.data.repository.RelaySessionRepository
import com.enigma.securechat.data.repository.ServerStatusRepository
import com.enigma.securechat.domain.model.AppResult
import com.enigma.securechat.domain.model.UserVisibleError
import com.enigma.securechat.qr.EnigmaQrPayloads
import com.enigma.securechat.qr.ParsedEnigmaQrPayload
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch

data class BubblesUiState(
    val bubbles: List<BubbleEntity> = emptyList(),
    val customRelays: List<RelayProfile> = emptyList(),
    val activeContext: ActiveBubbleContext? = null,
    val selectedBubbleRelays: List<BubbleRelayEntity> = emptyList(),
    val relayTestStatus: BubbleRelayTestStatus? = null,
    val relaySessionStatus: RelayPrivateSessionStatus? = null,
    val error: UserVisibleError? = null,
)

private data class BubbleTransientState(
    val relayTestStatus: BubbleRelayTestStatus? = null,
    val relaySessionStatus: RelayPrivateSessionStatus? = null,
    val error: UserVisibleError? = null,
)

sealed interface BubbleRelayTestStatus {
    data object Checking : BubbleRelayTestStatus
    data class Reachable(
        val status: String,
        val name: String,
        val version: String,
    ) : BubbleRelayTestStatus
}

class BubbleViewModel(
    private val bubbleRepository: BubbleRepository,
    private val relayRepository: RelayRepository,
    private val relaySessionRepository: RelaySessionRepository,
    private val serverStatusRepository: ServerStatusRepository,
) : ViewModel() {
    private val _error = MutableStateFlow<UserVisibleError?>(null)
    val error: StateFlow<UserVisibleError?> = _error.asStateFlow()
    private val _relayTestStatus = MutableStateFlow<BubbleRelayTestStatus?>(null)
    private val _relaySessionStatus = MutableStateFlow<RelayPrivateSessionStatus?>(null)
    private val transientState = combine(
        _relayTestStatus,
        _relaySessionStatus,
        _error,
    ) { relayTestStatus, relaySessionStatus, error ->
        BubbleTransientState(
            relayTestStatus = relayTestStatus,
            relaySessionStatus = relaySessionStatus,
            error = error,
        )
    }
    val state: StateFlow<BubblesUiState> = combine(
        bubbleRepository.bubbles,
        relayRepository.customRelays,
        bubbleRepository.activeContext,
        transientState,
    ) { bubbles, customRelays, activeContext, transient ->
        BubblesUiState(
            bubbles = bubbles,
            customRelays = customRelays,
            activeContext = activeContext,
            relayTestStatus = transient.relayTestStatus,
            relaySessionStatus = transient.relaySessionStatus,
            error = transient.error,
        )
    }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), BubblesUiState())

    fun load() {
        viewModelScope.launch { bubbleRepository.ensureDefaults() }
    }

    fun activateBubble(bubbleId: String) {
        viewModelScope.launch { bubbleRepository.activateBubble(bubbleId) }
    }

    fun syncRemote() {
        viewModelScope.launch {
            when (val result = bubbleRepository.syncBubbles()) {
                is AppResult.Ok -> _error.value = null
                is AppResult.Err -> _error.value = result.error
            }
        }
    }

    fun attachRelayToActiveBubble(relayId: String, fallbackAllowed: Boolean) {
        viewModelScope.launch {
            val context = state.value.activeContext ?: return@launch
            val bubbleId = context.bubble.id
            val effectiveFallback = fallbackAllowed && context.bubble.mode != BubbleMode.PRIVATE_ISOLATED.name
            runCatching {
                bubbleRepository.attachRelayToBubble(bubbleId, relayId, effectiveFallback)
            }.onSuccess {
                _error.value = null
                _relayTestStatus.value = null
            }.onFailure {
                _error.value = UserVisibleError(it.message ?: "Relay not attached")
            }
        }
    }

    fun addAndAttachRelayToActiveBubble(name: String, url: String, fallbackAllowed: Boolean) {
        viewModelScope.launch {
            val context = state.value.activeContext ?: return@launch
            val effectiveFallback = fallbackAllowed && context.bubble.mode != BubbleMode.PRIVATE_ISOLATED.name
            runCatching {
                val relay = relayRepository.addCustomRelay(name, url)
                bubbleRepository.attachRelayToBubble(context.bubble.id, relay.id, effectiveFallback)
            }.onSuccess {
                _error.value = null
                _relayTestStatus.value = null
            }.onFailure {
                _error.value = UserVisibleError(it.message ?: "Relais non attaché")
            }
        }
    }

    fun importRelayQrToActiveBubble(input: String, fallbackAllowed: Boolean) {
        viewModelScope.launch {
            val context = state.value.activeContext ?: return@launch
            val payload = EnigmaQrPayloads.parse(input) as? ParsedEnigmaQrPayload.Relay
            if (payload == null) {
                _error.value = UserVisibleError("QR relais invalide")
                return@launch
            }
            val effectiveFallback = fallbackAllowed && context.bubble.mode != BubbleMode.PRIVATE_ISOLATED.name
            runCatching {
                val relay = relayRepository.addCustomRelay(
                    name = payload.payload.name,
                    url = payload.payload.url,
                )
                bubbleRepository.attachRelayToBubble(context.bubble.id, relay.id, effectiveFallback)
            }.onSuccess {
                _error.value = null
                _relayTestStatus.value = null
            }.onFailure {
                _error.value = UserVisibleError(it.message ?: "QR relais non attaché")
            }
        }
    }

    fun useOfficialRelayForActiveBubble() {
        viewModelScope.launch {
            val context = state.value.activeContext ?: return@launch
            if (context.bubble.mode == BubbleMode.PRIVATE_ISOLATED.name) {
                _error.value = UserVisibleError("Private Isolated exige un relais privé")
                return@launch
            }
            val bubbleId = context.bubble.id
            bubbleRepository.useOfficialRelayForBubble(bubbleId)
            _error.value = null
            _relayTestStatus.value = null
        }
    }

    fun testActiveRelay() {
        viewModelScope.launch {
            _relayTestStatus.value = BubbleRelayTestStatus.Checking
            _error.value = null
            when (val result = serverStatusRepository.check()) {
                is AppResult.Ok -> _relayTestStatus.value = BubbleRelayTestStatus.Reachable(
                    status = result.value.status,
                    name = result.value.name,
                    version = result.value.version,
                )
                is AppResult.Err -> {
                    _relayTestStatus.value = null
                    _error.value = result.error
                }
            }
        }
    }

    fun signInActivePrivateRelay(publicId: String, password: String, deviceName: String) {
        if (publicId.isBlank() || password.isBlank()) return
        viewModelScope.launch {
            when (
                val result = relaySessionRepository.signInActivePrivateRelay(
                    publicId = publicId,
                    password = password,
                    deviceName = deviceName,
                )
            ) {
                is AppResult.Ok -> {
                    _relaySessionStatus.value = result.value
                    _error.value = null
                }
                is AppResult.Err -> _error.value = result.error
            }
        }
    }

    fun signOutActivePrivateRelay() {
        viewModelScope.launch {
            when (val result = relaySessionRepository.signOutActivePrivateRelay()) {
                is AppResult.Ok -> {
                    _relaySessionStatus.value = null
                    _error.value = null
                }
                is AppResult.Err -> _error.value = result.error
            }
        }
    }

    fun createPrivateConnectedBubble() {
        createRemoteBubble(
            name = "Private Connected Bubble",
            mode = BubbleMode.PRIVATE_CONNECTED,
            visibility = BubbleVisibility.PRIVATE,
            joinPolicy = BubbleJoinPolicy.INVITE_ONLY,
            indexPolicy = BubbleIndexPolicy.PRIVATE_ONLY,
        )
    }

    fun createPrivateIsolatedBubble() {
        createRemoteBubble(
            name = "Private Isolated Bubble",
            mode = BubbleMode.PRIVATE_ISOLATED,
            visibility = BubbleVisibility.SECRET,
            joinPolicy = BubbleJoinPolicy.INVITE_ONLY,
            indexPolicy = BubbleIndexPolicy.INDEX_FORBIDDEN,
        )
    }

    fun importBubbleInviteQr(input: String) {
        viewModelScope.launch {
            val payload = EnigmaQrPayloads.parse(input) as? ParsedEnigmaQrPayload.BubbleInvite
            if (payload == null) {
                _error.value = UserVisibleError("QR invitation bulle invalide")
                return@launch
            }
            bubbleRepository.seedBubbleFromInvite(
                bubbleId = payload.payload.bubble_id,
                name = payload.payload.bubble_name,
                mode = payload.payload.mode,
                relayHint = payload.payload.relay_hint,
            )
            _error.value = null
        }
    }

    private fun createRemoteBubble(
        name: String,
        mode: BubbleMode,
        visibility: BubbleVisibility,
        joinPolicy: BubbleJoinPolicy,
        indexPolicy: BubbleIndexPolicy,
    ) {
        viewModelScope.launch {
            when (
                val result = bubbleRepository.createBubbleRemote(
                    name = name,
                    mode = mode,
                    visibility = visibility,
                    joinPolicy = joinPolicy,
                    indexPolicy = indexPolicy,
                )
            ) {
                is AppResult.Ok -> {
                    bubbleRepository.activateBubble(result.value.id)
                    _error.value = null
                }
                is AppResult.Err -> _error.value = result.error
            }
        }
    }
}
