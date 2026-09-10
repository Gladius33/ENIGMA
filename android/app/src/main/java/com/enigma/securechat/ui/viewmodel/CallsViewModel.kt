package com.enigma.securechat.ui.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.enigma.securechat.calls.CallEngineEvent
import com.enigma.securechat.data.db.CallEventEntity
import com.enigma.securechat.data.repository.CallsRepository
import com.enigma.securechat.domain.model.AppResult
import com.enigma.securechat.network.dto.TurnCredentialsResponseDto
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import org.webrtc.VideoTrack

data class CallsUiState(
    val error: String? = null,
    val selectedCallId: String? = null,
    val turnSummary: String? = null,
    val mediaState: String = "idle",
    val microphoneEnabled: Boolean = true,
    val cameraEnabled: Boolean = true,
    val speakerEnabled: Boolean = true,
    val localVideoTrack: VideoTrack? = null,
    val remoteVideoTrack: VideoTrack? = null,
)

class CallsViewModel(
    private val repository: CallsRepository,
) : ViewModel() {
    val events: StateFlow<List<CallEventEntity>> = repository.observeEvents()
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyList())

    private val _state = MutableStateFlow(CallsUiState())
    val state = _state.asStateFlow()

    init {
        viewModelScope.launch {
            repository.mediaEvents.collect { event ->
                when (event) {
                    is CallEngineEvent.LocalIceCandidate -> repository.sendLocalIceCandidate(event)
                    is CallEngineEvent.StateChanged -> _state.value = _state.value.copy(
                        selectedCallId = event.callId,
                        mediaState = event.state,
                        error = null,
                    )
                    is CallEngineEvent.Error -> _state.value = _state.value.copy(
                        selectedCallId = event.callId,
                        error = event.message,
                    )
                    is CallEngineEvent.LocalVideoTrackReady -> _state.value = _state.value.copy(
                        selectedCallId = event.callId,
                        localVideoTrack = event.track,
                    )
                    is CallEngineEvent.RemoteVideoTrackReady -> _state.value = _state.value.copy(
                        selectedCallId = event.callId,
                        remoteVideoTrack = event.track,
                    )
                }
            }
        }
    }

    fun start(calleeUserId: String, video: Boolean = false) {
        if (calleeUserId.isBlank()) return
        viewModelScope.launch {
            _state.value = _state.value.copy(error = null, mediaState = "connecting")
            when (val result = repository.startCall(calleeUserId.trim(), video = video)) {
                is AppResult.Ok -> _state.value = _state.value.copy(
                    error = null,
                    selectedCallId = result.value.callId,
                    mediaState = result.value.state,
                    cameraEnabled = video,
                )
                is AppResult.Err -> _state.value = _state.value.copy(
                    error = result.error.message,
                    mediaState = "failed",
                )
            }
        }
    }

    fun select(callId: String) {
        _state.value = _state.value.copy(selectedCallId = callId.ifBlank { null }, error = null)
    }

    fun accept(callId: String) = runCall(callId) { repository.accept(it) }

    fun reject(callId: String) = runCall(callId) { repository.reject(it) }

    fun hangup(callId: String) = runCall(callId) { repository.hangup(it) }

    fun syncSignaling(callId: String) = runCall(callId) { repository.syncSignaling(it) }

    fun fetchIce(callId: String) = runCall(callId) { repository.fetchIceCandidates(it) }

    fun toggleMicrophone() {
        val callId = state.value.selectedCallId ?: return
        val next = !state.value.microphoneEnabled
        repository.setMicrophoneEnabled(callId, next)
        _state.value = _state.value.copy(microphoneEnabled = next)
    }

    fun toggleCamera() {
        val callId = state.value.selectedCallId ?: return
        val next = !state.value.cameraEnabled
        repository.setCameraEnabled(callId, next)
        _state.value = _state.value.copy(cameraEnabled = next)
    }

    fun toggleSpeaker() {
        val next = !state.value.speakerEnabled
        repository.setSpeakerEnabled(next)
        _state.value = _state.value.copy(speakerEnabled = next)
    }

    fun permissionDenied(video: Boolean) {
        _state.value = _state.value.copy(
            error = if (video) {
                "Permission micro/caméra refusée"
            } else {
                "Permission micro refusée"
            },
            mediaState = "failed",
        )
    }

    fun loadTurn() {
        viewModelScope.launch {
            when (val result = repository.turnCredentials()) {
                is AppResult.Ok -> _state.value = _state.value.copy(
                    error = null,
                    turnSummary = result.value.safeSummary(),
                )
                is AppResult.Err -> _state.value = _state.value.copy(error = result.error.message)
            }
        }
    }

    private fun runCall(callId: String, action: suspend (String) -> AppResult<Unit>) {
        val normalized = callId.trim()
        if (normalized.isBlank()) return
        viewModelScope.launch {
            _state.value = _state.value.copy(selectedCallId = normalized)
            when (val result = action(normalized)) {
                is AppResult.Ok -> _state.value = _state.value.copy(error = null)
                is AppResult.Err -> _state.value = _state.value.copy(error = result.error.message)
            }
        }
    }

    private fun TurnCredentialsResponseDto.safeSummary(): String =
        "${uris.joinToString()} · ttl ${ttlSeconds}s · realm $realm"
}
