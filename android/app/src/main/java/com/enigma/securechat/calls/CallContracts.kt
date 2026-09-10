package com.enigma.securechat.calls

import kotlinx.coroutines.flow.Flow
import org.webrtc.VideoTrack

data class CallSession(
    val callId: String,
    val callKind: String,
    val state: String,
)

data class CallIceServer(
    val urls: List<String>,
    val username: String? = null,
    val credential: String? = null,
)

data class CallMediaConfig(
    val callId: String,
    val video: Boolean,
    val iceServers: List<CallIceServer>,
)

data class CallIceCandidate(
    val sdpMid: String?,
    val sdpMLineIndex: Int,
    val candidate: String,
)

sealed interface CallEngineEvent {
    data class LocalIceCandidate(
        val callId: String,
        val candidate: CallIceCandidate,
    ) : CallEngineEvent

    data class StateChanged(
        val callId: String,
        val state: String,
    ) : CallEngineEvent

    data class Error(
        val callId: String,
        val message: String,
    ) : CallEngineEvent

    data class LocalVideoTrackReady(
        val callId: String,
        val track: VideoTrack,
    ) : CallEngineEvent

    data class RemoteVideoTrackReady(
        val callId: String,
        val track: VideoTrack,
    ) : CallEngineEvent
}

interface CallEngine {
    val events: Flow<CallEngineEvent>

    suspend fun startOutgoing(config: CallMediaConfig): String

    suspend fun acceptIncoming(config: CallMediaConfig, remoteOfferSdp: String): String

    suspend fun setRemoteAnswer(callId: String, remoteAnswerSdp: String)

    suspend fun addRemoteIceCandidate(callId: String, candidate: CallIceCandidate)

    fun setMicrophoneEnabled(callId: String, enabled: Boolean)

    fun setCameraEnabled(callId: String, enabled: Boolean)

    fun setSpeakerEnabled(enabled: Boolean)

    fun release(callId: String)

    fun dispose()
}
