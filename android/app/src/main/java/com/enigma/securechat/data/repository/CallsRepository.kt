package com.enigma.securechat.data.repository

import com.enigma.securechat.calls.CallEngine
import com.enigma.securechat.calls.CallEngineEvent
import com.enigma.securechat.calls.CallIceCandidate
import com.enigma.securechat.calls.CallIceServer
import com.enigma.securechat.calls.CallMediaConfig
import com.enigma.securechat.calls.CallSession
import com.enigma.securechat.calls.CallSignalingCodec
import com.enigma.securechat.data.db.CallEventDao
import com.enigma.securechat.data.db.CallEventEntity
import com.enigma.securechat.domain.model.AppResult
import com.enigma.securechat.network.RelayScopedApiProvider
import com.enigma.securechat.network.dto.CreateCallRequestDto
import com.enigma.securechat.network.dto.IceCandidatesRequestDto
import com.enigma.securechat.network.dto.SdpRequestDto
import com.enigma.securechat.network.dto.SignalingEventDto
import com.enigma.securechat.network.dto.TurnCredentialsResponseDto
import com.enigma.securechat.network.dto.WsEventDto
import com.enigma.securechat.network.toUserVisibleError
import com.enigma.securechat.storage.RelaySettingsStore
import java.time.Instant
import java.util.Collections
import java.util.concurrent.ConcurrentHashMap
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flatMapLatest
import kotlinx.coroutines.flow.flowOf

class CallsRepository(
    private val apiProvider: RelayScopedApiProvider,
    private val callEventDao: CallEventDao,
    private val callEngine: CallEngine,
    private val activeBubbleId: Flow<String> = flowOf(RelaySettingsStore.DEFAULT_MAIN_BUBBLE_ID),
    private val activeBubbleIdProvider: suspend () -> String = {
        RelaySettingsStore.DEFAULT_MAIN_BUBBLE_ID
    },
) {
    private val processedSignalingEvents = Collections.newSetFromMap(ConcurrentHashMap<String, Boolean>())

    val mediaEvents: Flow<CallEngineEvent> = callEngine.events

    @OptIn(ExperimentalCoroutinesApi::class)
    fun observeEvents(): Flow<List<CallEventEntity>> =
        activeBubbleId.flatMapLatest { bubbleId -> callEventDao.observeCallEvents(bubbleId) }

    suspend fun startCall(calleeUserId: String, video: Boolean = false): AppResult<CallSession> = runCatching {
        val bubbleId = activeBubbleIdProvider()
        val turn = fetchTurnCredentials()
        val response = apiProvider.withActiveApi {
            it.createCall(
                CreateCallRequestDto(
                    bubbleId = bubbleId,
                    calleeUserId = calleeUserId,
                    callKind = if (video) "video" else "audio",
                ),
            )
        }
        callEventDao.upsert(
            CallEventEntity(
                id = response.id,
                bubbleId = response.bubbleId,
                callId = response.id,
                callKind = response.callKind,
                state = response.state,
                eventKind = "created",
                createdAt = response.createdAt,
            ),
        )

        val offer = callEngine.startOutgoing(
            CallMediaConfig(
                callId = response.id,
                video = video,
                iceServers = turn.toIceServers(),
            ),
        )
        apiProvider.withActiveApi {
            it.callOffer(response.id, SdpRequestDto(bubbleId = response.bubbleId, sdp = offer))
        }
        upsertLocalEvent(response.id, response.bubbleId, response.callKind, "connecting", "offer")
        CallSession(response.id, response.callKind, "connecting")
    }.fold(
        onSuccess = { AppResult.Ok(it) },
        onFailure = { AppResult.Err(it.toUserVisibleError("Appel WebRTC non créé")) },
    )

    suspend fun accept(callId: String): AppResult<Unit> = runCatching {
        val remoteEvents = fetchSignalingEvents(callId)
        val offer = remoteEvents.lastOrNull { it.eventKind == "offer" && !it.payload.isNullOrBlank() }
            ?: error("Offer WebRTC distante introuvable")
        val existing = callEventDao.latestForCall(callId)
        val bubbleId = existing?.bubbleId ?: offer.bubbleId
        val video = existing?.callKind == "video" || offer.payload.hasVideoMedia()
        val turn = fetchTurnCredentials()

        processedSignalingEvents.add(offer.id)
        callEventDao.upsert(
            CallEventEntity(
                id = offer.id,
                bubbleId = offer.bubbleId,
                callId = callId,
                callKind = if (video) "video" else "audio",
                state = "ringing",
                eventKind = "offer",
                createdAt = offer.createdAt,
            ),
        )
        apiProvider.withActiveApi { it.acceptCall(callId) }
        val answer = callEngine.acceptIncoming(
            CallMediaConfig(
                callId = callId,
                video = video,
                iceServers = turn.toIceServers(),
            ),
            remoteOfferSdp = requireNotNull(offer.payload),
        )
        apiProvider.withActiveApi { it.callAnswer(callId, SdpRequestDto(bubbleId = bubbleId, sdp = answer)) }
        upsertLocalEvent(callId, bubbleId, if (video) "video" else "audio", "connecting", "accepted")
        upsertLocalEvent(callId, bubbleId, if (video) "video" else "audio", "connecting", "answer")
        processRemoteSignaling(callId, remoteEvents.filterNot { it.id == offer.id })
    }.fold(
        onSuccess = { AppResult.Ok(Unit) },
        onFailure = { AppResult.Err(it.toUserVisibleError("Appel WebRTC non accepté")) },
    )

    suspend fun reject(callId: String): AppResult<Unit> = callTransition(callId, "rejected") {
        apiProvider.withActiveApi { it.rejectCall(callId) }
        callEngine.release(callId)
        Unit
    }

    suspend fun hangup(callId: String): AppResult<Unit> = callTransition(callId, "ended") {
        apiProvider.withActiveApi { it.hangupCall(callId) }
        callEngine.release(callId)
        Unit
    }

    suspend fun sendLocalIceCandidate(event: CallEngineEvent.LocalIceCandidate): AppResult<Unit> =
        addIceCandidates(
            callId = event.callId,
            candidates = listOf(CallSignalingCodec.encodeIceCandidate(event.candidate)),
        )

    suspend fun sendOffer(callId: String, sdp: String): AppResult<Unit> =
        sendSignalingPayload(callId, eventKind = "offer") { bubbleId ->
            apiProvider.withActiveApi { it.callOffer(callId, SdpRequestDto(bubbleId = bubbleId, sdp = sdp)) }
        }

    suspend fun sendAnswer(callId: String, sdp: String): AppResult<Unit> =
        sendSignalingPayload(callId, eventKind = "answer") { bubbleId ->
            apiProvider.withActiveApi { it.callAnswer(callId, SdpRequestDto(bubbleId = bubbleId, sdp = sdp)) }
        }

    suspend fun addIceCandidates(callId: String, candidates: List<String>): AppResult<Unit> =
        sendSignalingPayload(callId, eventKind = "ice") { bubbleId ->
            apiProvider.withActiveApi {
                it.addIceCandidates(
                    callId,
                    IceCandidatesRequestDto(
                        bubbleId = bubbleId,
                        candidates = candidates.filter { candidate -> candidate.isNotBlank() },
                    ),
                )
            }
        }

    suspend fun syncSignaling(callId: String): AppResult<Unit> = runCatching {
        processRemoteSignaling(callId, fetchSignalingEvents(callId))
    }.fold(
        onSuccess = { AppResult.Ok(Unit) },
        onFailure = { AppResult.Err(it.toUserVisibleError("Signal d'appel non synchronisé")) },
    )

    suspend fun handleRealtimeEvent(event: WsEventDto): AppResult<Unit> = runCatching {
        val callId = event.callId ?: return@runCatching
        when (event.type) {
            "incoming_call" -> {
                val bubbleId = event.bubbleId ?: activeBubbleIdProvider()
                callEventDao.upsert(
                    CallEventEntity(
                        id = "$callId-incoming",
                        bubbleId = bubbleId,
                        callId = callId,
                        callKind = "audio",
                        state = "ringing",
                        eventKind = "incoming_call",
                        createdAt = Instant.now().toString(),
                    ),
                )
            }
            "call_signaling" -> processRemoteSignaling(callId, fetchSignalingEvents(callId))
        }
    }.fold(
        onSuccess = { AppResult.Ok(Unit) },
        onFailure = { AppResult.Err(it.toUserVisibleError("Événement d'appel non appliqué")) },
    )

    suspend fun fetchIceCandidates(callId: String): AppResult<Unit> = runCatching {
        val response = apiProvider.withActiveApi { it.iceCandidates(callId) }
        processRemoteSignaling(callId, response.candidates)
        if (response.candidates.isEmpty()) {
            val call = callEventDao.latestForCall(callId)
            callEventDao.upsert(
                CallEventEntity(
                    id = "$callId-ice-empty-${System.currentTimeMillis()}",
                    bubbleId = call?.bubbleId ?: activeBubbleIdProvider(),
                    callId = callId,
                    callKind = call?.callKind ?: "audio",
                    state = call?.state ?: "signaling",
                    eventKind = "ice_checked",
                    createdAt = Instant.now().toString(),
                ),
            )
        }
    }.fold(
        onSuccess = { AppResult.Ok(Unit) },
        onFailure = { AppResult.Err(it.toUserVisibleError("ICE indisponible")) },
    )

    suspend fun turnCredentials(): AppResult<TurnCredentialsResponseDto> = runCatching {
        fetchTurnCredentials()
    }.fold(
        onSuccess = { AppResult.Ok(it) },
        onFailure = { AppResult.Err(it.toUserVisibleError("TURN indisponible")) },
    )

    fun setMicrophoneEnabled(callId: String, enabled: Boolean) {
        callEngine.setMicrophoneEnabled(callId, enabled)
    }

    fun setCameraEnabled(callId: String, enabled: Boolean) {
        callEngine.setCameraEnabled(callId, enabled)
    }

    fun setSpeakerEnabled(enabled: Boolean) {
        callEngine.setSpeakerEnabled(enabled)
    }

    private suspend fun fetchTurnCredentials(): TurnCredentialsResponseDto =
        apiProvider.withActiveApi { it.turnCredentials() }

    private suspend fun fetchSignalingEvents(callId: String): List<SignalingEventDto> =
        apiProvider.withActiveApi { it.callSignaling(callId).events }

    private suspend fun processRemoteSignaling(callId: String, events: List<SignalingEventDto>) {
        for (event in events) {
            if (!processedSignalingEvents.add(event.id)) continue
            val existing = callEventDao.latestForCall(callId)
            val state = event.eventKind.toLocalState(existing?.state)
            val callKind = when {
                existing?.callKind == "video" -> "video"
                event.payload.hasVideoMedia() -> "video"
                else -> existing?.callKind ?: "audio"
            }
            callEventDao.upsert(
                CallEventEntity(
                    id = event.id,
                    bubbleId = event.bubbleId,
                    callId = callId,
                    callKind = callKind,
                    state = state,
                    eventKind = event.eventKind,
                    createdAt = event.createdAt,
                ),
            )
            when (event.eventKind) {
                "answer" -> event.payload?.let { callEngine.setRemoteAnswer(callId, it) }
                "ice" -> event.payload
                    ?.let(CallSignalingCodec::decodeIceCandidate)
                    ?.let { callEngine.addRemoteIceCandidate(callId, it) }
                "reject",
                "hangup",
                -> callEngine.release(callId)
            }
        }
    }

    private suspend fun callTransition(
        callId: String,
        state: String,
        action: suspend () -> Unit,
    ): AppResult<Unit> = runCatching {
        val existing = callEventDao.latestForCall(callId)
        val bubbleId = existing?.bubbleId ?: activeBubbleIdProvider()
        action()
        callEventDao.upsert(
            CallEventEntity(
                id = "$callId-$state-${System.currentTimeMillis()}",
                bubbleId = bubbleId,
                callId = callId,
                callKind = existing?.callKind ?: "audio",
                state = state,
                eventKind = state,
                createdAt = Instant.now().toString(),
            ),
        )
    }.fold(
        onSuccess = { AppResult.Ok(Unit) },
        onFailure = { AppResult.Err(it.toUserVisibleError("Signal d'appel non envoyé")) },
    )

    private suspend fun sendSignalingPayload(
        callId: String,
        eventKind: String,
        action: suspend (bubbleId: String) -> Unit,
    ): AppResult<Unit> = runCatching {
        val existing = callEventDao.latestForCall(callId)
        val bubbleId = existing?.bubbleId ?: activeBubbleIdProvider()
        action(bubbleId)
        callEventDao.upsert(
            CallEventEntity(
                id = "$callId-$eventKind-${System.currentTimeMillis()}",
                bubbleId = bubbleId,
                callId = callId,
                callKind = existing?.callKind ?: "audio",
                state = existing?.state ?: "signaling",
                eventKind = eventKind,
                createdAt = Instant.now().toString(),
            ),
        )
    }.fold(
        onSuccess = { AppResult.Ok(Unit) },
        onFailure = { AppResult.Err(it.toUserVisibleError("Signal d'appel non envoyé")) },
    )

    private suspend fun upsertLocalEvent(
        callId: String,
        bubbleId: String,
        callKind: String,
        state: String,
        eventKind: String,
    ) {
        callEventDao.upsert(
            CallEventEntity(
                id = "$callId-$eventKind-${System.currentTimeMillis()}",
                bubbleId = bubbleId,
                callId = callId,
                callKind = callKind,
                state = state,
                eventKind = eventKind,
                createdAt = Instant.now().toString(),
            ),
        )
    }

    private fun TurnCredentialsResponseDto.toIceServers(): List<CallIceServer> {
        require(uris.isNotEmpty()) { "TURN indisponible: aucune URI fournie" }
        return listOf(
            CallIceServer(
                urls = uris,
                username = username,
                credential = credential,
            ),
        )
    }

    private fun String.toLocalState(previous: String?): String = when (this) {
        "offer" -> "ringing"
        "answer",
        "accept",
        -> "connecting"
        "ice" -> previous ?: "connecting"
        "reject" -> "rejected"
        "hangup" -> "ended"
        else -> previous ?: "signaling"
    }

    private fun String?.hasVideoMedia(): Boolean =
        this?.contains("\nm=video", ignoreCase = true) == true ||
            this?.startsWith("m=video", ignoreCase = true) == true
}
