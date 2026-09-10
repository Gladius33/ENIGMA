package com.enigma.securechat.p2p

import android.content.Context
import java.nio.ByteBuffer
import java.util.concurrent.ConcurrentHashMap
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withTimeoutOrNull
import org.webrtc.DataChannel
import org.webrtc.IceCandidate
import org.webrtc.MediaConstraints
import org.webrtc.MediaStream
import org.webrtc.PeerConnection
import org.webrtc.PeerConnectionFactory
import org.webrtc.RtpReceiver
import org.webrtc.SessionDescription
import org.webrtc.SdpObserver

class WebRtcP2pEngine(context: Context) : P2pEngine {
    private val appContext = context.applicationContext
    private val factory: PeerConnectionFactory
    private val sessions = ConcurrentHashMap<String, P2pSession>()
    private val _events = MutableSharedFlow<P2pEngineEvent>(
        replay = 0,
        extraBufferCapacity = 128,
        onBufferOverflow = BufferOverflow.DROP_OLDEST,
    )

    override val events: Flow<P2pEngineEvent> = _events

    init {
        initialize(appContext)
        factory = PeerConnectionFactory.builder().createPeerConnectionFactory()
    }

    override suspend fun startOutgoing(config: P2pSessionConfig): String {
        val session = createSession(config)
        val dataChannel = requireNotNull(
            session.peerConnection.createDataChannel(
                DATA_CHANNEL_LABEL,
                DataChannel.Init().apply {
                    ordered = true
                },
            ),
        ) { "P2P DataChannel indisponible" }
        attachDataChannel(config.sessionId, dataChannel)

        val offer = session.peerConnection.createOfferAwait(MediaConstraints())
        session.peerConnection.setLocalDescriptionAwait(offer)
        session.localFingerprint = extractDtlsFingerprint(offer.description)
        emit(P2pEngineEvent.StateChanged(config.sessionId, "connecting"))
        return offer.description
    }

    override suspend fun acceptIncoming(
        config: P2pSessionConfig,
        remoteOfferSdp: String,
    ): String {
        val session = createSession(config)
        session.remoteFingerprint = extractDtlsFingerprint(remoteOfferSdp)
        session.peerConnection.setRemoteDescriptionAwait(
            SessionDescription(SessionDescription.Type.OFFER, remoteOfferSdp),
        )
        val answer = session.peerConnection.createAnswerAwait(MediaConstraints())
        session.peerConnection.setLocalDescriptionAwait(answer)
        session.localFingerprint = extractDtlsFingerprint(answer.description)
        emit(P2pEngineEvent.StateChanged(config.sessionId, "connecting"))
        return answer.description
    }

    override suspend fun setRemoteAnswer(sessionId: String, remoteAnswerSdp: String) {
        val session = sessions[sessionId] ?: return
        session.remoteFingerprint = extractDtlsFingerprint(remoteAnswerSdp)
        session.peerConnection.setRemoteDescriptionAwait(
            SessionDescription(SessionDescription.Type.ANSWER, remoteAnswerSdp),
        )
    }

    override suspend fun addRemoteIceCandidate(sessionId: String, candidate: P2pIceCandidate) {
        sessions[sessionId]?.peerConnection?.addIceCandidate(
            IceCandidate(
                candidate.sdpMid ?: "0",
                candidate.sdpMLineIndex,
                candidate.candidate,
            ),
        )
    }

    override fun localDtlsFingerprint(sessionId: String): String? =
        sessions[sessionId]?.localFingerprint

    override fun remoteDtlsFingerprint(sessionId: String): String? =
        sessions[sessionId]?.remoteFingerprint

    override suspend fun selectedRoute(sessionId: String): P2pSelectedRoute? {
        val peerConnection = sessions[sessionId]?.peerConnection ?: return null
        return suspendCancellableCoroutine { continuation ->
            peerConnection.getStats { report ->
                if (!continuation.isActive) return@getStats
                val stats = report.statsMap
                val selectedPairId = stats.values
                    .firstOrNull { stat -> stat.type == "transport" }
                    ?.members
                    ?.get("selectedCandidatePairId") as? String
                    ?: stats.values
                        .firstOrNull { stat ->
                            stat.type == "candidate-pair" &&
                                stat.members["state"] == "succeeded" &&
                                stat.members["nominated"] == true
                        }
                        ?.id

                val pair = selectedPairId?.let(stats::get)
                val localCandidateId = pair?.members?.get("localCandidateId") as? String
                val remoteCandidateId = pair?.members?.get("remoteCandidateId") as? String
                val localType = localCandidateId
                    ?.let(stats::get)
                    ?.members
                    ?.get("candidateType") as? String
                val remoteType = remoteCandidateId
                    ?.let(stats::get)
                    ?.members
                    ?.get("candidateType") as? String

                val route = if (localType != null && remoteType != null) {
                    P2pSelectedRoute(
                        route = if (localType == "relay" || remoteType == "relay") {
                            P2pRoute.TURN
                        } else {
                            P2pRoute.DIRECT
                        },
                        localCandidateType = localType,
                        remoteCandidateType = remoteType,
                    )
                } else {
                    null
                }
                continuation.resume(route)
            }
        }
    }

    override fun send(sessionId: String, payload: String): Boolean {
        val bytes = payload.toByteArray(Charsets.UTF_8)
        if (bytes.isEmpty() || bytes.size > MAX_DATA_CHANNEL_PAYLOAD_BYTES) {
            bytes.fill(0)
            return false
        }
        val channel = sessions[sessionId]?.dataChannel
        if (channel == null || channel.state() != DataChannel.State.OPEN) {
            bytes.fill(0)
            return false
        }
        val sent = channel.send(DataChannel.Buffer(ByteBuffer.wrap(bytes), false))
        bytes.fill(0)
        return sent
    }

    override suspend fun sendBinary(sessionId: String, payload: ByteArray): Boolean {
        if (payload.isEmpty() || payload.size > MAX_BINARY_CHUNK_BYTES) return false
        val channel = sessions[sessionId]?.dataChannel ?: return false
        if (channel.state() != DataChannel.State.OPEN) return false

        val ready = withTimeoutOrNull(BUFFER_DRAIN_TIMEOUT_MILLIS) {
            while (channel.state() == DataChannel.State.OPEN && channel.bufferedAmount() > MAX_BUFFERED_AMOUNT_BYTES) {
                delay(BUFFER_POLL_MILLIS)
            }
            channel.state() == DataChannel.State.OPEN
        } == true
        if (!ready) return false

        return channel.send(DataChannel.Buffer(ByteBuffer.wrap(payload), true))
    }

    override fun release(sessionId: String) {
        val session = sessions.remove(sessionId) ?: return
        session.dispose()
        emit(P2pEngineEvent.StateChanged(sessionId, "ended"))
    }

    override fun dispose() {
        sessions.keys.toList().forEach(::release)
        factory.dispose()
    }

    private fun createSession(config: P2pSessionConfig): P2pSession {
        sessions.remove(config.sessionId)?.dispose()
        val peerConnection = factory.createPeerConnection(
            PeerConnection.RTCConfiguration(config.iceServers.toRtcIceServers()).apply {
                sdpSemantics = PeerConnection.SdpSemantics.UNIFIED_PLAN
                continualGatheringPolicy = PeerConnection.ContinualGatheringPolicy.GATHER_CONTINUALLY
            },
            PeerObserver(config.sessionId),
        ) ?: error("PeerConnection P2P indisponible")

        return P2pSession(peerConnection).also { sessions[config.sessionId] = it }
    }

    private fun attachDataChannel(sessionId: String, dataChannel: DataChannel) {
        val session = sessions[sessionId] ?: run {
            dataChannel.dispose()
            return
        }
        session.dataChannel?.takeIf { it !== dataChannel }?.dispose()
        session.dataChannel = dataChannel
        dataChannel.registerObserver(
            object : DataChannel.Observer {
                override fun onBufferedAmountChange(previousAmount: Long) = Unit

                override fun onStateChange() {
                    when (dataChannel.state()) {
                        DataChannel.State.OPEN -> emit(P2pEngineEvent.ChannelOpen(sessionId))
                        DataChannel.State.CLOSED -> emit(P2pEngineEvent.StateChanged(sessionId, "closed"))
                        else -> Unit
                    }
                }

                override fun onMessage(buffer: DataChannel.Buffer) {
                    val duplicate = buffer.data.slice()
                    val bytes = ByteArray(duplicate.remaining())
                    duplicate.get(bytes)
                    if (buffer.binary) {
                        emit(P2pEngineEvent.BinaryPayload(sessionId, bytes))
                        return
                    }
                    val payload = bytes.toString(Charsets.UTF_8)
                    bytes.fill(0)
                    emit(P2pEngineEvent.Payload(sessionId, payload))
                }
            },
        )
    }

    private fun List<com.enigma.securechat.calls.CallIceServer>.toRtcIceServers(): List<PeerConnection.IceServer> =
        map { server ->
            val builder = if (server.urls.size == 1) {
                PeerConnection.IceServer.builder(server.urls.first())
            } else {
                PeerConnection.IceServer.builder(server.urls)
            }
            builder
                .setUsername(server.username.orEmpty())
                .setPassword(server.credential.orEmpty())
                .createIceServer()
        }

    private fun extractDtlsFingerprint(sdp: String): String? =
        sdp.lineSequence()
            .map(String::trim)
            .firstOrNull { it.startsWith("a=fingerprint:", ignoreCase = true) }
            ?.substringAfter(':', missingDelimiterValue = "")
            ?.trim()
            ?.split(Regex("\\s+"), limit = 2)
            ?.takeIf { it.size == 2 && it.all(String::isNotBlank) }
            ?.let { parts -> "${parts[0].lowercase()} ${parts[1].uppercase()}" }

    private fun emit(event: P2pEngineEvent) {
        _events.tryEmit(event)
    }

    private inner class PeerObserver(
        private val sessionId: String,
    ) : PeerConnection.Observer {
        override fun onSignalingChange(newState: PeerConnection.SignalingState?) = Unit

        override fun onIceConnectionChange(newState: PeerConnection.IceConnectionState?) {
            val state = when (newState) {
                PeerConnection.IceConnectionState.CONNECTED,
                PeerConnection.IceConnectionState.COMPLETED,
                -> "connected"
                PeerConnection.IceConnectionState.FAILED -> "failed"
                PeerConnection.IceConnectionState.DISCONNECTED -> "disconnected"
                PeerConnection.IceConnectionState.CLOSED -> "ended"
                else -> "connecting"
            }
            emit(P2pEngineEvent.StateChanged(sessionId, state))
        }

        override fun onIceConnectionReceivingChange(receiving: Boolean) = Unit

        override fun onIceGatheringChange(newState: PeerConnection.IceGatheringState?) = Unit

        override fun onIceCandidate(candidate: IceCandidate?) {
            if (candidate == null) return
            emit(
                P2pEngineEvent.LocalIceCandidate(
                    sessionId = sessionId,
                    candidate = P2pIceCandidate(
                        sdpMid = candidate.sdpMid,
                        sdpMLineIndex = candidate.sdpMLineIndex,
                        candidate = candidate.sdp,
                    ),
                ),
            )
        }

        override fun onIceCandidatesRemoved(candidates: Array<out IceCandidate>?) = Unit

        override fun onAddStream(stream: MediaStream?) = Unit

        override fun onRemoveStream(stream: MediaStream?) = Unit

        override fun onDataChannel(dataChannel: DataChannel?) {
            if (dataChannel != null && dataChannel.label() == DATA_CHANNEL_LABEL) {
                attachDataChannel(sessionId, dataChannel)
            }
        }

        override fun onRenegotiationNeeded() = Unit

        override fun onAddTrack(receiver: RtpReceiver?, mediaStreams: Array<out MediaStream>?) = Unit
    }

    private data class P2pSession(
        val peerConnection: PeerConnection,
        var dataChannel: DataChannel? = null,
        var localFingerprint: String? = null,
        var remoteFingerprint: String? = null,
    ) {
        fun dispose() {
            dataChannel?.unregisterObserver()
            dataChannel?.dispose()
            peerConnection.dispose()
        }
    }

    private companion object {
        const val DATA_CHANNEL_LABEL = "enigma-p2p-v1"
        const val MAX_DATA_CHANNEL_PAYLOAD_BYTES = 512 * 1024
        const val MAX_BINARY_CHUNK_BYTES = 64 * 1024
        const val MAX_BUFFERED_AMOUNT_BYTES = 512 * 1024L
        const val BUFFER_DRAIN_TIMEOUT_MILLIS = 10_000L
        const val BUFFER_POLL_MILLIS = 10L
        @Volatile private var initialized = false

        @Synchronized
        fun initialize(context: Context) {
            if (initialized) return
            PeerConnectionFactory.initialize(
                PeerConnectionFactory.InitializationOptions.builder(context)
                    .createInitializationOptions(),
            )
            initialized = true
        }
    }
}

private suspend fun PeerConnection.createOfferAwait(
    constraints: MediaConstraints,
): SessionDescription = suspendCancellableCoroutine { continuation ->
    createOffer(object : SdpObserver {
        override fun onCreateSuccess(description: SessionDescription?) {
            if (description == null) {
                continuation.resumeWithException(IllegalStateException("Offer P2P vide"))
            } else {
                continuation.resume(description)
            }
        }

        override fun onSetSuccess() = Unit
        override fun onCreateFailure(error: String?) {
            continuation.resumeWithException(IllegalStateException(error ?: "Offer P2P non créée"))
        }
        override fun onSetFailure(error: String?) = Unit
    }, constraints)
}

private suspend fun PeerConnection.createAnswerAwait(
    constraints: MediaConstraints,
): SessionDescription = suspendCancellableCoroutine { continuation ->
    createAnswer(object : SdpObserver {
        override fun onCreateSuccess(description: SessionDescription?) {
            if (description == null) {
                continuation.resumeWithException(IllegalStateException("Answer P2P vide"))
            } else {
                continuation.resume(description)
            }
        }

        override fun onSetSuccess() = Unit
        override fun onCreateFailure(error: String?) {
            continuation.resumeWithException(IllegalStateException(error ?: "Answer P2P non créée"))
        }
        override fun onSetFailure(error: String?) = Unit
    }, constraints)
}

private suspend fun PeerConnection.setLocalDescriptionAwait(
    description: SessionDescription,
): Unit = suspendCancellableCoroutine { continuation ->
    setLocalDescription(object : SdpObserver {
        override fun onCreateSuccess(description: SessionDescription?) = Unit
        override fun onSetSuccess() = continuation.resume(Unit)
        override fun onCreateFailure(error: String?) = Unit
        override fun onSetFailure(error: String?) {
            continuation.resumeWithException(IllegalStateException(error ?: "Local P2P SDP refusée"))
        }
    }, description)
}

private suspend fun PeerConnection.setRemoteDescriptionAwait(
    description: SessionDescription,
): Unit = suspendCancellableCoroutine { continuation ->
    setRemoteDescription(object : SdpObserver {
        override fun onCreateSuccess(description: SessionDescription?) = Unit
        override fun onSetSuccess() = continuation.resume(Unit)
        override fun onCreateFailure(error: String?) = Unit
        override fun onSetFailure(error: String?) {
            continuation.resumeWithException(IllegalStateException(error ?: "Remote P2P SDP refusée"))
        }
    }, description)
}
