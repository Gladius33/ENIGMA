package com.enigma.securechat.p2p

import com.enigma.securechat.calls.CallIceServer
import kotlinx.coroutines.flow.Flow

enum class P2pRoute {
    DIRECT,
    TURN,
}

enum class P2pPeerIdentityState {
    VERIFIED,
    UNVERIFIED,
    CHANGED,
}

enum class P2pReceiptStatus {
    DELIVERED,
    READ,
}

data class P2pSessionConfig(
    val sessionId: String,
    val bubbleId: String,
    val localDeviceId: String,
    val remoteDeviceId: String,
    val iceServers: List<CallIceServer>,
)

data class P2pIceCandidate(
    val sdpMid: String?,
    val sdpMLineIndex: Int,
    val candidate: String,
)

data class P2pSelectedRoute(
    val route: P2pRoute,
    val localCandidateType: String,
    val remoteCandidateType: String,
)

fun consensusRoute(
    local: P2pSelectedRoute,
    remote: P2pSelectedRoute,
): P2pSelectedRoute = local.copy(
    route = if (local.route == P2pRoute.TURN || remote.route == P2pRoute.TURN) {
        P2pRoute.TURN
    } else {
        P2pRoute.DIRECT
    },
)

data class P2pDelivery(
    val sessionId: String,
    val route: P2pRoute,
    val peerIdentityState: P2pPeerIdentityState,
    val localCandidateType: String,
    val remoteCandidateType: String,
)

data class P2pIncomingMessage(
    val sessionId: String,
    val bubbleId: String,
    val senderDeviceId: String,
    val recipientDeviceId: String,
    val clientMessageId: String,
    val messageType: String,
    val ciphertext: String,
    val route: P2pRoute,
    val peerIdentityState: P2pPeerIdentityState,
)

sealed interface P2pIncomingMessageResult {
    data object Rejected : P2pIncomingMessageResult
    data object Delivered : P2pIncomingMessageResult
    data class AwaitingAttachments(
        val attachments: List<P2pAttachmentSpec>,
    ) : P2pIncomingMessageResult
}

data class P2pIncomingReceipt(
    val sessionId: String,
    val receiptId: String,
    val bubbleId: String,
    val senderDeviceId: String,
    val recipientDeviceId: String,
    val clientMessageId: String,
    val status: P2pReceiptStatus,
    val route: P2pRoute,
    val peerIdentityState: P2pPeerIdentityState,
)

sealed interface P2pEngineEvent {
    data class LocalIceCandidate(
        val sessionId: String,
        val candidate: P2pIceCandidate,
    ) : P2pEngineEvent

    data class ChannelOpen(
        val sessionId: String,
    ) : P2pEngineEvent

    data class Payload(
        val sessionId: String,
        val payload: String,
    ) : P2pEngineEvent

    data class BinaryPayload(
        val sessionId: String,
        val payload: ByteArray,
    ) : P2pEngineEvent

    data class StateChanged(
        val sessionId: String,
        val state: String,
    ) : P2pEngineEvent
}

interface P2pEngine {
    val events: Flow<P2pEngineEvent>

    suspend fun startOutgoing(config: P2pSessionConfig): String

    suspend fun acceptIncoming(config: P2pSessionConfig, remoteOfferSdp: String): String

    suspend fun setRemoteAnswer(sessionId: String, remoteAnswerSdp: String)

    suspend fun addRemoteIceCandidate(sessionId: String, candidate: P2pIceCandidate)

    fun localDtlsFingerprint(sessionId: String): String?

    fun remoteDtlsFingerprint(sessionId: String): String?

    suspend fun selectedRoute(sessionId: String): P2pSelectedRoute?

    fun send(sessionId: String, payload: String): Boolean

    suspend fun sendBinary(sessionId: String, payload: ByteArray): Boolean

    fun release(sessionId: String)

    fun dispose()
}
