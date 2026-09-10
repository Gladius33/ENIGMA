package com.enigma.securechat.p2p

import com.squareup.moshi.Json
import com.squareup.moshi.Moshi
import com.squareup.moshi.kotlin.reflect.KotlinJsonAdapterFactory
import java.util.Base64

data class P2pAuthProof(
    val sessionId: String,
    val bubbleId: String,
    val initiatorDeviceId: String,
    val responderDeviceId: String,
    val offerFingerprint: String,
    val answerFingerprint: String,
    val proofDeviceId: String,
    val nonce: String,
    val signature: String,
)

data class P2pRouteObservation(
    val sessionId: String,
    val bubbleId: String,
    val senderDeviceId: String,
    val route: P2pRoute,
    val localCandidateType: String,
    val remoteCandidateType: String,
)

data class P2pMessageEnvelope(
    val bubbleId: String,
    val senderDeviceId: String,
    val recipientDeviceId: String,
    val clientMessageId: String,
    val messageType: String,
    val ciphertext: String,
)

data class P2pReceiptEnvelope(
    val receiptId: String,
    val bubbleId: String,
    val senderDeviceId: String,
    val recipientDeviceId: String,
    val clientMessageId: String,
    val status: P2pReceiptStatus,
)

data class P2pReceiptAck(
    val receiptId: String,
)

class P2pFrameCodec(
    moshi: Moshi = Moshi.Builder().add(KotlinJsonAdapterFactory()).build(),
) {
    private val adapter = moshi.adapter(WireFrame::class.java)

    fun encodeAuth(proof: P2pAuthProof): String = adapter.toJson(
        WireFrame(
            kind = KIND_AUTH,
            sessionId = proof.sessionId,
            bubbleId = proof.bubbleId,
            initiatorDeviceId = proof.initiatorDeviceId,
            responderDeviceId = proof.responderDeviceId,
            offerFingerprint = proof.offerFingerprint,
            answerFingerprint = proof.answerFingerprint,
            proofDeviceId = proof.proofDeviceId,
            nonce = proof.nonce,
            signature = proof.signature,
        ),
    )

    fun encodeRoute(observation: P2pRouteObservation): String = adapter.toJson(
        WireFrame(
            kind = KIND_ROUTE,
            sessionId = observation.sessionId,
            bubbleId = observation.bubbleId,
            senderDeviceId = observation.senderDeviceId,
            route = observation.route.name,
            localCandidateType = observation.localCandidateType,
            remoteCandidateType = observation.remoteCandidateType,
        ),
    )

    fun encodeMessage(message: P2pMessageEnvelope): String = adapter.toJson(
        WireFrame(
            kind = KIND_MESSAGE,
            bubbleId = message.bubbleId,
            senderDeviceId = message.senderDeviceId,
            recipientDeviceId = message.recipientDeviceId,
            clientMessageId = message.clientMessageId,
            messageType = message.messageType,
            ciphertext = message.ciphertext,
        ),
    )

    fun encodeReceipt(receipt: P2pReceiptEnvelope): String = adapter.toJson(
        WireFrame(
            kind = KIND_RECEIPT,
            receiptId = receipt.receiptId,
            bubbleId = receipt.bubbleId,
            senderDeviceId = receipt.senderDeviceId,
            recipientDeviceId = receipt.recipientDeviceId,
            clientMessageId = receipt.clientMessageId,
            status = receipt.status.name,
        ),
    )

    fun encodeReceiptAck(ack: P2pReceiptAck): String = adapter.toJson(
        WireFrame(kind = KIND_RECEIPT_ACK, receiptId = ack.receiptId),
    )

    fun decode(value: String): DecodedP2pFrame {
        require(value.toByteArray(Charsets.UTF_8).size <= MAX_FRAME_BYTES) { "P2P frame too large" }
        val frame = requireNotNull(adapter.fromJson(value)) { "Invalid P2P frame" }
        require(frame.version == VERSION) { "Unsupported P2P frame version" }
        return when (frame.kind) {
            KIND_AUTH -> DecodedP2pFrame.Auth(
                P2pAuthProof(
                    sessionId = frame.sessionId.required("session_id"),
                    bubbleId = frame.bubbleId.required("bubble_id"),
                    initiatorDeviceId = frame.initiatorDeviceId.required("initiator_device_id"),
                    responderDeviceId = frame.responderDeviceId.required("responder_device_id"),
                    offerFingerprint = frame.offerFingerprint.required("offer_fingerprint"),
                    answerFingerprint = frame.answerFingerprint.required("answer_fingerprint"),
                    proofDeviceId = frame.proofDeviceId.required("proof_device_id"),
                    nonce = frame.nonce.required("nonce"),
                    signature = frame.signature.required("signature"),
                ),
            )
            KIND_ROUTE -> DecodedP2pFrame.Route(
                P2pRouteObservation(
                    sessionId = frame.sessionId.required("session_id"),
                    bubbleId = frame.bubbleId.required("bubble_id"),
                    senderDeviceId = frame.senderDeviceId.required("sender_device_id"),
                    route = runCatching { P2pRoute.valueOf(frame.route.required("route")) }
                        .getOrElse { error("Unsupported P2P route") },
                    localCandidateType = frame.localCandidateType.required("local_candidate_type"),
                    remoteCandidateType = frame.remoteCandidateType.required("remote_candidate_type"),
                ),
            )
            KIND_MESSAGE -> DecodedP2pFrame.Message(
                P2pMessageEnvelope(
                    bubbleId = frame.bubbleId.required("bubble_id"),
                    senderDeviceId = frame.senderDeviceId.required("sender_device_id"),
                    recipientDeviceId = frame.recipientDeviceId.required("recipient_device_id"),
                    clientMessageId = frame.clientMessageId.required("client_message_id"),
                    messageType = frame.messageType.required("message_type"),
                    ciphertext = frame.ciphertext.required("ciphertext"),
                ),
            )
            KIND_RECEIPT -> DecodedP2pFrame.Receipt(
                P2pReceiptEnvelope(
                    receiptId = frame.receiptId.required("receipt_id"),
                    bubbleId = frame.bubbleId.required("bubble_id"),
                    senderDeviceId = frame.senderDeviceId.required("sender_device_id"),
                    recipientDeviceId = frame.recipientDeviceId.required("recipient_device_id"),
                    clientMessageId = frame.clientMessageId.required("client_message_id"),
                    status = runCatching {
                        P2pReceiptStatus.valueOf(frame.status.required("status"))
                    }.getOrElse { error("Unsupported P2P receipt status") },
                ),
            )
            KIND_RECEIPT_ACK -> DecodedP2pFrame.ReceiptAck(
                P2pReceiptAck(frame.receiptId.required("receipt_id")),
            )
            else -> error("Unsupported P2P frame kind")
        }
    }

    fun transcript(
        sessionId: String,
        bubbleId: String,
        initiatorDeviceId: String,
        responderDeviceId: String,
        offerFingerprint: String,
        answerFingerprint: String,
        proofDeviceId: String,
        nonce: String,
    ): ByteArray = listOf(
        PROTOCOL_LABEL,
        sessionId,
        bubbleId,
        initiatorDeviceId,
        responderDeviceId,
        offerFingerprint,
        answerFingerprint,
        proofDeviceId,
        nonce,
    ).joinToString("\n").toByteArray(Charsets.UTF_8)

    fun encodeBytes(value: ByteArray): String =
        Base64.getEncoder().withoutPadding().encodeToString(value)

    fun decodeBytes(value: String): ByteArray = Base64.getDecoder().decode(value)

    sealed interface DecodedP2pFrame {
        data class Auth(val proof: P2pAuthProof) : DecodedP2pFrame
        data class Route(val observation: P2pRouteObservation) : DecodedP2pFrame
        data class Message(val message: P2pMessageEnvelope) : DecodedP2pFrame
        data class Receipt(val receipt: P2pReceiptEnvelope) : DecodedP2pFrame
        data class ReceiptAck(val ack: P2pReceiptAck) : DecodedP2pFrame
    }

    private data class WireFrame(
        val version: Int = VERSION,
        val kind: String,
        @Json(name = "session_id") val sessionId: String? = null,
        @Json(name = "initiator_device_id") val initiatorDeviceId: String? = null,
        @Json(name = "responder_device_id") val responderDeviceId: String? = null,
        @Json(name = "offer_fingerprint") val offerFingerprint: String? = null,
        @Json(name = "answer_fingerprint") val answerFingerprint: String? = null,
        @Json(name = "proof_device_id") val proofDeviceId: String? = null,
        val nonce: String? = null,
        val signature: String? = null,
        @Json(name = "bubble_id") val bubbleId: String? = null,
        @Json(name = "sender_device_id") val senderDeviceId: String? = null,
        @Json(name = "recipient_device_id") val recipientDeviceId: String? = null,
        @Json(name = "client_message_id") val clientMessageId: String? = null,
        @Json(name = "message_type") val messageType: String? = null,
        @Json(name = "receipt_id") val receiptId: String? = null,
        val status: String? = null,
        val ciphertext: String? = null,
        val route: String? = null,
        @Json(name = "local_candidate_type") val localCandidateType: String? = null,
        @Json(name = "remote_candidate_type") val remoteCandidateType: String? = null,
    )

    private fun String?.required(field: String): String =
        requireNotNull(this?.takeIf(String::isNotBlank)) { "Missing P2P field $field" }

    private companion object {
        const val VERSION = 1
        const val PROTOCOL_LABEL = "ENIGMA_P2P_AUTH_V1"
        const val KIND_AUTH = "auth"
        const val KIND_ROUTE = "route"
        const val KIND_MESSAGE = "message"
        const val KIND_RECEIPT = "receipt"
        const val KIND_RECEIPT_ACK = "receipt_ack"
        const val MAX_FRAME_BYTES = 768 * 1024
    }
}
