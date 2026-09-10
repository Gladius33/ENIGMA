package com.enigma.securechat.p2p

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Test

class P2pFrameCodecTest {
    private val codec = P2pFrameCodec()

    @Test
    fun authRoundTripPreservesBubbleAndFingerprints() {
        val proof = P2pAuthProof(
            sessionId = "00000000-0000-0000-0000-000000000001",
            bubbleId = "00000000-0000-0000-0000-000000000002",
            initiatorDeviceId = "00000000-0000-0000-0000-000000000003",
            responderDeviceId = "00000000-0000-0000-0000-000000000004",
            offerFingerprint = "sha-256 AA:BB",
            answerFingerprint = "sha-256 CC:DD",
            proofDeviceId = "00000000-0000-0000-0000-000000000003",
            nonce = codec.encodeBytes(ByteArray(32) { 7 }),
            signature = codec.encodeBytes(ByteArray(64) { 9 }),
        )

        val decoded = codec.decode(codec.encodeAuth(proof)) as P2pFrameCodec.DecodedP2pFrame.Auth
        assertEquals(proof, decoded.proof)
    }

    @Test
    fun transcriptChangesWhenBubbleChanges() {
        val common = TranscriptFixture(codec)
        val bubbleA = common.transcript("bubble-a")
        val bubbleB = common.transcript("bubble-b")

        assertFalse(bubbleA.contentEquals(bubbleB))
    }

    @Test
    fun routeObservationRoundTripPreservesLocalEvidence() {
        val observation = P2pRouteObservation(
            sessionId = "session",
            bubbleId = "bubble",
            senderDeviceId = "device-a",
            route = P2pRoute.TURN,
            localCandidateType = "relay",
            remoteCandidateType = "srflx",
        )

        val decoded = codec.decode(codec.encodeRoute(observation)) as P2pFrameCodec.DecodedP2pFrame.Route
        assertEquals(observation, decoded.observation)
    }

    @Test
    fun readReceiptRoundTripPreservesAuthenticatedTarget() {
        val receipt = P2pReceiptEnvelope(
            receiptId = "receipt-1",
            bubbleId = "bubble-1",
            senderDeviceId = "device-b",
            recipientDeviceId = "device-a",
            clientMessageId = "message-1",
            status = P2pReceiptStatus.READ,
        )

        val decoded = codec.decode(codec.encodeReceipt(receipt)) as P2pFrameCodec.DecodedP2pFrame.Receipt
        assertEquals(receipt, decoded.receipt)
    }

    @Test
    fun deliveredReceiptRoundTripUsesSameProtocol() {
        val receipt = P2pReceiptEnvelope(
            receiptId = "receipt-2",
            bubbleId = "bubble-1",
            senderDeviceId = "device-b",
            recipientDeviceId = "device-a",
            clientMessageId = "message-2",
            status = P2pReceiptStatus.DELIVERED,
        )

        val decoded = codec.decode(codec.encodeReceipt(receipt)) as P2pFrameCodec.DecodedP2pFrame.Receipt
        assertEquals(receipt, decoded.receipt)
    }

    @Test
    fun receiptAckRoundTripPreservesReceiptIdOnly() {
        val ack = P2pReceiptAck(receiptId = "receipt-3")

        val decoded = codec.decode(codec.encodeReceiptAck(ack)) as P2pFrameCodec.DecodedP2pFrame.ReceiptAck
        assertEquals(ack, decoded.ack)
    }

    @Test
    fun routeConsensusUsesTurnIfEitherPeerObservedRelay() {
        val direct = P2pSelectedRoute(P2pRoute.DIRECT, "srflx", "srflx")
        val turn = P2pSelectedRoute(P2pRoute.TURN, "relay", "srflx")

        assertEquals(P2pRoute.DIRECT, consensusRoute(direct, direct).route)
        assertEquals(P2pRoute.TURN, consensusRoute(direct, turn).route)
        assertEquals(P2pRoute.TURN, consensusRoute(turn, direct).route)
    }

    @Test
    fun rejectsUnsupportedFrameVersion() {
        val proof = P2pAuthProof(
            sessionId = "session",
            bubbleId = "bubble",
            initiatorDeviceId = "a",
            responderDeviceId = "b",
            offerFingerprint = "sha-256 AA",
            answerFingerprint = "sha-256 BB",
            proofDeviceId = "a",
            nonce = codec.encodeBytes(ByteArray(32)),
            signature = codec.encodeBytes(ByteArray(64)),
        )
        val futureVersion = codec.encodeAuth(proof).replaceFirst("\"version\":1", "\"version\":2")

        assertThrows(IllegalArgumentException::class.java) {
            codec.decode(futureVersion)
        }
    }

    private data class TranscriptFixture(
        val codec: P2pFrameCodec,
    ) {
        fun transcript(bubbleId: String): ByteArray = codec.transcript(
            sessionId = "session",
            bubbleId = bubbleId,
            initiatorDeviceId = "device-a",
            responderDeviceId = "device-b",
            offerFingerprint = "sha-256 AA:BB",
            answerFingerprint = "sha-256 CC:DD",
            proofDeviceId = "device-a",
            nonce = "nonce",
        )
    }
}
