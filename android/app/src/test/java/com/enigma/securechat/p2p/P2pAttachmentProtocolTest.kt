package com.enigma.securechat.p2p

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class P2pAttachmentProtocolTest {
    private val codec = P2pAttachmentControlCodec()
    private val clientMessageId = "00000000-0000-0000-0000-000000000001"
    private val blobId = "00000000-0000-0000-0000-000000000002"
    private val sha256 = "ab".repeat(32)

    @Test
    fun offerRoundTripPreservesStrictMetadata() {
        val offer = P2pAttachmentControl.Offer(
            clientMessageId = clientMessageId,
            attachments = listOf(P2pAttachmentSpec(blobId, 123_456L, sha256)),
        )

        assertEquals(offer, codec.decode(codec.encode(offer)))
    }

    @Test
    fun readyRoundTripPreservesResumeOffset() {
        val ready = P2pAttachmentControl.Ready(
            clientMessageId = clientMessageId,
            offsets = listOf(P2pAttachmentOffset(blobId, 65_536L)),
        )

        assertEquals(ready, codec.decode(codec.encode(ready)))
    }

    @Test
    fun rejectsDuplicateAttachmentBlobIds() {
        val encoded = codec.encode(
            P2pAttachmentControl.Offer(
                clientMessageId = clientMessageId,
                attachments = listOf(
                    P2pAttachmentSpec(blobId, 10L, sha256),
                    P2pAttachmentSpec(blobId, 10L, sha256),
                ),
            ),
        )

        assertThrows(IllegalArgumentException::class.java) { codec.decode(encoded) }
    }

    @Test
    fun rejectsMoreThanSixteenAttachments() {
        val attachments = (1..17).map { index ->
            P2pAttachmentSpec(
                blobId = "00000000-0000-0000-0000-${index.toString().padStart(12, '0')}",
                sizeBytes = 1L,
                sha256 = sha256,
            )
        }
        val encoded = codec.encode(P2pAttachmentControl.Offer(clientMessageId, attachments))

        assertThrows(IllegalArgumentException::class.java) { codec.decode(encoded) }
    }

    @Test
    fun rejectsInvalidHashAndNegativeReadyOffset() {
        val invalidHash = codec.encode(
            P2pAttachmentControl.Offer(
                clientMessageId,
                listOf(P2pAttachmentSpec(blobId, 10L, "AA".repeat(32))),
            ),
        )
        val invalidOffset = codec.encode(
            P2pAttachmentControl.Ready(
                clientMessageId,
                listOf(P2pAttachmentOffset(blobId, -1L)),
            ),
        )

        assertThrows(IllegalArgumentException::class.java) { codec.decode(invalidHash) }
        assertThrows(IllegalArgumentException::class.java) { codec.decode(invalidOffset) }
    }

    @Test
    fun binaryChunkRoundTripPreservesIdsOffsetAndPayload() {
        val source = ByteArray(4096) { index -> (index and 0xff).toByte() }
        val encoded = P2pAttachmentChunkCodec.encode(
            clientMessageId = clientMessageId,
            blobId = blobId,
            offset = 131_072L,
            source = source,
            length = source.size,
        )

        val decoded = P2pAttachmentChunkCodec.decode(encoded)
        assertEquals(clientMessageId, decoded.clientMessageId)
        assertEquals(blobId, decoded.blobId)
        assertEquals(131_072L, decoded.offset)
        assertArrayEquals(source, decoded.data)
    }

    @Test
    fun binaryChunkRejectsTruncationLengthMismatchAndOversize() {
        val source = ByteArray(128) { 7 }
        val valid = P2pAttachmentChunkCodec.encode(
            clientMessageId = clientMessageId,
            blobId = blobId,
            offset = 0L,
            source = source,
            length = source.size,
        )
        val truncated = valid.copyOf(valid.size - 1)
        assertThrows(IllegalArgumentException::class.java) {
            P2pAttachmentChunkCodec.decode(truncated)
        }

        val oversized = ByteArray(P2pAttachmentChunkCodec.MAX_CHUNK_DATA_BYTES + 1)
        assertThrows(IllegalArgumentException::class.java) {
            P2pAttachmentChunkCodec.encode(
                clientMessageId = clientMessageId,
                blobId = blobId,
                offset = 0L,
                source = oversized,
                length = oversized.size,
            )
        }
    }
}
