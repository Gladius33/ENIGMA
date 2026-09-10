package com.enigma.securechat.repository

import com.enigma.securechat.data.repository.MessageAttachment
import com.enigma.securechat.data.repository.MessagePayloadCodec
import com.enigma.securechat.domain.model.AttachmentDescriptor
import java.util.Base64
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class MessagePayloadCodecTest {
    @Test
    fun roundTripPreservesAttachmentSecretsInsidePayload() {
        val attachment = MessageAttachment(
            descriptor = descriptor(),
            fileName = "preuve.pdf",
        )
        val encoded = MessagePayloadCodec.encode("document", listOf(attachment))

        assertTrue(encoded.startsWith("ENIGMA_PAYLOAD_V1:"))
        val decoded = MessagePayloadCodec.decode(encoded)
        assertEquals("document", decoded.body)
        assertEquals(1, decoded.attachments.size)
        assertEquals(attachment, decoded.attachments.single())
    }

    @Test
    fun textOnlyPayloadIsStillVersioned() {
        val encoded = MessagePayloadCodec.encode("message", emptyList())
        assertTrue(encoded.startsWith("ENIGMA_PAYLOAD_V1:"))
        val decoded = MessagePayloadCodec.decode(encoded)
        assertEquals("message", decoded.body)
        assertTrue(decoded.attachments.isEmpty())
    }

    @Test
    fun unversionedPayloadIsRejected() {
        expectFailure { MessagePayloadCodec.decode("ancien message") }
    }

    @Test
    fun duplicateBlobIdsAreRejected() {
        val attachment = MessageAttachment(descriptor())
        expectFailure {
            MessagePayloadCodec.encode("", listOf(attachment, attachment))
        }
    }

    @Test
    fun invalidKeyLengthIsRejected() {
        val invalid = descriptor().copy(
            key = Base64.getEncoder().withoutPadding().encodeToString(ByteArray(16)),
        )
        expectFailure {
            MessagePayloadCodec.encode("", listOf(MessageAttachment(invalid)))
        }
    }

    @Test
    fun legacyTwelveByteNonceIsRejected() {
        val invalid = descriptor().copy(
            nonce = Base64.getEncoder().withoutPadding().encodeToString(ByteArray(12)),
        )
        expectFailure {
            MessagePayloadCodec.encode("", listOf(MessageAttachment(invalid)))
        }
    }

    private fun descriptor() = AttachmentDescriptor(
        blobId = "11111111-1111-4111-8111-111111111111",
        bubbleId = "22222222-2222-4222-8222-222222222222",
        contentType = "application/pdf",
        sizeBytes = 12_345,
        sha256 = "ab".repeat(32),
        key = Base64.getEncoder().withoutPadding().encodeToString(ByteArray(32) { 7 }),
        nonce = Base64.getEncoder().withoutPadding().encodeToString(ByteArray(8) { 9 }),
        downloadSecret = "0123456789abcdef0123456789abcdef",
    )

    private fun expectFailure(block: () -> Unit) {
        var failed = false
        try {
            block()
        } catch (_: Exception) {
            failed = true
        }
        if (!failed) fail("Expected payload validation to fail")
    }
}
