package com.enigma.securechat.repository

import com.enigma.securechat.data.repository.MessagePayloadCodec
import com.enigma.securechat.data.repository.SenderSyncPayload
import com.enigma.securechat.data.repository.SenderSyncPayloadCodec
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class SenderSyncPayloadCodecTest {
    @Test
    fun senderSyncRoundTripsAndCarriesLogicalMessageIdentity() {
        val encodedMessage = MessagePayloadCodec.encode("bonjour", emptyList())
        val encoded = SenderSyncPayloadCodec.encode(
            SenderSyncPayload(
                contactUserId = "11111111-1111-4111-8111-111111111111",
                contactPublicId = "contact",
                contactDisplayName = "Contact",
                bubbleId = "22222222-2222-4222-8222-222222222222",
                clientMessageId = "33333333-3333-4333-8333-333333333333",
                originalCreatedAt = 1_700_000_000_000,
                encodedMessagePayload = encodedMessage,
            ),
        )

        assertTrue(SenderSyncPayloadCodec.isSenderSync(encoded))
        val decoded = SenderSyncPayloadCodec.decode(encoded)
        assertEquals("11111111-1111-4111-8111-111111111111", decoded.contactUserId)
        assertEquals("33333333-3333-4333-8333-333333333333", decoded.clientMessageId)
        assertEquals("bonjour", MessagePayloadCodec.decode(decoded.encodedMessagePayload).body)
    }

    @Test
    fun ordinaryMessagePayloadIsNotSenderSync() {
        val ordinary = MessagePayloadCodec.encode("bonjour", emptyList())
        assertFalse(SenderSyncPayloadCodec.isSenderSync(ordinary))
        assertThrows(IllegalArgumentException::class.java) {
            SenderSyncPayloadCodec.decode(ordinary)
        }
    }
}
