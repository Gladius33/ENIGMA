package com.enigma.securechat.crypto

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class RecipientEnvelopeCodecTest {
    @Test
    fun encodesBase64EnvelopeAndSelectsRecipientCiphertext() {
        val encoded = RecipientEnvelopeCodec.encode(
            RecipientEncryptedEnvelope(
                recipients = listOf(
                    RecipientCiphertext(deviceId = "device-a", ciphertext = "cipher-a"),
                    RecipientCiphertext(deviceId = "device-b", ciphertext = "cipher-b"),
                ),
            ),
        )

        assertEquals("cipher-b", RecipientEnvelopeCodec.ciphertextForDevice(encoded, "device-b"))
        assertNull(RecipientEnvelopeCodec.ciphertextForDevice(encoded, "missing"))
        assertEquals(1, RecipientEnvelopeCodec.decode(encoded).version)
    }
}
