package com.enigma.securechat.crypto

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class RecoverySecretVerifierTest {
    @Test
    fun generateReturnsClientSideVerifierOnly() {
        val generated = RecoverySecretVerifier.generate()

        assertTrue(generated.secret.length >= 32)
        assertTrue(generated.verifier.startsWith("pbkdf2-sha256$120000$"))
        assertEquals(4, generated.verifier.split('$').size)
    }
}
