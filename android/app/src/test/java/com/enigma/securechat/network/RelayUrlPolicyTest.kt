package com.enigma.securechat.network

import org.junit.Assert.assertEquals
import org.junit.Test

class RelayUrlPolicyTest {
    @Test
    fun allowsHttpWhenCleartextIsAllowed() {
        val result = RelayUrlPolicy.validate("http://192.168.1.20:8080", cleartextAllowed = true)

        assertEquals("http://192.168.1.20:8080/", result.normalizedUrl)
        assertEquals(null, result.error)
    }

    @Test
    fun rejectsHttpWhenCleartextIsDisabled() {
        val result = RelayUrlPolicy.validate("http://192.168.1.20:8080", cleartextAllowed = false)

        assertEquals(null, result.normalizedUrl)
        assertEquals(RelayUrlPolicy.Error.CLEARTEXT_NOT_ALLOWED, result.error)
    }

    @Test
    fun allowsHttpsWhenCleartextIsDisabled() {
        val result = RelayUrlPolicy.validate("https://relay.example.org", cleartextAllowed = false)

        assertEquals("https://relay.example.org/", result.normalizedUrl)
        assertEquals(null, result.error)
    }

    @Test
    fun allowsWssWhenCleartextIsDisabled() {
        val result = RelayUrlPolicy.validate("wss://relay.example.org", cleartextAllowed = false)

        assertEquals("wss://relay.example.org/", result.normalizedUrl)
        assertEquals(null, result.error)
    }

    @Test
    fun rejectsMissingScheme() {
        val result = RelayUrlPolicy.validate("192.168.1.20:8080", cleartextAllowed = true)

        assertEquals(null, result.normalizedUrl)
        assertEquals(RelayUrlPolicy.Error.MISSING_SCHEME, result.error)
    }
}
