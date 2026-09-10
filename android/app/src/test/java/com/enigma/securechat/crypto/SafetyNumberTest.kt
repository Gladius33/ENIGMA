package com.enigma.securechat.crypto

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Test

class SafetyNumberTest {
    @Test
    fun pairFingerprintIsStableAndSymmetric() {
        val aliceFirst = SafetyNumber.pairFingerprint("alice-key", "bob-key")
        val bobFirst = SafetyNumber.pairFingerprint("bob-key", "alice-key")

        assertEquals(aliceFirst, bobFirst)
        assertEquals(aliceFirst, SafetyNumber.pairFingerprint("alice-key", "bob-key"))
    }

    @Test
    fun localFingerprintDiffersAcrossIdentities() {
        assertNotEquals(
            SafetyNumber.localFingerprint("alice-key"),
            SafetyNumber.localFingerprint("bob-key"),
        )
    }
}
