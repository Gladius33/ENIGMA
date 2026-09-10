package com.enigma.securechat.crypto

import java.security.SecureRandom
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.signal.libsignal.protocol.IdentityKeyPair
import org.signal.libsignal.protocol.state.impl.InMemorySignalProtocolStore

class SignalPreKeyBundleFactoryTest {
    @Test
    fun storesGeneratedSignalRecordsAndReturnsEnigmaUploadBundle() {
        val store = InMemorySignalProtocolStore(IdentityKeyPair.generate(), 7777)
        val bundle = SignalPreKeyBundleFactory(SecureRandom(byteArrayOf(1, 2, 3))).createAndStoreUploadBundle(
            store = store,
            deviceId = "device-uuid",
            protocolDeviceId = 1,
            oneTimePreKeyCount = 2,
            signedPreKeyId = 101,
            kyberPreKeyId = 102,
            firstOneTimePreKeyId = 201,
            timestampMillis = 1_700_000_000_000,
        )

        assertEquals("device-uuid", bundle.deviceId)
        assertEquals(7777, bundle.registrationId)
        assertEquals(1, bundle.protocolDeviceId)
        assertEquals(101L, bundle.signedPreKey.keyId)
        assertEquals(102L, bundle.kyberPreKey?.keyId)
        assertEquals(listOf(201L, 202L), bundle.oneTimePreKeys.map { it.keyId })
        assertTrue(store.containsSignedPreKey(101))
        assertTrue(store.containsKyberPreKey(102))
        assertTrue(store.containsPreKey(201))
        assertTrue(store.containsPreKey(202))
        assertNotNull(bundle.identityKey)
        assertNotNull(bundle.signedPreKey.publicKey)
        assertNotNull(bundle.signedPreKey.signature)
        assertNotNull(bundle.kyberPreKey?.publicKey)
        assertNotNull(bundle.kyberPreKey?.signature)
    }
}
