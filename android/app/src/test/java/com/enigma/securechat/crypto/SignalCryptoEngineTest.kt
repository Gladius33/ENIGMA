package com.enigma.securechat.crypto

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SignalCryptoEngineTest {
    @Test
    fun encryptsDecryptsAndKeepsSessionsAcrossReopen() = kotlinx.coroutines.test.runTest {
        val aliceStorage = InMemorySignalRecordStorage()
        val bobStorage = InMemorySignalRecordStorage()
        val aliceEngine = SignalCryptoEngine(PersistentSignalProtocolStore.open(aliceStorage))
        val bobEngine = SignalCryptoEngine(PersistentSignalProtocolStore.open(bobStorage))

        val aliceUpload = aliceEngine.createPreKeyUpload("alice-device", oneTimePreKeyCount = 1)
        val bobUpload = bobEngine.createPreKeyUpload("bob-device", oneTimePreKeyCount = 1)
        val bobRef = RemoteDeviceRef("bob-device", bobUpload.protocolDeviceId)

        assertFalse(aliceEngine.hasSession(bobRef))

        val firstCiphertext = aliceEngine.encryptText("bonjour bob", bobUpload.toRemoteBundle())
        assertTrue(aliceEngine.hasSession(bobRef))
        assertEquals("bonjour bob", bobEngine.decryptText(firstCiphertext))

        val reopenedAliceEngine = SignalCryptoEngine(PersistentSignalProtocolStore.open(aliceStorage))
        val reopenedBobEngine = SignalCryptoEngine(PersistentSignalProtocolStore.open(bobStorage))

        assertTrue(reopenedAliceEngine.hasSession(bobRef))
        val replyCiphertext = reopenedBobEngine.encryptText("bonjour alice", aliceUpload.toRemoteBundle())
        assertEquals("bonjour alice", reopenedAliceEngine.decryptText(replyCiphertext))
    }

    @Test
    fun identityProofOnlyVerifiesForMatchingIdentityAndTranscript() = kotlinx.coroutines.test.runTest {
        val aliceEngine = SignalCryptoEngine(PersistentSignalProtocolStore.open(InMemorySignalRecordStorage()))
        val bobEngine = SignalCryptoEngine(PersistentSignalProtocolStore.open(InMemorySignalRecordStorage()))
        val aliceIdentity = aliceEngine.ensureIdentity().identityPublicKey
        val bobIdentity = bobEngine.ensureIdentity().identityPublicKey
        val transcript = "ENIGMA_P2P_AUTH_V1\nsession\nbubble-a\nalice\nbob".toByteArray()
        val signature = aliceEngine.signIdentityProof(transcript)

        assertTrue(bobEngine.verifyIdentityProof(aliceIdentity, transcript, signature))
        assertFalse(bobEngine.verifyIdentityProof(bobIdentity, transcript, signature))
        assertFalse(
            bobEngine.verifyIdentityProof(
                aliceIdentity,
                "ENIGMA_P2P_AUTH_V1\nsession\nbubble-b\nalice\nbob".toByteArray(),
                signature,
            ),
        )
    }

    private fun PreKeyUploadBundle.toRemoteBundle(): RemoteDeviceBundle = RemoteDeviceBundle(
        deviceId = deviceId,
        identityKey = identityKey,
        registrationId = registrationId,
        protocolDeviceId = protocolDeviceId,
        signedPreKey = RemoteSignedPreKey(
            keyId = signedPreKey.keyId,
            publicKey = signedPreKey.publicKey,
            signature = signedPreKey.signature,
        ),
        kyberPreKey = requireNotNull(kyberPreKey).let {
            RemoteKyberPreKey(
                keyId = it.keyId,
                publicKey = it.publicKey,
                signature = it.signature,
            )
        },
        oneTimePreKey = oneTimePreKeys.first().let {
            RemoteOneTimePreKey(
                keyId = it.keyId,
                publicKey = it.publicKey,
            )
        },
    )

    private class InMemorySignalRecordStorage : SignalRecordStorage {
        private val values = linkedMapOf<String, ByteArray>()

        override fun read(key: String): ByteArray? = values[key]?.copyOf()

        override fun write(key: String, value: ByteArray) {
            values[key] = value.copyOf()
        }

        override fun remove(key: String) {
            values.remove(key)
        }

        override fun keys(prefix: String): List<String> =
            values.keys.filter { it.startsWith(prefix) }
    }
}
