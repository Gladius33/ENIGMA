package com.enigma.securechat.crypto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.signal.libsignal.protocol.SessionBuilder
import org.signal.libsignal.protocol.SessionCipher
import org.signal.libsignal.protocol.SignalProtocolAddress
import org.signal.libsignal.protocol.message.PreKeySignalMessage

class PersistentSignalProtocolStoreTest {
    @Test
    fun persistsIdentityPreKeysAndSessionsAcrossReopen() {
        val aliceStorage = InMemorySignalRecordStorage()
        val bobStorage = InMemorySignalRecordStorage()
        val aliceStore = PersistentSignalProtocolStore.open(aliceStorage)
        val bobStore = PersistentSignalProtocolStore.open(bobStorage)

        val bobUpload = SignalPreKeyBundleFactory().createAndStoreUploadBundle(
            store = bobStore,
            deviceId = "bob-device",
            protocolDeviceId = 1,
            oneTimePreKeyCount = 1,
            signedPreKeyId = 101,
            kyberPreKeyId = 102,
            firstOneTimePreKeyId = 201,
            timestampMillis = 1_700_000_000_000,
        )
        val bobRemote = bobUpload.toRemoteBundle()
        val preKeyBundle = SignalKeyCodec.toLibsignalPreKeyBundle(bobRemote)

        val aliceToBob = SignalProtocolAddress("bob", 1)
        SessionBuilder(aliceStore, aliceToBob).process(preKeyBundle)
        val aliceCipher = SessionCipher(aliceStore, aliceToBob)
        val firstPlaintext = "persisted signal store".toByteArray(Charsets.UTF_8)
        val firstCiphertext = aliceCipher.encrypt(firstPlaintext)

        val bobFromAlice = SignalProtocolAddress("alice", 1)
        val bobCipher = SessionCipher(bobStore, bobFromAlice)
        assertArrayEquals(
            firstPlaintext,
            bobCipher.decrypt(
                PreKeySignalMessage(firstCiphertext.serialize()),
            ),
        )

        val reopenedAliceStore = PersistentSignalProtocolStore.open(aliceStorage)
        val reopenedBobStore = PersistentSignalProtocolStore.open(bobStorage)

        assertEquals(aliceStore.localRegistrationId, reopenedAliceStore.localRegistrationId)
        assertEquals(bobStore.localRegistrationId, reopenedBobStore.localRegistrationId)
        assertTrue(reopenedAliceStore.containsSession(aliceToBob))
        assertTrue(reopenedBobStore.containsSession(bobFromAlice))
        assertTrue(reopenedBobStore.containsSignedPreKey(101))
        assertTrue(reopenedBobStore.containsKyberPreKey(102))

        val replyPlaintext = "reply after reopen".toByteArray(Charsets.UTF_8)
        val replyCiphertext = SessionCipher(reopenedBobStore, bobFromAlice).encrypt(replyPlaintext)
        val decryptedReply = SessionCipher(reopenedAliceStore, aliceToBob)
            .decrypt(org.signal.libsignal.protocol.message.SignalMessage(replyCiphertext.serialize()))

        assertArrayEquals(replyPlaintext, decryptedReply)
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
