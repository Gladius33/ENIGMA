package com.enigma.securechat.crypto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.fail
import org.junit.Test
import org.signal.libsignal.protocol.IdentityKey
import org.signal.libsignal.protocol.IdentityKeyPair
import org.signal.libsignal.protocol.SessionBuilder
import org.signal.libsignal.protocol.SessionCipher
import org.signal.libsignal.protocol.SignalProtocolAddress
import org.signal.libsignal.protocol.ecc.ECKeyPair
import org.signal.libsignal.protocol.kem.KEMKeyPair
import org.signal.libsignal.protocol.kem.KEMKeyType
import org.signal.libsignal.protocol.message.CiphertextMessage
import org.signal.libsignal.protocol.message.PreKeySignalMessage
import org.signal.libsignal.protocol.message.SignalMessage
import org.signal.libsignal.protocol.state.KyberPreKeyRecord
import org.signal.libsignal.protocol.state.PreKeyBundle
import org.signal.libsignal.protocol.state.PreKeyRecord
import org.signal.libsignal.protocol.state.SignedPreKeyRecord
import org.signal.libsignal.protocol.state.impl.InMemorySignalProtocolStore
import org.signal.libsignal.protocol.util.KeyHelper

class LibsignalProtocolSmokeTest {
    @Test
    fun identitySerializationMatchesDesktopGoldenVectorV1() {
        val expectedPublicKey = byteArrayOf(
            0x05,
            0x13,
            0x2c,
            0x44,
            0x2b,
            0xe0.toByte(),
            0x10,
            0xfb.toByte(),
            0xd5.toByte(),
            0x7e,
            0x72,
            0x60,
            0x33,
            0x28,
            0xaa.toByte(),
            0x76,
            0xe7.toByte(),
            0x1f,
            0xcc.toByte(),
            0xc1.toByte(),
            0x50,
            0x3a,
            0xae.toByte(),
            0x21,
            0x93.toByte(),
            0x27,
            0xd1.toByte(),
            0x4d,
            0x9c.toByte(),
            0x99.toByte(),
            0x93.toByte(),
            0xf4.toByte(),
            0x72,
        )
        val decodedIdentity = IdentityKey(expectedPublicKey)

        assertArrayEquals(expectedPublicKey, decodedIdentity.serialize())
    }

    @Test
    fun rejectsTamperedSignedPreKeyBundle() {
        val bobAddress = SignalProtocolAddress("bob", 1)
        val aliceIdentity = IdentityKeyPair.generate()
        val bobIdentity = IdentityKeyPair.generate()
        val aliceStore = InMemorySignalProtocolStore(
            aliceIdentity,
            KeyHelper.generateRegistrationId(false),
        )
        val bobStore = InMemorySignalProtocolStore(
            bobIdentity,
            KeyHelper.generateRegistrationId(false),
        )
        val tamperedBundle = createAndStorePreKeyBundle(
            bobStore,
            bobIdentity,
            tamperSignedPreKeySignature = true,
        )

        try {
            SessionBuilder(aliceStore, bobAddress).process(tamperedBundle)
            fail("tampered signed pre-key must fail closed")
        } catch (_: Exception) {
            // Expected: libsignal verifies the signed pre-key before establishing a session.
        }
    }

    @Test
    fun establishesSignalSessionAndDecryptsMessages() {
        val aliceAddress = SignalProtocolAddress("alice", 1)
        val bobAddress = SignalProtocolAddress("bob", 1)

        val aliceIdentity = IdentityKeyPair.generate()
        val bobIdentity = IdentityKeyPair.generate()
        val aliceStore = InMemorySignalProtocolStore(
            aliceIdentity,
            KeyHelper.generateRegistrationId(false),
        )
        val bobStore = InMemorySignalProtocolStore(
            bobIdentity,
            KeyHelper.generateRegistrationId(false),
        )

        val bobBundle = createAndStorePreKeyBundle(bobStore, bobIdentity)

        SessionBuilder(aliceStore, bobAddress).process(bobBundle)

        val aliceCipher = SessionCipher(aliceStore, bobAddress)
        val firstPlaintext = "bonjour depuis libsignal".toByteArray(Charsets.UTF_8)
        val firstCiphertext = aliceCipher.encrypt(firstPlaintext)
        val firstSerialized = firstCiphertext.serialize()

        assertEquals(CiphertextMessage.PREKEY_TYPE, firstCiphertext.type)
        assertFalse(firstSerialized.containsSubsequence(firstPlaintext))

        val bobCipher = SessionCipher(bobStore, aliceAddress)
        val decryptedFirst = bobCipher.decrypt(
            PreKeySignalMessage(firstSerialized),
        )

        assertArrayEquals(firstPlaintext, decryptedFirst)

        val replyPlaintext = "reponse libsignal".toByteArray(Charsets.UTF_8)
        val replyCiphertext = bobCipher.encrypt(replyPlaintext)
        val replySerialized = replyCiphertext.serialize()

        assertEquals(CiphertextMessage.WHISPER_TYPE, replyCiphertext.type)
        assertFalse(replySerialized.containsSubsequence(replyPlaintext))

        val decryptedReply = aliceCipher.decrypt(SignalMessage(replySerialized))

        assertArrayEquals(replyPlaintext, decryptedReply)
    }

    private fun ByteArray.containsSubsequence(needle: ByteArray): Boolean {
        if (needle.isEmpty() || needle.size > size) return false
        return indices
            .asSequence()
            .take(size - needle.size + 1)
            .any { start ->
                needle.indices.all { offset -> this[start + offset] == needle[offset] }
            }
    }

    private fun createAndStorePreKeyBundle(
        store: InMemorySignalProtocolStore,
        identity: IdentityKeyPair,
        tamperSignedPreKeySignature: Boolean = false,
    ): PreKeyBundle {
        val preKeyId = 1001
        val preKeyPair = ECKeyPair.generate()
        store.storePreKey(preKeyId, PreKeyRecord(preKeyId, preKeyPair))

        val signedPreKeyId = 2001
        val signedPreKeyPair = ECKeyPair.generate()
        val signedPreKeySignature = identity.privateKey.calculateSignature(
            signedPreKeyPair.publicKey.serialize(),
        )
        store.storeSignedPreKey(
            signedPreKeyId,
            SignedPreKeyRecord(
                signedPreKeyId,
                System.currentTimeMillis(),
                signedPreKeyPair,
                signedPreKeySignature,
            ),
        )
        val bundleSignedPreKeySignature = signedPreKeySignature.copyOf()
        if (tamperSignedPreKeySignature) {
            bundleSignedPreKeySignature[0] =
                (bundleSignedPreKeySignature[0].toInt() xor 0x80).toByte()
        }

        val kyberPreKeyId = 3001
        val kyberKeyPair = KEMKeyPair.generate(KEMKeyType.KYBER_1024)
        val kyberSignature = identity.privateKey.calculateSignature(
            kyberKeyPair.publicKey.serialize(),
        )
        store.storeKyberPreKey(
            kyberPreKeyId,
            KyberPreKeyRecord(
                kyberPreKeyId,
                System.currentTimeMillis(),
                kyberKeyPair,
                kyberSignature,
            ),
        )

        return PreKeyBundle(
            store.localRegistrationId,
            1,
            preKeyId,
            preKeyPair.publicKey,
            signedPreKeyId,
            signedPreKeyPair.publicKey,
            bundleSignedPreKeySignature,
            identity.publicKey,
            kyberPreKeyId,
            kyberKeyPair.publicKey,
            kyberSignature,
        )
    }
}
