package com.enigma.securechat.crypto

import java.io.File
import java.util.Base64
import java.util.Properties
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.signal.libsignal.protocol.IdentityKey
import org.signal.libsignal.protocol.IdentityKeyPair
import org.signal.libsignal.protocol.SessionBuilder
import org.signal.libsignal.protocol.SessionCipher
import org.signal.libsignal.protocol.SignalProtocolAddress
import org.signal.libsignal.protocol.ecc.ECKeyPair
import org.signal.libsignal.protocol.ecc.ECPrivateKey
import org.signal.libsignal.protocol.ecc.ECPublicKey
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
    fun identityDerivationMatchesDesktopGoldenVectorV1() {
        val fixedPrivateKeyInput = ByteArray(32) { 0x42.toByte() }
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
        val privateKey = ECPrivateKey(fixedPrivateKeyInput)
        val derivedIdentity = IdentityKey(privateKey.getPublicKey())
        val decodedIdentity = IdentityKey(expectedPublicKey)

        // The cross-runtime contract is the derived public identity. libsignal may normalize/clamp
        // private material internally, so its private serialization is intentionally not asserted.
        assertArrayEquals(expectedPublicKey, derivedIdentity.serialize())
        assertArrayEquals(expectedPublicKey, decodedIdentity.serialize())
    }

    @Test
    fun preKeyDerivationMatchesDesktopGoldenVectorV1() {
        val fixedPrivateKeyInput = ByteArray(32) { 0x24.toByte() }
        val expectedPublicKey = byteArrayOf(
            0x05,
            0x04,
            0xbc.toByte(),
            0xd2.toByte(),
            0xe0.toByte(),
            0xd0.toByte(),
            0x0f,
            0x2c,
            0xce.toByte(),
            0x5f,
            0xe8.toByte(),
            0xf1.toByte(),
            0xc6.toByte(),
            0xc2.toByte(),
            0xfb.toByte(),
            0xec.toByte(),
            0x5c,
            0x07,
            0xfa.toByte(),
            0x56,
            0xe3.toByte(),
            0xaa.toByte(),
            0x5c,
            0x88.toByte(),
            0xa5.toByte(),
            0x68,
            0x99.toByte(),
            0x75,
            0xd8.toByte(),
            0x8b.toByte(),
            0x3f,
            0xce.toByte(),
            0x05,
        )
        val privateKey = ECPrivateKey(fixedPrivateKeyInput)

        // This is the same deterministic public pre-key contract asserted by the Rust desktop
        // runtime. Session/ciphertext interoperability remains a separate SIG-001 release gate.
        assertArrayEquals(expectedPublicKey, privateKey.getPublicKey().serialize())
    }

    @Test
    fun xeddsaVerificationMatchesDesktopGoldenVectorV1() {
        val identityPublicKey = byteArrayOf(
            0xab.toByte(), 0x7e, 0x71, 0x7d, 0x4a, 0x16, 0x3b, 0x7d,
            0x9a.toByte(), 0x1d, 0x80.toByte(), 0x71, 0xdf.toByte(), 0xe9.toByte(), 0xdc.toByte(), 0xf8.toByte(),
            0xcd.toByte(), 0xcd.toByte(), 0x1c, 0xea.toByte(), 0x33, 0x39, 0xb6.toByte(), 0x35,
            0x6b, 0xe8.toByte(), 0x4d, 0x88.toByte(), 0x7e, 0x32, 0x2c, 0x64,
        )
        val signedPreKeyPublic = byteArrayOf(
            0x05, 0xed.toByte(), 0xce.toByte(), 0x9d.toByte(), 0x9c.toByte(), 0x41, 0x5c, 0xa7.toByte(),
            0x8c.toByte(), 0xb7.toByte(), 0x25, 0x2e, 0x72, 0xc2.toByte(), 0xc4.toByte(), 0xa5.toByte(),
            0x54, 0xd3.toByte(), 0xeb.toByte(), 0x29, 0x48, 0x5a, 0x0e, 0x1d,
            0x50, 0x31, 0x18, 0xd1.toByte(), 0xa8.toByte(), 0x2d, 0x99.toByte(), 0xfb.toByte(),
            0x4a,
        )
        val signature = byteArrayOf(
            0x5d, 0xe8.toByte(), 0x8c.toByte(), 0xa9.toByte(), 0xa8.toByte(), 0x9b.toByte(), 0x4a, 0x11,
            0x5d, 0xa7.toByte(), 0x91.toByte(), 0x09, 0xc6.toByte(), 0x7c, 0x9c.toByte(), 0x74,
            0x64, 0xa3.toByte(), 0xe4.toByte(), 0x18, 0x02, 0x74, 0xf1.toByte(), 0xcb.toByte(),
            0x8c.toByte(), 0x63, 0xc2.toByte(), 0x98.toByte(), 0x4e, 0x28, 0x6d, 0xfb.toByte(),
            0xed.toByte(), 0xe8.toByte(), 0x2d, 0xeb.toByte(), 0x9d.toByte(), 0xcd.toByte(), 0x9f.toByte(), 0xae.toByte(),
            0x0b, 0xfb.toByte(), 0xb8.toByte(), 0x21, 0x56, 0x9b.toByte(), 0x3d, 0x90.toByte(),
            0x01, 0xbd.toByte(), 0x81.toByte(), 0x30, 0xcd.toByte(), 0x11, 0xd4.toByte(), 0x86.toByte(),
            0xce.toByte(), 0xf0.toByte(), 0x47, 0xbd.toByte(), 0x60, 0xb8.toByte(), 0x6e, 0x88.toByte(),
        )
        val identityPublic = ECPublicKey.fromPublicKeyBytes(identityPublicKey)

        assertTrue(identityPublic.verifySignature(signedPreKeyPublic, signature))

        val tamperedSignature = signature.copyOf()
        tamperedSignature[0] = (tamperedSignature[0].toInt() xor 0x01).toByte()
        assertFalse(identityPublic.verifySignature(signedPreKeyPublic, tamperedSignature))
    }

    @Test
    fun desktopRustPreKeyCiphertextRoundTripsBackToRust() {
        val fixturePath = System.getenv("ENIGMA_ANDROID_INTEROP_FIXTURE") ?: return
        val replyPath = requireNotNull(System.getenv("ENIGMA_ANDROID_INTEROP_REPLY")) {
            "ENIGMA_ANDROID_INTEROP_REPLY is required when the cross-runtime fixture is enabled"
        }
        val fixture = Properties().apply {
            File(fixturePath).inputStream().buffered().use(::load)
        }
        fun property(name: String): String = requireNotNull(fixture.getProperty(name)) {
            "Missing cross-runtime fixture property: $name"
        }
        fun decoded(name: String): ByteArray = Base64.getDecoder().decode(property(name))

        assertEquals("1", property("version"))

        val bobIdentity = IdentityKeyPair(decoded("bob_identity"))
        val bobStore = InMemorySignalProtocolStore(
            bobIdentity,
            property("bob_registration_id").toInt(),
        )
        val preKeyId = property("bob_pre_key_id").toInt()
        val signedPreKeyId = property("bob_signed_pre_key_id").toInt()
        val kyberPreKeyId = property("bob_kyber_pre_key_id").toInt()
        bobStore.storePreKey(preKeyId, PreKeyRecord(decoded("bob_pre_key_record")))
        bobStore.storeSignedPreKey(
            signedPreKeyId,
            SignedPreKeyRecord(decoded("bob_signed_pre_key_record")),
        )
        bobStore.storeKyberPreKey(
            kyberPreKeyId,
            KyberPreKeyRecord(decoded("bob_kyber_pre_key_record")),
        )

        val firstCiphertext = decoded("first_ciphertext")
        val firstPlaintext = decoded("first_plaintext")
        assertFalse(firstCiphertext.containsSubsequence(firstPlaintext))

        val bobCipher = SessionCipher(
            bobStore,
            SignalProtocolAddress("alice", 1),
        )
        val decrypted = bobCipher.decrypt(PreKeySignalMessage(firstCiphertext))
        assertArrayEquals(firstPlaintext, decrypted)

        val replyPlaintext = decoded("reply_plaintext")
        val reply = bobCipher.encrypt(replyPlaintext)
        val replyCiphertext = reply.serialize()
        assertEquals(CiphertextMessage.WHISPER_TYPE, reply.type)
        assertFalse(replyCiphertext.containsSubsequence(replyPlaintext))

        val encoder = Base64.getEncoder()
        File(replyPath).writeText(
            buildString {
                appendLine("version=1")
                appendLine("reply_ciphertext=${encoder.encodeToString(replyCiphertext)}")
            },
        )
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
    fun rejectsTamperedKyberPreKeyBundle() {
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
            tamperKyberPreKeySignature = true,
        )

        try {
            SessionBuilder(aliceStore, bobAddress).process(tamperedBundle)
            fail("tampered kyber pre-key must fail closed")
        } catch (_: Exception) {
            // Expected: libsignal verifies the PQ pre-key before establishing a session.
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
        tamperKyberPreKeySignature: Boolean = false,
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
        val bundleKyberSignature = kyberSignature.copyOf()
        if (tamperKyberPreKeySignature) {
            bundleKyberSignature[0] =
                (bundleKyberSignature[0].toInt() xor 0x80).toByte()
        }

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
            bundleKyberSignature,
        )
    }
}
