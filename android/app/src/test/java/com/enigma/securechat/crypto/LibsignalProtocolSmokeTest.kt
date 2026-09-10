package com.enigma.securechat.crypto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test
import org.signal.libsignal.protocol.IdentityKeyPair
import org.signal.libsignal.protocol.SessionBuilder
import org.signal.libsignal.protocol.SessionCipher
import org.signal.libsignal.protocol.SignalProtocolAddress
import org.signal.libsignal.protocol.UsePqRatchet
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

        SessionBuilder(aliceStore, bobAddress).process(bobBundle, UsePqRatchet.YES)

        val aliceCipher = SessionCipher(aliceStore, bobAddress)
        val firstPlaintext = "bonjour depuis libsignal".toByteArray(Charsets.UTF_8)
        val firstCiphertext = aliceCipher.encrypt(firstPlaintext)

        assertEquals(CiphertextMessage.PREKEY_TYPE, firstCiphertext.type)

        val bobCipher = SessionCipher(bobStore, aliceAddress)
        val decryptedFirst = bobCipher.decrypt(
            PreKeySignalMessage(firstCiphertext.serialize()),
            UsePqRatchet.YES,
        )

        assertArrayEquals(firstPlaintext, decryptedFirst)

        val replyPlaintext = "reponse libsignal".toByteArray(Charsets.UTF_8)
        val replyCiphertext = bobCipher.encrypt(replyPlaintext)
        val decryptedReply = aliceCipher.decrypt(SignalMessage(replyCiphertext.serialize()))

        assertArrayEquals(replyPlaintext, decryptedReply)
    }

    private fun createAndStorePreKeyBundle(
        store: InMemorySignalProtocolStore,
        identity: IdentityKeyPair,
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
            signedPreKeySignature,
            identity.publicKey,
            kyberPreKeyId,
            kyberKeyPair.publicKey,
            kyberSignature,
        )
    }
}
