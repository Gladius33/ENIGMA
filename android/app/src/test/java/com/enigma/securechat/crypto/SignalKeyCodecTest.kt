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
import org.signal.libsignal.protocol.message.PreKeySignalMessage
import org.signal.libsignal.protocol.state.KyberPreKeyRecord
import org.signal.libsignal.protocol.state.PreKeyRecord
import org.signal.libsignal.protocol.state.SignedPreKeyRecord
import org.signal.libsignal.protocol.state.impl.InMemorySignalProtocolStore
import org.signal.libsignal.protocol.util.KeyHelper

class SignalKeyCodecTest {
    @Test
    fun enigmaKeyBundleRoundTripCanBuildLibsignalSession() {
        val aliceStore = InMemorySignalProtocolStore(
            IdentityKeyPair.generate(),
            KeyHelper.generateRegistrationId(false),
        )
        val bobIdentity = IdentityKeyPair.generate()
        val bobRegistrationId = KeyHelper.generateRegistrationId(false)
        val bobStore = InMemorySignalProtocolStore(bobIdentity, bobRegistrationId)

        val bobSignalMaterial = createAndStoreBobMaterial(bobStore, bobIdentity)
        val upload = SignalKeyCodec.createUploadBundle(
            deviceId = "bob-device-uuid",
            registrationId = bobRegistrationId,
            protocolDeviceId = 1,
            identity = bobIdentity,
            signedPreKey = bobSignalMaterial.signedPreKey,
            kyberPreKey = bobSignalMaterial.kyberPreKey,
            oneTimePreKeys = listOf(bobSignalMaterial.oneTimePreKey),
        )
        val remote = upload.toRemoteBundle()
        val preKeyBundle = SignalKeyCodec.toLibsignalPreKeyBundle(remote)

        assertEquals(bobRegistrationId, upload.registrationId)
        assertEquals(1, upload.protocolDeviceId)
        assertEquals(bobSignalMaterial.kyberPreKey.id.toLong(), upload.kyberPreKey?.keyId)

        val aliceToBobAddress = SignalProtocolAddress("bob", 1)
        SessionBuilder(aliceStore, aliceToBobAddress).process(preKeyBundle, UsePqRatchet.YES)
        val aliceCipher = SessionCipher(aliceStore, aliceToBobAddress)
        val plaintext = "message via enigma key codec".toByteArray(Charsets.UTF_8)
        val ciphertext = aliceCipher.encrypt(plaintext)

        val bobFromAliceAddress = SignalProtocolAddress("alice", 1)
        val bobCipher = SessionCipher(bobStore, bobFromAliceAddress)
        val decrypted = bobCipher.decrypt(
            PreKeySignalMessage(ciphertext.serialize()),
            UsePqRatchet.YES,
        )

        assertArrayEquals(plaintext, decrypted)
    }

    private fun createAndStoreBobMaterial(
        store: InMemorySignalProtocolStore,
        identity: IdentityKeyPair,
    ): BobSignalMaterial {
        val preKeyId = 11
        val preKey = PreKeyRecord(preKeyId, ECKeyPair.generate())
        store.storePreKey(preKeyId, preKey)

        val signedPreKeyId = 12
        val signedPreKeyPair = ECKeyPair.generate()
        val signedPreKey = SignedPreKeyRecord(
            signedPreKeyId,
            System.currentTimeMillis(),
            signedPreKeyPair,
            identity.privateKey.calculateSignature(signedPreKeyPair.publicKey.serialize()),
        )
        store.storeSignedPreKey(signedPreKeyId, signedPreKey)

        val kyberPreKeyId = 13
        val kyberKeyPair = KEMKeyPair.generate(KEMKeyType.KYBER_1024)
        val kyberPreKey = KyberPreKeyRecord(
            kyberPreKeyId,
            System.currentTimeMillis(),
            kyberKeyPair,
            identity.privateKey.calculateSignature(kyberKeyPair.publicKey.serialize()),
        )
        store.storeKyberPreKey(kyberPreKeyId, kyberPreKey)

        return BobSignalMaterial(
            oneTimePreKey = preKey,
            signedPreKey = signedPreKey,
            kyberPreKey = kyberPreKey,
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

    private data class BobSignalMaterial(
        val oneTimePreKey: PreKeyRecord,
        val signedPreKey: SignedPreKeyRecord,
        val kyberPreKey: KyberPreKeyRecord,
    )
}
