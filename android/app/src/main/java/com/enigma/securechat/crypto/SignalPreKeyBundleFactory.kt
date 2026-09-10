package com.enigma.securechat.crypto

import java.security.SecureRandom
import org.signal.libsignal.protocol.ecc.ECKeyPair
import org.signal.libsignal.protocol.kem.KEMKeyPair
import org.signal.libsignal.protocol.kem.KEMKeyType
import org.signal.libsignal.protocol.state.KyberPreKeyRecord
import org.signal.libsignal.protocol.state.PreKeyRecord
import org.signal.libsignal.protocol.state.SignalProtocolStore
import org.signal.libsignal.protocol.state.SignedPreKeyRecord

class SignalPreKeyBundleFactory(
    private val random: SecureRandom = SecureRandom(),
) {
    fun createAndStoreUploadBundle(
        store: SignalProtocolStore,
        deviceId: String,
        protocolDeviceId: Int,
        oneTimePreKeyCount: Int = 20,
        signedPreKeyId: Int = randomKeyId(),
        kyberPreKeyId: Int = randomKeyId(),
        firstOneTimePreKeyId: Int = randomKeyId(maxExclusive = Int.MAX_VALUE - oneTimePreKeyCount),
        timestampMillis: Long = System.currentTimeMillis(),
    ): PreKeyUploadBundle {
        require(protocolDeviceId in 1..127) { "protocolDeviceId must be between 1 and 127" }
        require(oneTimePreKeyCount in 1..100) { "oneTimePreKeyCount must be between 1 and 100" }
        require(firstOneTimePreKeyId > 0) { "firstOneTimePreKeyId must be positive" }
        require(firstOneTimePreKeyId + oneTimePreKeyCount <= Int.MAX_VALUE) {
            "one-time prekey range overflows libsignal int range"
        }

        val identity = store.identityKeyPair
        val signedPreKeyPair = ECKeyPair.generate()
        val signedPreKey = SignedPreKeyRecord(
            signedPreKeyId,
            timestampMillis,
            signedPreKeyPair,
            identity.privateKey.calculateSignature(signedPreKeyPair.publicKey.serialize()),
        )
        store.storeSignedPreKey(signedPreKeyId, signedPreKey)

        val kyberKeyPair = KEMKeyPair.generate(KEMKeyType.KYBER_1024)
        val kyberPreKey = KyberPreKeyRecord(
            kyberPreKeyId,
            timestampMillis,
            kyberKeyPair,
            identity.privateKey.calculateSignature(kyberKeyPair.publicKey.serialize()),
        )
        store.storeKyberPreKey(kyberPreKeyId, kyberPreKey)

        val oneTimePreKeys = (0 until oneTimePreKeyCount).map { index ->
            val keyId = firstOneTimePreKeyId + index
            PreKeyRecord(keyId, ECKeyPair.generate()).also {
                store.storePreKey(keyId, it)
            }
        }

        return SignalKeyCodec.createUploadBundle(
            deviceId = deviceId,
            registrationId = store.localRegistrationId,
            protocolDeviceId = protocolDeviceId,
            identity = identity,
            signedPreKey = signedPreKey,
            kyberPreKey = kyberPreKey,
            oneTimePreKeys = oneTimePreKeys,
        )
    }

    private fun randomKeyId(maxExclusive: Int = Int.MAX_VALUE): Int =
        random.nextInt(maxExclusive - 1) + 1
}
