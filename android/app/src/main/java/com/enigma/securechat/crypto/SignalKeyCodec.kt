package com.enigma.securechat.crypto

import java.util.Base64
import org.signal.libsignal.protocol.IdentityKey
import org.signal.libsignal.protocol.IdentityKeyPair
import org.signal.libsignal.protocol.ecc.ECPublicKey
import org.signal.libsignal.protocol.kem.KEMPublicKey
import org.signal.libsignal.protocol.state.KyberPreKeyRecord
import org.signal.libsignal.protocol.state.PreKeyBundle
import org.signal.libsignal.protocol.state.PreKeyRecord
import org.signal.libsignal.protocol.state.SignedPreKeyRecord

object SignalKeyCodec {
    fun createUploadBundle(
        deviceId: String,
        registrationId: Int,
        protocolDeviceId: Int,
        identity: IdentityKeyPair,
        signedPreKey: SignedPreKeyRecord,
        kyberPreKey: KyberPreKeyRecord,
        oneTimePreKeys: List<PreKeyRecord>,
    ): PreKeyUploadBundle {
        require(registrationId > 0) { "registrationId must be positive" }
        require(protocolDeviceId in 1..127) { "protocolDeviceId must be between 1 and 127" }

        return PreKeyUploadBundle(
            deviceId = deviceId,
            identityKey = encode(identity.publicKey.serialize()),
            registrationId = registrationId,
            protocolDeviceId = protocolDeviceId,
            signedPreKey = SignedPreKeyUpload(
                keyId = signedPreKey.id.toLong(),
                publicKey = encode(signedPreKey.keyPair.publicKey.serialize()),
                signature = encode(signedPreKey.signature),
            ),
            kyberPreKey = KyberPreKeyUpload(
                keyId = kyberPreKey.id.toLong(),
                publicKey = encode(kyberPreKey.keyPair.publicKey.serialize()),
                signature = encode(kyberPreKey.signature),
            ),
            oneTimePreKeys = oneTimePreKeys.map { preKey ->
                OneTimePreKeyUpload(
                    keyId = preKey.id.toLong(),
                    publicKey = encode(preKey.keyPair.publicKey.serialize()),
                )
            },
        )
    }

    fun toLibsignalPreKeyBundle(remote: RemoteDeviceBundle): PreKeyBundle {
        val registrationId = requireNotNull(remote.registrationId) {
            "Remote bundle is missing libsignal registrationId"
        }
        val protocolDeviceId = requireNotNull(remote.protocolDeviceId) {
            "Remote bundle is missing libsignal protocolDeviceId"
        }
        val kyberPreKey = requireNotNull(remote.kyberPreKey) {
            "Remote bundle is missing libsignal Kyber prekey"
        }
        require(registrationId > 0) { "registrationId must be positive" }
        require(protocolDeviceId in 1..127) { "protocolDeviceId must be between 1 and 127" }

        val oneTimePreKeyId = remote.oneTimePreKey
            ?.keyId
            ?.toSignalInt("oneTimePreKey.keyId")
            ?: PreKeyBundle.NULL_PRE_KEY_ID
        val oneTimePreKeyPublic = remote.oneTimePreKey?.let {
            ECPublicKey(decode(it.publicKey))
        }

        return PreKeyBundle(
            registrationId,
            protocolDeviceId,
            oneTimePreKeyId,
            oneTimePreKeyPublic,
            remote.signedPreKey.keyId.toSignalInt("signedPreKey.keyId"),
            ECPublicKey(decode(remote.signedPreKey.publicKey)),
            decode(remote.signedPreKey.signature),
            IdentityKey(decode(remote.identityKey)),
            kyberPreKey.keyId.toSignalInt("kyberPreKey.keyId"),
            KEMPublicKey(decode(kyberPreKey.publicKey)),
            decode(kyberPreKey.signature),
        )
    }

    private fun Long.toSignalInt(field: String): Int {
        require(this in 0..Int.MAX_VALUE.toLong()) { "$field is outside libsignal int range" }
        return toInt()
    }

    private fun encode(bytes: ByteArray): String =
        Base64.getEncoder().withoutPadding().encodeToString(bytes)

    private fun decode(value: String): ByteArray =
        Base64.getDecoder().decode(value)
}
