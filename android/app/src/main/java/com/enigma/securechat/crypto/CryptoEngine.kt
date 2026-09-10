package com.enigma.securechat.crypto

data class LocalIdentity(
    val identityPublicKey: String,
)

data class SignedPreKeyUpload(
    val keyId: Long,
    val publicKey: String,
    val signature: String,
)

data class OneTimePreKeyUpload(
    val keyId: Long,
    val publicKey: String,
)

data class KyberPreKeyUpload(
    val keyId: Long,
    val publicKey: String,
    val signature: String,
)

data class PreKeyUploadBundle(
    val deviceId: String,
    val identityKey: String,
    val registrationId: Int? = null,
    val protocolDeviceId: Int? = null,
    val signedPreKey: SignedPreKeyUpload,
    val kyberPreKey: KyberPreKeyUpload? = null,
    val oneTimePreKeys: List<OneTimePreKeyUpload>,
)

data class RemoteSignedPreKey(
    val keyId: Long,
    val publicKey: String,
    val signature: String,
)

data class RemoteOneTimePreKey(
    val keyId: Long,
    val publicKey: String,
)

data class RemoteKyberPreKey(
    val keyId: Long,
    val publicKey: String,
    val signature: String,
)

data class RemoteDeviceBundle(
    val deviceId: String,
    val identityKey: String,
    val registrationId: Int? = null,
    val protocolDeviceId: Int? = null,
    val signedPreKey: RemoteSignedPreKey,
    val kyberPreKey: RemoteKyberPreKey? = null,
    val oneTimePreKey: RemoteOneTimePreKey?,
)

data class RemoteDeviceRef(
    val deviceId: String,
    val protocolDeviceId: Int? = null,
)

fun RemoteDeviceBundle.toRef(): RemoteDeviceRef = RemoteDeviceRef(
    deviceId = deviceId,
    protocolDeviceId = protocolDeviceId,
)

interface CryptoEngine {
    suspend fun ensureIdentity(): LocalIdentity
    suspend fun createPreKeyUpload(deviceId: String, oneTimePreKeyCount: Int = 20): PreKeyUploadBundle
    suspend fun hasSession(recipient: RemoteDeviceRef): Boolean
    suspend fun ensureSession(recipient: RemoteDeviceBundle)
    suspend fun encryptText(plaintext: String, recipient: RemoteDeviceRef): String
    suspend fun encryptText(plaintext: String, recipient: RemoteDeviceBundle): String {
        ensureSession(recipient)
        return encryptText(plaintext, recipient.toRef())
    }
    suspend fun decryptText(ciphertext: String): String

    /** Signs a bounded P2P channel transcript with the persistent Signal identity private key. */
    fun signIdentityProof(transcript: ByteArray): ByteArray =
        error("P2P identity proofs are unavailable for this crypto engine")

    /** Verifies a P2P channel transcript against the already-known remote Signal identity key. */
    fun verifyIdentityProof(
        identityPublicKey: String,
        transcript: ByteArray,
        signature: ByteArray,
    ): Boolean = false
}
