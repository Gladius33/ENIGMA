package com.enigma.securechat.crypto

import com.squareup.moshi.Moshi
import com.squareup.moshi.kotlin.reflect.KotlinJsonAdapterFactory
import java.util.Base64
import org.signal.libsignal.protocol.IdentityKey
import org.signal.libsignal.protocol.SessionBuilder
import org.signal.libsignal.protocol.SessionCipher
import org.signal.libsignal.protocol.SignalProtocolAddress
import org.signal.libsignal.protocol.message.CiphertextMessage
import org.signal.libsignal.protocol.message.PreKeySignalMessage
import org.signal.libsignal.protocol.message.SignalMessage
import org.signal.libsignal.protocol.state.SignalProtocolStore

class SignalCryptoEngine(
    private val store: SignalProtocolStore,
    private val preKeyFactory: SignalPreKeyBundleFactory = SignalPreKeyBundleFactory(),
) : CryptoEngine {
    private val moshi = Moshi.Builder().add(KotlinJsonAdapterFactory()).build()
    private val envelopeAdapter = moshi.adapter(SignalMessageEnvelope::class.java)
    private val persistentStore = store as? PersistentSignalProtocolStore

    @Volatile
    private var localDeviceId: String? = null

    @Volatile
    private var localProtocolDeviceId: Int = V1_PROTOCOL_DEVICE_ID

    init {
        persistentStore?.localAddress()?.let { (deviceId, protocolDeviceId) ->
            localDeviceId = deviceId
            localProtocolDeviceId = protocolDeviceId
        }
    }

    override suspend fun ensureIdentity(): LocalIdentity =
        LocalIdentity(encode(store.identityKeyPair.publicKey.serialize()))

    override suspend fun createPreKeyUpload(
        deviceId: String,
        oneTimePreKeyCount: Int,
    ): PreKeyUploadBundle {
        localDeviceId = deviceId
        localProtocolDeviceId = V1_PROTOCOL_DEVICE_ID
        persistentStore?.saveLocalAddress(deviceId, localProtocolDeviceId)
        return preKeyFactory.createAndStoreUploadBundle(
            store = store,
            deviceId = deviceId,
            protocolDeviceId = localProtocolDeviceId,
            oneTimePreKeyCount = oneTimePreKeyCount,
        )
    }

    override suspend fun hasSession(recipient: RemoteDeviceRef): Boolean =
        store.containsSession(recipient.signalAddress())

    override suspend fun ensureSession(recipient: RemoteDeviceBundle) {
        val address = recipient.toRef().signalAddress()
        if (!store.containsSession(address)) {
            SessionBuilder(store, address).process(SignalKeyCodec.toLibsignalPreKeyBundle(recipient))
        }
    }

    override suspend fun encryptText(plaintext: String, recipient: RemoteDeviceBundle): String {
        ensureSession(recipient)
        return encryptText(plaintext, recipient.toRef())
    }

    override suspend fun encryptText(plaintext: String, recipient: RemoteDeviceRef): String {
        val address = recipient.signalAddress()
        require(store.containsSession(address)) { "Missing libsignal session for remote device" }
        val encrypted = SessionCipher(store, address).encrypt(plaintext.toByteArray(Charsets.UTF_8))
        val envelope = SignalMessageEnvelope(
            version = 1,
            algorithm = ALGORITHM,
            messageType = encrypted.signalMessageType(),
            senderDeviceId = requireNotNull(localDeviceId) {
                "Local device id is required before encrypting with Signal"
            },
            senderProtocolDeviceId = localProtocolDeviceId,
            recipientDeviceId = recipient.deviceId,
            recipientProtocolDeviceId = recipient.protocolDeviceId ?: V1_PROTOCOL_DEVICE_ID,
            ciphertext = encode(encrypted.serialize()),
        )
        return encode(envelopeAdapter.toJson(envelope).toByteArray(Charsets.UTF_8))
    }

    override suspend fun decryptText(ciphertext: String): String {
        val envelopeBytes = decode(ciphertext)
        val envelopeJson = envelopeBytes.toString(Charsets.UTF_8)
        envelopeBytes.fill(0)
        val envelope = requireNotNull(envelopeAdapter.fromJson(envelopeJson)) {
            "Invalid Signal envelope"
        }
        require(envelope.version == 1) { "Unsupported Signal envelope version" }
        require(envelope.algorithm == ALGORITHM) { "Unsupported Signal envelope algorithm" }

        val address = SignalProtocolAddress(envelope.senderDeviceId, envelope.senderProtocolDeviceId)
        val sessionCipher = SessionCipher(store, address)
        val signalBytes = decode(envelope.ciphertext)
        val plaintext = when (envelope.messageType) {
            MESSAGE_TYPE_PREKEY -> sessionCipher.decrypt(PreKeySignalMessage(signalBytes))
            MESSAGE_TYPE_SIGNAL -> sessionCipher.decrypt(SignalMessage(signalBytes))
            else -> error("Unsupported libsignal ciphertext type")
        }
        signalBytes.fill(0)

        val text = plaintext.toString(Charsets.UTF_8)
        plaintext.fill(0)
        return text
    }

    override fun signIdentityProof(transcript: ByteArray): ByteArray {
        require(transcript.isNotEmpty() && transcript.size <= MAX_IDENTITY_PROOF_TRANSCRIPT_BYTES) {
            "Invalid identity proof transcript size"
        }
        return store.identityKeyPair.privateKey.calculateSignature(transcript)
    }

    override fun verifyIdentityProof(
        identityPublicKey: String,
        transcript: ByteArray,
        signature: ByteArray,
    ): Boolean {
        if (transcript.isEmpty() || transcript.size > MAX_IDENTITY_PROOF_TRANSCRIPT_BYTES) return false
        if (signature.isEmpty() || signature.size > 128) return false
        return runCatching {
            IdentityKey(decode(identityPublicKey)).publicKey.verifySignature(transcript, signature)
        }.getOrDefault(false)
    }

    private fun RemoteDeviceRef.signalAddress(): SignalProtocolAddress =
        SignalProtocolAddress(
            deviceId,
            protocolDeviceId ?: error("Remote device is missing libsignal protocolDeviceId"),
        )

    private fun CiphertextMessage.signalMessageType(): String = when (type) {
        CiphertextMessage.PREKEY_TYPE -> MESSAGE_TYPE_PREKEY
        CiphertextMessage.WHISPER_TYPE -> MESSAGE_TYPE_SIGNAL
        else -> error("Unsupported libsignal ciphertext type: $type")
    }

    private data class SignalMessageEnvelope(
        val version: Int,
        val algorithm: String,
        val messageType: String,
        val senderDeviceId: String,
        val senderProtocolDeviceId: Int,
        val recipientDeviceId: String,
        val recipientProtocolDeviceId: Int,
        val ciphertext: String,
    )

    private companion object {
        const val V1_PROTOCOL_DEVICE_ID = 1
        const val ALGORITHM = "Signal-Protocol-libsignal-0.76"
        const val MESSAGE_TYPE_PREKEY = "prekey"
        const val MESSAGE_TYPE_SIGNAL = "signal"
        const val MAX_IDENTITY_PROOF_TRANSCRIPT_BYTES = 16 * 1024

        fun encode(bytes: ByteArray): String =
            Base64.getEncoder().withoutPadding().encodeToString(bytes)

        fun decode(value: String): ByteArray =
            Base64.getDecoder().decode(value)
    }
}
