package com.enigma.securechat.crypto

import java.util.Base64
import java.util.UUID
import org.signal.libsignal.protocol.IdentityKey
import org.signal.libsignal.protocol.IdentityKeyPair
import org.signal.libsignal.protocol.InvalidKeyIdException
import org.signal.libsignal.protocol.InvalidMessageException
import org.signal.libsignal.protocol.NoSessionException
import org.signal.libsignal.protocol.SignalProtocolAddress
import org.signal.libsignal.protocol.groups.state.SenderKeyRecord
import org.signal.libsignal.protocol.state.IdentityKeyStore
import org.signal.libsignal.protocol.state.KyberPreKeyRecord
import org.signal.libsignal.protocol.state.PreKeyRecord
import org.signal.libsignal.protocol.state.SessionRecord
import org.signal.libsignal.protocol.state.SignalProtocolStore
import org.signal.libsignal.protocol.state.SignedPreKeyRecord
import org.signal.libsignal.protocol.util.KeyHelper

interface SignalRecordStorage {
    fun read(key: String): ByteArray?
    fun write(key: String, value: ByteArray)
    fun remove(key: String)
    fun keys(prefix: String): List<String>
    fun clearAll() {
        keys("").forEach(::remove)
    }
}

class PersistentSignalProtocolStore private constructor(
    private val storage: SignalRecordStorage,
    private val localIdentity: IdentityKeyPair,
    private val registrationIdValue: Int,
) : SignalProtocolStore {
    override fun getIdentityKeyPair(): IdentityKeyPair = localIdentity

    override fun getLocalRegistrationId(): Int = registrationIdValue

    override fun saveIdentity(
        address: SignalProtocolAddress,
        identityKey: IdentityKey,
    ): IdentityKeyStore.IdentityChange {
        val key = remoteIdentityKey(address)
        val existing = storage.read(key)?.let(::identityKeyFromSerialized)
        storage.write(key, identityKey.serialize())
        return if (existing == null || existing == identityKey) {
            IdentityKeyStore.IdentityChange.NEW_OR_UNCHANGED
        } else {
            IdentityKeyStore.IdentityChange.REPLACED_EXISTING
        }
    }

    override fun isTrustedIdentity(
        address: SignalProtocolAddress,
        identityKey: IdentityKey,
        direction: IdentityKeyStore.Direction,
    ): Boolean {
        val trusted = storage.read(remoteIdentityKey(address))?.let(::identityKeyFromSerialized)
        return trusted == null || trusted == identityKey
    }

    override fun getIdentity(address: SignalProtocolAddress): IdentityKey? =
        storage.read(remoteIdentityKey(address))?.let(::identityKeyFromSerialized)

    override fun loadPreKey(preKeyId: Int): PreKeyRecord =
        storage.read(preKeyKey(preKeyId))?.let(::preKeyRecordFromSerialized)
            ?: throw InvalidKeyIdException("No such PreKeyRecord: $preKeyId")

    override fun storePreKey(preKeyId: Int, record: PreKeyRecord) {
        storage.write(preKeyKey(preKeyId), record.serialize())
    }

    override fun containsPreKey(preKeyId: Int): Boolean =
        storage.read(preKeyKey(preKeyId)) != null

    override fun removePreKey(preKeyId: Int) {
        storage.remove(preKeyKey(preKeyId))
    }

    override fun loadSession(address: SignalProtocolAddress): SessionRecord =
        storage.read(sessionKey(address))?.let(::sessionRecordFromSerialized) ?: SessionRecord()

    override fun loadExistingSessions(addresses: MutableList<SignalProtocolAddress>): MutableList<SessionRecord> =
        addresses.map { address ->
            if (!containsSession(address)) {
                throw NoSessionException(address, "no session for $address")
            }
            loadSession(address)
        }.toMutableList()

    override fun getSubDeviceSessions(name: String): MutableList<Int> =
        storage.keys(SESSION_PREFIX)
            .mapNotNull(::addressFromSessionKey)
            .filter { it.first == name && it.second != 1 }
            .map { it.second }
            .toMutableList()

    override fun storeSession(address: SignalProtocolAddress, record: SessionRecord) {
        storage.write(sessionKey(address), record.serialize())
    }

    override fun containsSession(address: SignalProtocolAddress): Boolean =
        storage.read(sessionKey(address)) != null

    override fun deleteSession(address: SignalProtocolAddress) {
        storage.remove(sessionKey(address))
    }

    override fun deleteAllSessions(name: String) {
        storage.keys(SESSION_PREFIX)
            .filter { addressFromSessionKey(it)?.first == name }
            .forEach(storage::remove)
    }

    override fun loadSignedPreKey(signedPreKeyId: Int): SignedPreKeyRecord =
        storage.read(signedPreKeyKey(signedPreKeyId))?.let(::signedPreKeyRecordFromSerialized)
            ?: throw InvalidKeyIdException("No such SignedPreKeyRecord: $signedPreKeyId")

    override fun loadSignedPreKeys(): MutableList<SignedPreKeyRecord> =
        storage.keys(SIGNED_PREKEY_PREFIX)
            .mapNotNull { storage.read(it)?.let(::signedPreKeyRecordFromSerialized) }
            .toMutableList()

    override fun storeSignedPreKey(signedPreKeyId: Int, record: SignedPreKeyRecord) {
        storage.write(signedPreKeyKey(signedPreKeyId), record.serialize())
    }

    override fun containsSignedPreKey(signedPreKeyId: Int): Boolean =
        storage.read(signedPreKeyKey(signedPreKeyId)) != null

    override fun removeSignedPreKey(signedPreKeyId: Int) {
        storage.remove(signedPreKeyKey(signedPreKeyId))
    }

    override fun loadKyberPreKey(kyberPreKeyId: Int): KyberPreKeyRecord =
        storage.read(kyberPreKeyKey(kyberPreKeyId))?.let(::kyberPreKeyRecordFromSerialized)
            ?: throw InvalidKeyIdException("No such KyberPreKeyRecord: $kyberPreKeyId")

    override fun loadKyberPreKeys(): MutableList<KyberPreKeyRecord> =
        storage.keys(KYBER_PREKEY_PREFIX)
            .mapNotNull { storage.read(it)?.let(::kyberPreKeyRecordFromSerialized) }
            .toMutableList()

    override fun storeKyberPreKey(kyberPreKeyId: Int, record: KyberPreKeyRecord) {
        storage.write(kyberPreKeyKey(kyberPreKeyId), record.serialize())
    }

    override fun containsKyberPreKey(kyberPreKeyId: Int): Boolean =
        storage.read(kyberPreKeyKey(kyberPreKeyId)) != null

    override fun markKyberPreKeyUsed(kyberPreKeyId: Int) {
        storage.write(kyberUsedKey(kyberPreKeyId), byteArrayOf(1))
    }

    fun hasKyberPreKeyBeenUsed(kyberPreKeyId: Int): Boolean =
        storage.read(kyberUsedKey(kyberPreKeyId)) != null

    fun saveLocalAddress(deviceId: String, protocolDeviceId: Int) {
        require(deviceId.isNotBlank()) { "deviceId is required" }
        require(protocolDeviceId in 1..127) { "protocolDeviceId must be between 1 and 127" }
        storage.write(LOCAL_DEVICE_ID_KEY, deviceId.toByteArray(Charsets.UTF_8))
        storage.write(LOCAL_PROTOCOL_DEVICE_ID_KEY, protocolDeviceId.toString().toByteArray(Charsets.UTF_8))
    }

    fun localAddress(): Pair<String, Int>? {
        val deviceId = storage.read(LOCAL_DEVICE_ID_KEY)?.toString(Charsets.UTF_8) ?: return null
        val protocolDeviceId = storage.read(LOCAL_PROTOCOL_DEVICE_ID_KEY)
            ?.toString(Charsets.UTF_8)
            ?.toIntOrNull()
            ?: return null
        return deviceId to protocolDeviceId
    }

    override fun storeSenderKey(
        sender: SignalProtocolAddress,
        distributionId: UUID,
        record: SenderKeyRecord,
    ) {
        storage.write(senderKey(sender, distributionId), record.serialize())
    }

    override fun loadSenderKey(
        sender: SignalProtocolAddress,
        distributionId: UUID,
    ): SenderKeyRecord? =
        storage.read(senderKey(sender, distributionId))?.let(::senderKeyRecordFromSerialized)

    private fun identityKeyFromSerialized(serialized: ByteArray): IdentityKey =
        runCatching { IdentityKey(serialized) }.getOrElse { throw AssertionError(it) }

    private fun preKeyRecordFromSerialized(serialized: ByteArray): PreKeyRecord =
        runCatching { PreKeyRecord(serialized) }.getOrElse { throw AssertionError(it) }

    private fun signedPreKeyRecordFromSerialized(serialized: ByteArray): SignedPreKeyRecord =
        runCatching { SignedPreKeyRecord(serialized) }.getOrElse { throw AssertionError(it) }

    private fun kyberPreKeyRecordFromSerialized(serialized: ByteArray): KyberPreKeyRecord =
        runCatching { KyberPreKeyRecord(serialized) }.getOrElse { throw AssertionError(it) }

    private fun sessionRecordFromSerialized(serialized: ByteArray): SessionRecord =
        try {
            SessionRecord(serialized)
        } catch (error: InvalidMessageException) {
            throw AssertionError(error)
        }

    private fun senderKeyRecordFromSerialized(serialized: ByteArray): SenderKeyRecord =
        runCatching { SenderKeyRecord(serialized) }.getOrElse { throw AssertionError(it) }

    private fun remoteIdentityKey(address: SignalProtocolAddress) = "identity:${addressKey(address)}"
    private fun preKeyKey(id: Int) = "$PREKEY_PREFIX$id"
    private fun signedPreKeyKey(id: Int) = "$SIGNED_PREKEY_PREFIX$id"
    private fun kyberPreKeyKey(id: Int) = "$KYBER_PREKEY_PREFIX$id"
    private fun kyberUsedKey(id: Int) = "kyber_used:$id"
    private fun sessionKey(address: SignalProtocolAddress) = "$SESSION_PREFIX${addressKey(address)}"
    private fun senderKey(sender: SignalProtocolAddress, distributionId: UUID) =
        "sender_key:${addressKey(sender)}:$distributionId"

    private fun addressKey(address: SignalProtocolAddress): String =
        "${encode(address.name.toByteArray(Charsets.UTF_8))}:${address.deviceId}"

    private fun addressFromSessionKey(key: String): Pair<String, Int>? {
        if (!key.startsWith(SESSION_PREFIX)) return null
        val parts = key.removePrefix(SESSION_PREFIX).split(":")
        if (parts.size != 2) return null
        val name = runCatching { decode(parts[0]).toString(Charsets.UTF_8) }.getOrNull() ?: return null
        val deviceId = parts[1].toIntOrNull() ?: return null
        return name to deviceId
    }

    companion object {
        private const val LOCAL_IDENTITY_KEY = "local_identity"
        private const val LOCAL_REGISTRATION_ID_KEY = "local_registration_id"
        private const val LOCAL_DEVICE_ID_KEY = "local_device_id"
        private const val LOCAL_PROTOCOL_DEVICE_ID_KEY = "local_protocol_device_id"
        private const val PREKEY_PREFIX = "prekey:"
        private const val SIGNED_PREKEY_PREFIX = "signed_prekey:"
        private const val KYBER_PREKEY_PREFIX = "kyber_prekey:"
        private const val SESSION_PREFIX = "session:"

        fun open(storage: SignalRecordStorage): PersistentSignalProtocolStore {
            val identity = storage.read(LOCAL_IDENTITY_KEY)?.let {
                runCatching { IdentityKeyPair(it) }.getOrElse { error -> throw AssertionError(error) }
            } ?: IdentityKeyPair.generate().also {
                storage.write(LOCAL_IDENTITY_KEY, it.serialize())
            }
            val registrationId = storage.read(LOCAL_REGISTRATION_ID_KEY)
                ?.toString(Charsets.UTF_8)
                ?.toInt()
                ?: KeyHelper.generateRegistrationId(false).also {
                    storage.write(LOCAL_REGISTRATION_ID_KEY, it.toString().toByteArray(Charsets.UTF_8))
                }
            return PersistentSignalProtocolStore(storage, identity, registrationId)
        }

        private fun encode(bytes: ByteArray): String =
            Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)

        private fun decode(value: String): ByteArray =
            Base64.getUrlDecoder().decode(value)
    }
}
