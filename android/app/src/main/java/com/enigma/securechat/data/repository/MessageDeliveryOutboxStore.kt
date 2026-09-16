package com.enigma.securechat.data.repository

import android.content.Context
import android.util.AtomicFile
import com.enigma.securechat.storage.LocalCipher
import com.squareup.moshi.JsonAdapter
import com.squareup.moshi.Moshi
import com.squareup.moshi.Types
import com.squareup.moshi.kotlin.reflect.KotlinJsonAdapterFactory
import java.util.UUID
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

data class PendingMessageDelivery(
    val deliveryId: String,
    val bubbleId: String,
    val senderDeviceId: String,
    val recipientUserId: String,
    val recipientDeviceId: String,
    val clientMessageId: String,
    val messageType: String,
    val ciphertext: String,
    val senderSync: Boolean,
    val createdAt: Long,
)

class MessageDeliveryOutboxStore(
    context: Context,
    private val localCipher: LocalCipher,
    moshi: Moshi = Moshi.Builder().add(KotlinJsonAdapterFactory()).build(),
) {
    private val file = AtomicFile(context.noBackupFilesDir.resolve(FILE_NAME))
    private val mutex = Mutex()
    private val adapter: JsonAdapter<List<PendingMessageDelivery>> = moshi.adapter(
        Types.newParameterizedType(List::class.java, PendingMessageDelivery::class.java),
    )

    suspend fun enqueue(
        bubbleId: String,
        senderDeviceId: String,
        recipientUserId: String,
        recipientDeviceId: String,
        clientMessageId: String,
        messageType: String,
        ciphertext: String,
        senderSync: Boolean,
    ): PendingMessageDelivery = mutex.withLock {
        withContext(Dispatchers.IO) {
            val candidate = PendingMessageDelivery(
                deliveryId = UUID.randomUUID().toString(),
                bubbleId = bubbleId,
                senderDeviceId = senderDeviceId,
                recipientUserId = recipientUserId,
                recipientDeviceId = recipientDeviceId,
                clientMessageId = clientMessageId,
                messageType = messageType,
                ciphertext = ciphertext,
                senderSync = senderSync,
                createdAt = System.currentTimeMillis(),
            )
            validateEntry(candidate)

            val entries = readEntries().toMutableList()
            entries.firstOrNull {
                it.senderDeviceId == senderDeviceId &&
                    it.recipientDeviceId == recipientDeviceId &&
                    it.clientMessageId == clientMessageId
            }?.let { existing ->
                require(existing.bubbleId == candidate.bubbleId)
                require(existing.recipientUserId == candidate.recipientUserId)
                require(existing.messageType == candidate.messageType)
                require(existing.ciphertext == candidate.ciphertext)
                require(existing.senderSync == candidate.senderSync)
                return@withContext existing
            }

            require(entries.size < MAX_PENDING_DELIVERIES) { "Message delivery outbox is full" }
            entries += candidate
            writeEntries(entries)
            candidate
        }
    }

    suspend fun pending(limit: Int = DEFAULT_BATCH_SIZE): List<PendingMessageDelivery> =
        mutex.withLock {
            withContext(Dispatchers.IO) {
                require(limit in 1..MAX_BATCH_SIZE)
                readEntries()
                    .sortedBy(PendingMessageDelivery::createdAt)
                    .take(limit)
            }
        }

    suspend fun pendingFor(clientMessageId: String): List<PendingMessageDelivery> =
        mutex.withLock {
            withContext(Dispatchers.IO) {
                requireUuid(clientMessageId, "client_message_id")
                readEntries()
                    .filter { it.clientMessageId == clientMessageId }
                    .sortedBy(PendingMessageDelivery::createdAt)
            }
        }

    suspend fun hasPendingFor(clientMessageId: String): Boolean =
        pendingFor(clientMessageId).isNotEmpty()

    suspend fun remove(deliveryId: String) = mutex.withLock {
        withContext(Dispatchers.IO) {
            requireUuid(deliveryId, "delivery_id")
            val entries = readEntries()
            val remaining = entries.filterNot { it.deliveryId == deliveryId }
            if (remaining.size != entries.size) {
                writeEntries(remaining)
            }
        }
    }

    suspend fun clear() = mutex.withLock {
        withContext(Dispatchers.IO) {
            file.delete()
        }
    }

    private fun readEntries(): List<PendingMessageDelivery> {
        if (!file.baseFile.exists()) return emptyList()
        val encryptedBytes = file.openRead().use { it.readBytes() }
        if (encryptedBytes.isEmpty()) return emptyList()
        val encoded = encryptedBytes.toString(Charsets.UTF_8)
        encryptedBytes.fill(0)
        val plaintext = localCipher.decryptFromString(encoded)
        return try {
            adapter.fromJson(plaintext.toString(Charsets.UTF_8)).orEmpty().also { entries ->
                require(entries.size <= MAX_PENDING_DELIVERIES)
                entries.forEach(::validateEntry)
            }
        } finally {
            plaintext.fill(0)
        }
    }

    private fun writeEntries(entries: List<PendingMessageDelivery>) {
        require(entries.size <= MAX_PENDING_DELIVERIES)
        entries.forEach(::validateEntry)
        if (entries.isEmpty()) {
            file.delete()
            return
        }

        val plaintext = adapter.toJson(entries).toByteArray(Charsets.UTF_8)
        val encrypted = try {
            localCipher.encryptToString(plaintext).toByteArray(Charsets.UTF_8)
        } finally {
            plaintext.fill(0)
        }
        val stream = file.startWrite()
        try {
            stream.write(encrypted)
            stream.fd.sync()
            file.finishWrite(stream)
        } catch (error: Throwable) {
            file.failWrite(stream)
            throw error
        } finally {
            encrypted.fill(0)
        }
    }

    private fun validateEntry(entry: PendingMessageDelivery) {
        requireUuid(entry.deliveryId, "delivery_id")
        requireUuid(entry.bubbleId, "bubble_id")
        requireUuid(entry.senderDeviceId, "sender_device_id")
        requireUuid(entry.recipientUserId, "recipient_user_id")
        requireUuid(entry.recipientDeviceId, "recipient_device_id")
        requireUuid(entry.clientMessageId, "client_message_id")
        require(entry.messageType in ALLOWED_MESSAGE_TYPES) { "Invalid delivery message_type" }
        require(entry.ciphertext.isNotBlank() && entry.ciphertext.length <= MAX_CIPHERTEXT_CHARS) {
            "Invalid delivery ciphertext"
        }
        require(entry.createdAt > 0L) { "Invalid delivery timestamp" }
    }

    private fun requireUuid(value: String, field: String) {
        require(runCatching { UUID.fromString(value) }.isSuccess) {
            "Invalid message delivery $field"
        }
    }

    private companion object {
        const val FILE_NAME = "message-delivery-outbox.enc"
        const val DEFAULT_BATCH_SIZE = 64
        const val MAX_BATCH_SIZE = 256
        const val MAX_PENDING_DELIVERIES = 4_096
        const val MAX_CIPHERTEXT_CHARS = 2 * 1024 * 1024
        val ALLOWED_MESSAGE_TYPES = setOf(
            "text",
            "opaque",
            "image",
            "video",
            "audio_message",
            "video_message",
            "file",
        )
    }
}
