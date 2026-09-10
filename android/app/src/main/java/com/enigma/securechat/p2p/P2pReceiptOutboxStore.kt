package com.enigma.securechat.p2p

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

data class PendingP2pReadReceipt(
    val receiptId: String,
    val bubbleId: String,
    val recipientDeviceId: String,
    val clientMessageId: String,
    val remoteMessageId: String?,
    val createdAt: Long,
)

class P2pReceiptOutboxStore(
    context: Context,
    private val localCipher: LocalCipher,
    moshi: Moshi = Moshi.Builder().add(KotlinJsonAdapterFactory()).build(),
) {
    private val file = AtomicFile(context.noBackupFilesDir.resolve(FILE_NAME))
    private val mutex = Mutex()
    private val adapter: JsonAdapter<List<PendingP2pReadReceipt>> = moshi.adapter(
        Types.newParameterizedType(List::class.java, PendingP2pReadReceipt::class.java),
    )

    suspend fun enqueue(
        bubbleId: String,
        recipientDeviceId: String,
        clientMessageId: String,
        remoteMessageId: String?,
    ): PendingP2pReadReceipt = mutex.withLock {
        withContext(Dispatchers.IO) {
            validateField(bubbleId, "bubble_id")
            validateField(recipientDeviceId, "recipient_device_id")
            validateField(clientMessageId, "client_message_id")
            remoteMessageId?.let { validateField(it, "remote_message_id") }

            val entries = readEntries().toMutableList()
            entries.firstOrNull {
                it.bubbleId == bubbleId &&
                    it.recipientDeviceId == recipientDeviceId &&
                    it.clientMessageId == clientMessageId
            }?.let { existing ->
                if (existing.remoteMessageId == null && remoteMessageId != null) {
                    val upgraded = existing.copy(remoteMessageId = remoteMessageId)
                    entries[entries.indexOf(existing)] = upgraded
                    writeEntries(entries)
                    return@withContext upgraded
                }
                return@withContext existing
            }

            require(entries.size < MAX_PENDING_RECEIPTS) { "P2P receipt outbox is full" }
            val pending = PendingP2pReadReceipt(
                receiptId = UUID.randomUUID().toString(),
                bubbleId = bubbleId,
                recipientDeviceId = recipientDeviceId,
                clientMessageId = clientMessageId,
                remoteMessageId = remoteMessageId,
                createdAt = System.currentTimeMillis(),
            )
            entries += pending
            writeEntries(entries)
            pending
        }
    }

    suspend fun pending(limit: Int = DEFAULT_BATCH_SIZE): List<PendingP2pReadReceipt> = mutex.withLock {
        withContext(Dispatchers.IO) {
            require(limit in 1..MAX_BATCH_SIZE)
            readEntries()
                .sortedBy(PendingP2pReadReceipt::createdAt)
                .take(limit)
        }
    }

    suspend fun remove(receiptId: String) = mutex.withLock {
        withContext(Dispatchers.IO) {
            validateField(receiptId, "receipt_id")
            val entries = readEntries()
            val remaining = entries.filterNot { it.receiptId == receiptId }
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

    private fun readEntries(): List<PendingP2pReadReceipt> {
        if (!file.baseFile.exists()) return emptyList()
        val encryptedBytes = file.openRead().use { it.readBytes() }
        if (encryptedBytes.isEmpty()) return emptyList()
        val encoded = encryptedBytes.toString(Charsets.UTF_8)
        encryptedBytes.fill(0)
        val plaintext = localCipher.decryptFromString(encoded)
        return try {
            adapter.fromJson(plaintext.toString(Charsets.UTF_8)).orEmpty().also { entries ->
                require(entries.size <= MAX_PENDING_RECEIPTS) { "P2P receipt outbox exceeds limit" }
                entries.forEach(::validateEntry)
            }
        } finally {
            plaintext.fill(0)
        }
    }

    private fun writeEntries(entries: List<PendingP2pReadReceipt>) {
        require(entries.size <= MAX_PENDING_RECEIPTS)
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

    private fun validateEntry(entry: PendingP2pReadReceipt) {
        validateField(entry.receiptId, "receipt_id")
        validateField(entry.bubbleId, "bubble_id")
        validateField(entry.recipientDeviceId, "recipient_device_id")
        validateField(entry.clientMessageId, "client_message_id")
        entry.remoteMessageId?.let { validateField(it, "remote_message_id") }
        require(entry.createdAt > 0) { "Invalid P2P receipt timestamp" }
    }

    private fun validateField(value: String, field: String) {
        require(value.isNotBlank() && value.length <= MAX_FIELD_LENGTH) { "Invalid P2P receipt $field" }
    }

    private companion object {
        const val FILE_NAME = "p2p-read-receipts.enc"
        const val DEFAULT_BATCH_SIZE = 64
        const val MAX_BATCH_SIZE = 256
        const val MAX_PENDING_RECEIPTS = 4_096
        const val MAX_FIELD_LENGTH = 512
    }
}
