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

data class PendingP2pAttachmentCommit(
    val commitId: String,
    val bubbleId: String,
    val senderDeviceId: String,
    val recipientDeviceId: String,
    val clientMessageId: String,
    val attachmentBlobIds: List<String>,
    val createdAt: Long,
)

class P2pAttachmentCommitOutboxStore(
    context: Context,
    private val localCipher: LocalCipher,
    moshi: Moshi = Moshi.Builder().add(KotlinJsonAdapterFactory()).build(),
) {
    private val file = AtomicFile(context.noBackupFilesDir.resolve(FILE_NAME))
    private val mutex = Mutex()
    private val adapter: JsonAdapter<List<PendingP2pAttachmentCommit>> = moshi.adapter(
        Types.newParameterizedType(List::class.java, PendingP2pAttachmentCommit::class.java),
    )

    suspend fun enqueue(
        bubbleId: String,
        senderDeviceId: String,
        recipientDeviceId: String,
        clientMessageId: String,
        attachmentBlobIds: List<String>,
    ): PendingP2pAttachmentCommit = mutex.withLock {
        withContext(Dispatchers.IO) {
            val candidate = PendingP2pAttachmentCommit(
                commitId = UUID.randomUUID().toString(),
                bubbleId = bubbleId,
                senderDeviceId = senderDeviceId,
                recipientDeviceId = recipientDeviceId,
                clientMessageId = clientMessageId,
                attachmentBlobIds = attachmentBlobIds.distinct(),
                createdAt = System.currentTimeMillis(),
            )
            validateEntry(candidate)
            val entries = readEntries().toMutableList()
            entries.firstOrNull {
                it.senderDeviceId == senderDeviceId && it.clientMessageId == clientMessageId
            }?.let { existing ->
                require(existing.bubbleId == bubbleId)
                require(existing.recipientDeviceId == recipientDeviceId)
                require(existing.attachmentBlobIds == candidate.attachmentBlobIds)
                return@withContext existing
            }
            require(entries.size < MAX_PENDING_COMMITS) { "P2P attachment commit outbox is full" }
            entries += candidate
            writeEntries(entries)
            candidate
        }
    }

    suspend fun pending(limit: Int = DEFAULT_BATCH_SIZE): List<PendingP2pAttachmentCommit> = mutex.withLock {
        withContext(Dispatchers.IO) {
            require(limit in 1..MAX_BATCH_SIZE)
            readEntries().sortedBy(PendingP2pAttachmentCommit::createdAt).take(limit)
        }
    }

    suspend fun remove(commitId: String) = mutex.withLock {
        withContext(Dispatchers.IO) {
            requireUuid(commitId, "commit_id")
            val entries = readEntries()
            val remaining = entries.filterNot { it.commitId == commitId }
            if (remaining.size != entries.size) writeEntries(remaining)
        }
    }

    suspend fun clear() = mutex.withLock {
        withContext(Dispatchers.IO) { file.delete() }
    }

    private fun readEntries(): List<PendingP2pAttachmentCommit> {
        if (!file.baseFile.exists()) return emptyList()
        val encryptedBytes = file.openRead().use { it.readBytes() }
        if (encryptedBytes.isEmpty()) return emptyList()
        val encoded = encryptedBytes.toString(Charsets.UTF_8)
        encryptedBytes.fill(0)
        val plaintext = localCipher.decryptFromString(encoded)
        return try {
            adapter.fromJson(plaintext.toString(Charsets.UTF_8)).orEmpty().also { entries ->
                require(entries.size <= MAX_PENDING_COMMITS)
                entries.forEach(::validateEntry)
            }
        } finally {
            plaintext.fill(0)
        }
    }

    private fun writeEntries(entries: List<PendingP2pAttachmentCommit>) {
        require(entries.size <= MAX_PENDING_COMMITS)
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

    private fun validateEntry(entry: PendingP2pAttachmentCommit) {
        requireUuid(entry.commitId, "commit_id")
        requireUuid(entry.bubbleId, "bubble_id")
        requireUuid(entry.senderDeviceId, "sender_device_id")
        requireUuid(entry.recipientDeviceId, "recipient_device_id")
        requireUuid(entry.clientMessageId, "client_message_id")
        require(entry.attachmentBlobIds.isNotEmpty() && entry.attachmentBlobIds.size <= 16)
        require(entry.attachmentBlobIds.distinct().size == entry.attachmentBlobIds.size)
        entry.attachmentBlobIds.forEach { requireUuid(it, "attachment_blob_id") }
        require(entry.createdAt > 0L)
    }

    private fun requireUuid(value: String, field: String) {
        require(runCatching { UUID.fromString(value) }.isSuccess) { "Invalid P2P attachment $field" }
    }

    private companion object {
        const val FILE_NAME = "p2p-attachment-commits.enc"
        const val DEFAULT_BATCH_SIZE = 32
        const val MAX_BATCH_SIZE = 128
        const val MAX_PENDING_COMMITS = 1_024
    }
}
