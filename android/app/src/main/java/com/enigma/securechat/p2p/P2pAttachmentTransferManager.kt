package com.enigma.securechat.p2p

import com.enigma.securechat.storage.SecureFileStore
import java.io.File
import java.io.FileOutputStream
import java.io.InputStream
import java.security.MessageDigest
import java.util.concurrent.ConcurrentHashMap
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.withTimeoutOrNull

class P2pAttachmentTransferManager(
    private val engine: P2pEngine,
    private val fileStore: SecureFileStore,
    private val controlCodec: P2pAttachmentControlCodec = P2pAttachmentControlCodec(),
    private val readyTimeoutMillis: Long = 5_000,
) {
    private val readyWaiters = ConcurrentHashMap<String, CompletableDeferred<List<P2pAttachmentOffset>>>()
    private val inbound = ConcurrentHashMap<String, InboundTransfer>()

    init {
        require(readyTimeoutMillis in 1_000..30_000)
    }

    fun isControl(payload: String): Boolean = controlCodec.isAttachmentControl(payload)

    suspend fun sendAttachments(
        sessionId: String,
        clientMessageId: String,
        attachments: List<P2pAttachmentSpec>,
    ): Boolean {
        if (attachments.isEmpty() || attachments.size > 16) return false
        for (attachment in attachments) {
            val file = fileStore.encryptedAttachment(attachment.blobId) ?: return false
            if (file.length() != attachment.sizeBytes || sha256(file) != attachment.sha256) return false
        }

        val key = key(sessionId, clientMessageId)
        val ready = CompletableDeferred<List<P2pAttachmentOffset>>()
        readyWaiters[key] = ready
        val offered = engine.send(
            sessionId,
            controlCodec.encode(P2pAttachmentControl.Offer(clientMessageId, attachments)),
        )
        if (!offered) {
            readyWaiters.remove(key)
            return false
        }

        val offsets = withTimeoutOrNull(readyTimeoutMillis) { ready.await() }
        readyWaiters.remove(key)
        if (offsets == null || offsets.size != attachments.size) return false
        val offsetByBlob = offsets.associate { it.blobId to it.offset }
        if (offsetByBlob.size != attachments.size) return false

        for (attachment in attachments) {
            val offset = offsetByBlob[attachment.blobId] ?: return false
            if (offset !in 0..attachment.sizeBytes) return false
            if (!sendFileFromOffset(sessionId, clientMessageId, attachment, offset)) {
                sendAbort(sessionId, clientMessageId, "binary_send_failed")
                return false
            }
        }

        return engine.send(
            sessionId,
            controlCodec.encode(P2pAttachmentControl.Complete(clientMessageId)),
        )
    }

    suspend fun handleControl(
        sessionId: String,
        payload: String,
        validateOffer: suspend (clientMessageId: String, attachments: List<P2pAttachmentSpec>) -> Boolean,
        completeIncoming: suspend (clientMessageId: String) -> Boolean,
    ): Boolean {
        if (!controlCodec.isAttachmentControl(payload)) return false
        when (val control = controlCodec.decode(payload)) {
            is P2pAttachmentControl.Offer -> {
                if (!validateOffer(control.clientMessageId, control.attachments)) {
                    sendAbort(sessionId, control.clientMessageId, "offer_rejected")
                    return true
                }
                prepareInbound(sessionId, control)
            }
            is P2pAttachmentControl.Ready -> {
                readyWaiters[key(sessionId, control.clientMessageId)]?.complete(control.offsets)
            }
            is P2pAttachmentControl.Complete -> {
                completeInbound(sessionId, control.clientMessageId, completeIncoming)
            }
            is P2pAttachmentControl.Abort -> {
                readyWaiters.remove(key(sessionId, control.clientMessageId))
                    ?.completeExceptionally(IllegalStateException("P2P attachment aborted: ${control.reason}"))
                closeInbound(key(sessionId, control.clientMessageId), keepPartial = true)
            }
        }
        return true
    }

    fun handleBinary(sessionId: String, payload: ByteArray): Boolean {
        val chunk = try {
            P2pAttachmentChunkCodec.decode(payload)
        } finally {
            payload.fill(0)
        }
        try {
            val transfer = inbound[key(sessionId, chunk.clientMessageId)] ?: return false
            val spec = transfer.specs[chunk.blobId] ?: return false
            val expectedOffset = transfer.offsets[chunk.blobId] ?: return false
            if (chunk.offset != expectedOffset) return false
            val nextOffset = chunk.offset + chunk.data.size
            if (nextOffset > spec.sizeBytes) return false

            val writer = transfer.writers.getOrPut(chunk.blobId) {
                fileStore.openPartialForAppend(chunk.blobId, spec.sha256, expectedOffset)
            }
            writer.write(chunk.data)
            transfer.offsets[chunk.blobId] = nextOffset
            return true
        } finally {
            chunk.data.fill(0)
        }
    }

    fun releaseSession(sessionId: String) {
        val prefix = "$sessionId\u0000"
        readyWaiters.keys.filter { it.startsWith(prefix) }.forEach { key ->
            readyWaiters.remove(key)?.completeExceptionally(IllegalStateException("P2P session closed"))
        }
        inbound.keys.filter { it.startsWith(prefix) }.forEach { key ->
            closeInbound(key, keepPartial = true)
        }
    }

    private suspend fun prepareInbound(sessionId: String, offer: P2pAttachmentControl.Offer) {
        val transferKey = key(sessionId, offer.clientMessageId)
        closeInbound(transferKey, keepPartial = true)
        val specs = offer.attachments.associateBy(P2pAttachmentSpec::blobId)
        require(specs.size == offer.attachments.size)
        val offsets = linkedMapOf<String, Long>()
        for (spec in offer.attachments) {
            val localComplete = fileStore.encryptedAttachment(spec.blobId)
            val offset = if (
                localComplete != null &&
                localComplete.length() == spec.sizeBytes &&
                sha256(localComplete) == spec.sha256
            ) {
                spec.sizeBytes
            } else {
                if (localComplete != null) fileStore.deleteAttachment(spec.blobId)
                val partial = fileStore.partialLength(spec.blobId, spec.sha256)
                if (partial > spec.sizeBytes) {
                    fileStore.discardPartial(spec.blobId, spec.sha256)
                    0L
                } else {
                    partial
                }
            }
            offsets[spec.blobId] = offset
        }
        inbound[transferKey] = InboundTransfer(specs, offsets.toMutableMap())
        val ready = P2pAttachmentControl.Ready(
            clientMessageId = offer.clientMessageId,
            offsets = offer.attachments.map { P2pAttachmentOffset(it.blobId, offsets.getValue(it.blobId)) },
        )
        if (!engine.send(sessionId, controlCodec.encode(ready))) {
            closeInbound(transferKey, keepPartial = true)
            error("Unable to send P2P attachment ready")
        }
    }

    private suspend fun completeInbound(
        sessionId: String,
        clientMessageId: String,
        completeIncoming: suspend (clientMessageId: String) -> Boolean,
    ) {
        val transferKey = key(sessionId, clientMessageId)
        val transfer = inbound[transferKey] ?: run {
            sendAbort(sessionId, clientMessageId, "transfer_missing")
            return
        }
        transfer.closeWriters()

        val newlyCommittedBlobIds = mutableListOf<String>()
        try {
            for (spec in transfer.specs.values) {
                val alreadyComplete = fileStore.encryptedAttachment(spec.blobId)
                if (alreadyComplete != null) {
                    require(alreadyComplete.length() == spec.sizeBytes && sha256(alreadyComplete) == spec.sha256) {
                        "Stored P2P attachment mismatch"
                    }
                    continue
                }

                require(transfer.offsets[spec.blobId] == spec.sizeBytes) { "Incomplete P2P attachment" }
                val partial = requireNotNull(fileStore.openPartial(spec.blobId, spec.sha256)) {
                    "P2P attachment partial missing"
                }
                val actualSha = partial.use(::sha256)
                require(actualSha == spec.sha256) { "P2P attachment hash mismatch" }
                fileStore.commitPartial(spec.blobId, spec.sha256, spec.sizeBytes)
                newlyCommittedBlobIds += spec.blobId
            }

            if (!completeIncoming(clientMessageId)) {
                newlyCommittedBlobIds.forEach(fileStore::deleteAttachment)
                sendAbort(sessionId, clientMessageId, "message_commit_failed")
                return
            }
            inbound.remove(transferKey)
        } catch (error: Throwable) {
            newlyCommittedBlobIds.forEach(fileStore::deleteAttachment)
            closeInbound(transferKey, keepPartial = true)
            sendAbort(sessionId, clientMessageId, "verification_failed")
            throw error
        }
    }

    private suspend fun sendFileFromOffset(
        sessionId: String,
        clientMessageId: String,
        spec: P2pAttachmentSpec,
        offset: Long,
    ): Boolean {
        val source = fileStore.openEncryptedAttachment(spec.blobId) ?: return false
        return source.use { input ->
            if (!skipFully(input, offset)) return@use false
            val buffer = ByteArray(P2pAttachmentChunkCodec.MAX_CHUNK_DATA_BYTES)
            var currentOffset = offset
            try {
                while (currentOffset < spec.sizeBytes) {
                    val expected = minOf(buffer.size.toLong(), spec.sizeBytes - currentOffset).toInt()
                    val read = readFullyUpTo(input, buffer, expected)
                    if (read != expected) return@use false
                    val frame = P2pAttachmentChunkCodec.encode(
                        clientMessageId = clientMessageId,
                        blobId = spec.blobId,
                        offset = currentOffset,
                        source = buffer,
                        length = read,
                    )
                    try {
                        if (!engine.sendBinary(sessionId, frame)) return@use false
                    } finally {
                        frame.fill(0)
                        buffer.fill(0, 0, read)
                    }
                    currentOffset += read
                }
                true
            } finally {
                buffer.fill(0)
            }
        }
    }

    private fun sendAbort(sessionId: String, clientMessageId: String, reason: String) {
        engine.send(
            sessionId,
            controlCodec.encode(P2pAttachmentControl.Abort(clientMessageId, reason)),
        )
    }

    private fun closeInbound(transferKey: String, keepPartial: Boolean) {
        val transfer = inbound.remove(transferKey) ?: return
        transfer.closeWriters()
        if (!keepPartial) {
            transfer.specs.values.forEach { fileStore.discardPartial(it.blobId, it.sha256) }
        }
    }

    private fun sha256(file: File): String = file.inputStream().buffered().use(::sha256)

    private fun sha256(input: InputStream): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val buffer = ByteArray(64 * 1024)
        try {
            while (true) {
                val read = input.read(buffer)
                if (read == -1) break
                if (read == 0) continue
                digest.update(buffer, 0, read)
            }
        } finally {
            buffer.fill(0)
        }
        return digest.digest().joinToString("") { "%02x".format(it) }
    }

    private fun skipFully(input: InputStream, bytes: Long): Boolean {
        var remaining = bytes
        while (remaining > 0L) {
            val skipped = input.skip(remaining)
            if (skipped > 0L) {
                remaining -= skipped
                continue
            }
            if (input.read() == -1) return false
            remaining -= 1
        }
        return true
    }

    private fun readFullyUpTo(input: InputStream, buffer: ByteArray, expected: Int): Int {
        var total = 0
        while (total < expected) {
            val read = input.read(buffer, total, expected - total)
            if (read == -1) break
            if (read == 0) continue
            total += read
        }
        return total
    }

    private fun key(sessionId: String, clientMessageId: String): String = "$sessionId\u0000$clientMessageId"

    private data class InboundTransfer(
        val specs: Map<String, P2pAttachmentSpec>,
        val offsets: MutableMap<String, Long>,
        val writers: MutableMap<String, FileOutputStream> = linkedMapOf(),
    ) {
        fun closeWriters() {
            writers.values.forEach { runCatching { it.close() } }
            writers.clear()
        }
    }
}
