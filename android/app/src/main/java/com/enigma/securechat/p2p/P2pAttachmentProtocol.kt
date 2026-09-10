package com.enigma.securechat.p2p

import com.squareup.moshi.Json
import com.squareup.moshi.Moshi
import com.squareup.moshi.kotlin.reflect.KotlinJsonAdapterFactory
import java.nio.ByteBuffer
import java.util.UUID

data class P2pAttachmentSpec(
    val blobId: String,
    val sizeBytes: Long,
    val sha256: String,
)

data class P2pAttachmentOffset(
    val blobId: String,
    val offset: Long,
)

sealed interface P2pAttachmentControl {
    val clientMessageId: String

    data class Offer(
        override val clientMessageId: String,
        val attachments: List<P2pAttachmentSpec>,
    ) : P2pAttachmentControl

    data class Ready(
        override val clientMessageId: String,
        val offsets: List<P2pAttachmentOffset>,
    ) : P2pAttachmentControl

    data class Complete(
        override val clientMessageId: String,
    ) : P2pAttachmentControl

    data class Abort(
        override val clientMessageId: String,
        val reason: String,
    ) : P2pAttachmentControl
}

class P2pAttachmentControlCodec(
    moshi: Moshi = Moshi.Builder().add(KotlinJsonAdapterFactory()).build(),
) {
    private val adapter = moshi.adapter(WireControl::class.java)

    fun isAttachmentControl(value: String): Boolean = value.startsWith(PREFIX)

    fun encode(control: P2pAttachmentControl): String {
        val wire = when (control) {
            is P2pAttachmentControl.Offer -> WireControl(
                kind = KIND_OFFER,
                clientMessageId = control.clientMessageId,
                attachments = control.attachments.map {
                    WireAttachment(it.blobId, it.sizeBytes, it.sha256)
                },
            )
            is P2pAttachmentControl.Ready -> WireControl(
                kind = KIND_READY,
                clientMessageId = control.clientMessageId,
                offsets = control.offsets.map { WireOffset(it.blobId, it.offset) },
            )
            is P2pAttachmentControl.Complete -> WireControl(
                kind = KIND_COMPLETE,
                clientMessageId = control.clientMessageId,
            )
            is P2pAttachmentControl.Abort -> WireControl(
                kind = KIND_ABORT,
                clientMessageId = control.clientMessageId,
                reason = control.reason,
            )
        }
        return PREFIX + adapter.toJson(wire)
    }

    fun decode(value: String): P2pAttachmentControl {
        require(value.startsWith(PREFIX)) { "Unsupported P2P attachment control format" }
        require(value.toByteArray(Charsets.UTF_8).size <= MAX_CONTROL_BYTES) {
            "P2P attachment control too large"
        }
        val wire = requireNotNull(adapter.fromJson(value.removePrefix(PREFIX))) {
            "Invalid P2P attachment control"
        }
        require(wire.version == VERSION) { "Unsupported P2P attachment control version" }
        val clientMessageId = requireUuid(wire.clientMessageId, "client_message_id")
        return when (wire.kind) {
            KIND_OFFER -> P2pAttachmentControl.Offer(
                clientMessageId = clientMessageId,
                attachments = requireNotNull(wire.attachments)
                    .also { require(it.isNotEmpty() && it.size <= MAX_ATTACHMENTS) }
                    .map {
                        P2pAttachmentSpec(
                            blobId = requireUuid(it.blobId, "blob_id"),
                            sizeBytes = it.sizeBytes.also { size ->
                                require(size in 1..MAX_ATTACHMENT_BYTES) { "Invalid P2P attachment size" }
                            },
                            sha256 = it.sha256.also { sha ->
                                require(SHA256.matches(sha)) { "Invalid P2P attachment hash" }
                            },
                        )
                    }
                    .also { specs ->
                        require(specs.map(P2pAttachmentSpec::blobId).distinct().size == specs.size) {
                            "Duplicate P2P attachment"
                        }
                    },
            )
            KIND_READY -> P2pAttachmentControl.Ready(
                clientMessageId = clientMessageId,
                offsets = requireNotNull(wire.offsets)
                    .also { require(it.isNotEmpty() && it.size <= MAX_ATTACHMENTS) }
                    .map {
                        P2pAttachmentOffset(
                            blobId = requireUuid(it.blobId, "blob_id"),
                            offset = it.offset.also { offset ->
                                require(offset >= 0L) { "Invalid P2P attachment offset" }
                            },
                        )
                    }
                    .also { offsets ->
                        require(offsets.map(P2pAttachmentOffset::blobId).distinct().size == offsets.size) {
                            "Duplicate P2P attachment offset"
                        }
                    },
            )
            KIND_COMPLETE -> P2pAttachmentControl.Complete(clientMessageId)
            KIND_ABORT -> P2pAttachmentControl.Abort(
                clientMessageId = clientMessageId,
                reason = requireNotNull(wire.reason?.takeIf(String::isNotBlank))
                    .take(MAX_REASON_LENGTH),
            )
            else -> error("Unsupported P2P attachment control kind")
        }
    }

    private data class WireControl(
        val version: Int = VERSION,
        val kind: String,
        @Json(name = "client_message_id") val clientMessageId: String,
        val attachments: List<WireAttachment>? = null,
        val offsets: List<WireOffset>? = null,
        val reason: String? = null,
    )

    private data class WireAttachment(
        @Json(name = "blob_id") val blobId: String,
        @Json(name = "size_bytes") val sizeBytes: Long,
        val sha256: String,
    )

    private data class WireOffset(
        @Json(name = "blob_id") val blobId: String,
        val offset: Long,
    )

    private fun requireUuid(value: String?, field: String): String {
        val clean = requireNotNull(value?.takeIf(String::isNotBlank)) { "Missing $field" }
        require(runCatching { UUID.fromString(clean) }.isSuccess) { "Invalid $field" }
        return clean
    }

    private companion object {
        const val PREFIX = "ENIGMA_P2P_ATTACHMENT_V1:"
        const val VERSION = 1
        const val KIND_OFFER = "offer"
        const val KIND_READY = "ready"
        const val KIND_COMPLETE = "complete"
        const val KIND_ABORT = "abort"
        const val MAX_ATTACHMENTS = 16
        const val MAX_CONTROL_BYTES = 64 * 1024
        const val MAX_REASON_LENGTH = 128
        const val MAX_ATTACHMENT_BYTES = 64L * 1024 * 1024 * 1024
        val SHA256 = Regex("^[0-9a-f]{64}$")
    }
}

data class P2pAttachmentChunk(
    val clientMessageId: String,
    val blobId: String,
    val offset: Long,
    val data: ByteArray,
)

object P2pAttachmentChunkCodec {
    const val MAX_CHUNK_DATA_BYTES = 60 * 1024
    private const val HEADER_BYTES = 4 + 1 + 16 + 16 + 8 + 4
    private const val VERSION: Byte = 1
    private val MAGIC = byteArrayOf(0x45, 0x32, 0x41, 0x42) // E2AB

    fun encode(
        clientMessageId: String,
        blobId: String,
        offset: Long,
        source: ByteArray,
        length: Int,
    ): ByteArray {
        require(offset >= 0L)
        require(length in 1..MAX_CHUNK_DATA_BYTES && length <= source.size)
        val clientUuid = UUID.fromString(clientMessageId)
        val blobUuid = UUID.fromString(blobId)
        return ByteBuffer.allocate(HEADER_BYTES + length)
            .put(MAGIC)
            .put(VERSION)
            .putLong(clientUuid.mostSignificantBits)
            .putLong(clientUuid.leastSignificantBits)
            .putLong(blobUuid.mostSignificantBits)
            .putLong(blobUuid.leastSignificantBits)
            .putLong(offset)
            .putInt(length)
            .put(source, 0, length)
            .array()
    }

    fun decode(payload: ByteArray): P2pAttachmentChunk {
        require(payload.size in (HEADER_BYTES + 1)..(HEADER_BYTES + MAX_CHUNK_DATA_BYTES)) {
            "Invalid P2P attachment chunk size"
        }
        val buffer = ByteBuffer.wrap(payload)
        val magic = ByteArray(MAGIC.size)
        buffer.get(magic)
        require(magic.contentEquals(MAGIC)) { "Invalid P2P attachment chunk magic" }
        require(buffer.get() == VERSION) { "Unsupported P2P attachment chunk version" }
        val clientMessageId = UUID(buffer.long, buffer.long).toString()
        val blobId = UUID(buffer.long, buffer.long).toString()
        val offset = buffer.long
        require(offset >= 0L) { "Invalid P2P attachment chunk offset" }
        val length = buffer.int
        require(length in 1..MAX_CHUNK_DATA_BYTES && buffer.remaining() == length) {
            "Invalid P2P attachment chunk payload"
        }
        val data = ByteArray(length)
        buffer.get(data)
        return P2pAttachmentChunk(clientMessageId, blobId, offset, data)
    }
}
