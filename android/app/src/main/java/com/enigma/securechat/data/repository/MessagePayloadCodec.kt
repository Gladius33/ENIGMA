package com.enigma.securechat.data.repository

import com.enigma.securechat.domain.model.AttachmentDescriptor
import com.squareup.moshi.Moshi
import com.squareup.moshi.kotlin.reflect.KotlinJsonAdapterFactory
import java.util.Base64
import java.util.UUID

data class MessageAttachment(
    val descriptor: AttachmentDescriptor,
    val fileName: String? = null,
)

data class MessagePayload(
    val body: String,
    val attachments: List<MessageAttachment> = emptyList(),
)

object MessagePayloadCodec {
    private const val PREFIX = "ENIGMA_PAYLOAD_V1:"
    private const val MAX_ATTACHMENTS = 16
    private const val MAX_FILE_NAME_CHARS = 255

    private val adapter = Moshi.Builder()
        .add(KotlinJsonAdapterFactory())
        .build()
        .adapter(PayloadDto::class.java)

    fun encode(body: String, attachments: List<MessageAttachment>): String {
        validateAttachments(attachments)
        val dto = PayloadDto(
            version = 1,
            body = body,
            attachments = attachments.map { attachment ->
                val descriptor = attachment.descriptor
                AttachmentDto(
                    blobId = descriptor.blobId,
                    bubbleId = descriptor.bubbleId,
                    contentType = descriptor.contentType,
                    sizeBytes = descriptor.sizeBytes,
                    sha256 = descriptor.sha256,
                    key = descriptor.key,
                    nonce = descriptor.nonce,
                    downloadSecret = descriptor.downloadSecret,
                    fileName = attachment.fileName?.sanitizeFileName(),
                )
            },
        )
        return PREFIX + adapter.toJson(dto)
    }

    fun decode(value: String): MessagePayload {
        require(value.startsWith(PREFIX)) { "Unsupported Enigma message payload format" }
        val dto = requireNotNull(adapter.fromJson(value.removePrefix(PREFIX))) {
            "Invalid Enigma message payload"
        }
        require(dto.version == 1) { "Unsupported Enigma message payload version" }
        val attachments = dto.attachments.map { attachment ->
            MessageAttachment(
                descriptor = AttachmentDescriptor(
                    blobId = attachment.blobId,
                    bubbleId = attachment.bubbleId,
                    contentType = attachment.contentType,
                    sizeBytes = attachment.sizeBytes,
                    sha256 = attachment.sha256,
                    key = attachment.key,
                    nonce = attachment.nonce,
                    downloadSecret = attachment.downloadSecret,
                ),
                fileName = attachment.fileName?.sanitizeFileName(),
            )
        }
        validateAttachments(attachments)
        return MessagePayload(body = dto.body, attachments = attachments)
    }

    private fun validateAttachments(attachments: List<MessageAttachment>) {
        require(attachments.size <= MAX_ATTACHMENTS) { "Too many attachments" }
        require(attachments.map { it.descriptor.blobId }.distinct().size == attachments.size) {
            "Duplicate attachment blob id"
        }
        attachments.forEach { attachment ->
            val descriptor = attachment.descriptor
            UUID.fromString(descriptor.blobId)
            UUID.fromString(descriptor.bubbleId)
            require(descriptor.contentType.length in 3..128 && '/' in descriptor.contentType) {
                "Invalid attachment content type"
            }
            require(descriptor.sizeBytes > 0) { "Invalid attachment size" }
            require(descriptor.sha256.matches(Regex("[0-9a-fA-F]{64}"))) { "Invalid attachment SHA-256" }
            require(decodedSize(descriptor.key) == 32) { "Invalid attachment key" }
            require(decodedSize(descriptor.nonce) == 8) { "Invalid attachment streaming nonce" }
            require(descriptor.downloadSecret.length in 16..512) { "Invalid attachment download secret" }
            attachment.fileName?.let { fileName ->
                require(fileName.isNotBlank() && fileName.length <= MAX_FILE_NAME_CHARS) {
                    "Invalid attachment file name"
                }
                require(fileName.none { it.code < 0x20 || it == '/' || it == '\\' }) {
                    "Invalid attachment file name"
                }
            }
        }
    }

    private fun decodedSize(value: String): Int = Base64.getDecoder().decode(value).size

    private fun String.sanitizeFileName(): String =
        trim()
            .map { character ->
                if (character.code < 0x20 || character == '/' || character == '\\') '_' else character
            }
            .joinToString("")
            .take(MAX_FILE_NAME_CHARS)
            .ifBlank { "attachment" }

    private data class PayloadDto(
        val version: Int,
        val body: String,
        val attachments: List<AttachmentDto> = emptyList(),
    )

    private data class AttachmentDto(
        val blobId: String,
        val bubbleId: String,
        val contentType: String,
        val sizeBytes: Long,
        val sha256: String,
        val key: String,
        val nonce: String,
        val downloadSecret: String,
        val fileName: String? = null,
    )
}
