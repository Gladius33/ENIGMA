package com.enigma.securechat.data.repository

import com.squareup.moshi.Moshi
import com.squareup.moshi.kotlin.reflect.KotlinJsonAdapterFactory
import java.util.UUID

data class SenderSyncPayload(
    val contactUserId: String,
    val contactPublicId: String,
    val contactDisplayName: String,
    val bubbleId: String,
    val clientMessageId: String,
    val originalCreatedAt: Long,
    val encodedMessagePayload: String,
)

object SenderSyncPayloadCodec {
    private const val PREFIX = "ENIGMA_SENDER_SYNC_V1:"
    private const val MAX_PUBLIC_ID_CHARS = 128
    private const val MAX_DISPLAY_NAME_CHARS = 160
    private const val MAX_ENCODED_PAYLOAD_CHARS = 2 * 1024 * 1024

    private val adapter = Moshi.Builder()
        .add(KotlinJsonAdapterFactory())
        .build()
        .adapter(SenderSyncDto::class.java)

    fun encode(payload: SenderSyncPayload): String {
        validate(payload)
        return PREFIX + adapter.toJson(
            SenderSyncDto(
                version = 1,
                contactUserId = payload.contactUserId,
                contactPublicId = payload.contactPublicId,
                contactDisplayName = payload.contactDisplayName,
                bubbleId = payload.bubbleId,
                clientMessageId = payload.clientMessageId,
                originalCreatedAt = payload.originalCreatedAt,
                encodedMessagePayload = payload.encodedMessagePayload,
            ),
        )
    }

    fun decode(value: String): SenderSyncPayload {
        require(value.startsWith(PREFIX)) { "Unsupported sender-sync payload format" }
        val dto = requireNotNull(adapter.fromJson(value.removePrefix(PREFIX))) {
            "Invalid sender-sync payload"
        }
        require(dto.version == 1) { "Unsupported sender-sync payload version" }
        return SenderSyncPayload(
            contactUserId = dto.contactUserId,
            contactPublicId = dto.contactPublicId,
            contactDisplayName = dto.contactDisplayName,
            bubbleId = dto.bubbleId,
            clientMessageId = dto.clientMessageId,
            originalCreatedAt = dto.originalCreatedAt,
            encodedMessagePayload = dto.encodedMessagePayload,
        ).also(::validate)
    }

    fun isSenderSync(value: String): Boolean = value.startsWith(PREFIX)

    private fun validate(payload: SenderSyncPayload) {
        UUID.fromString(payload.contactUserId)
        UUID.fromString(payload.bubbleId)
        UUID.fromString(payload.clientMessageId)
        require(payload.contactPublicId.isNotBlank() && payload.contactPublicId.length <= MAX_PUBLIC_ID_CHARS)
        require(
            payload.contactDisplayName.isNotBlank() &&
                payload.contactDisplayName.length <= MAX_DISPLAY_NAME_CHARS,
        )
        require(payload.originalCreatedAt > 0L)
        require(
            payload.encodedMessagePayload.isNotBlank() &&
                payload.encodedMessagePayload.length <= MAX_ENCODED_PAYLOAD_CHARS,
        )
        MessagePayloadCodec.decode(payload.encodedMessagePayload)
    }

    private data class SenderSyncDto(
        val version: Int,
        val contactUserId: String,
        val contactPublicId: String,
        val contactDisplayName: String,
        val bubbleId: String,
        val clientMessageId: String,
        val originalCreatedAt: Long,
        val encodedMessagePayload: String,
    )
}
