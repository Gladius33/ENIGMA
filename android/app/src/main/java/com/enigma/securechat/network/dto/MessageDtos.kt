package com.enigma.securechat.network.dto

import com.squareup.moshi.Json

data class SendMessageRequestDto(
    @Json(name = "bubble_id") val bubbleId: String,
    @Json(name = "sender_device_id") val senderDeviceId: String,
    @Json(name = "recipient_device_id") val recipientDeviceId: String,
    @Json(name = "client_message_id") val clientMessageId: String,
    @Json(name = "message_type") val messageType: String = "text",
    val ciphertext: String,
    @Json(name = "attachment_blob_ids") val attachmentBlobIds: List<String> = emptyList(),
)

data class SendMessageResponseDto(
    val id: String,
    @Json(name = "bubble_id") val bubbleId: String,
    @Json(name = "client_message_id") val clientMessageId: String,
    @Json(name = "created_at") val createdAt: String,
    @Json(name = "expires_at") val expiresAt: String,
)

data class PendingMessagesResponseDto(
    val messages: List<PendingMessageDto>,
)

data class PendingMessageDto(
    val id: String,
    @Json(name = "bubble_id") val bubbleId: String,
    @Json(name = "sender_device_id") val senderDeviceId: String,
    @Json(name = "sender_user_id") val senderUserId: String?,
    @Json(name = "sender_public_id") val senderPublicId: String?,
    @Json(name = "recipient_device_id") val recipientDeviceId: String,
    @Json(name = "client_message_id") val clientMessageId: String,
    @Json(name = "message_type") val messageType: String,
    val ciphertext: String,
    @Json(name = "created_at") val createdAt: String,
    @Json(name = "expires_at") val expiresAt: String,
)

data class ReceiptRequestDto(
    @Json(name = "device_id") val deviceId: String,
    val status: String = "delivered",
)

data class ReceiptResponseDto(
    val id: String,
    val status: String,
)

data class SentReceiptsResponseDto(
    val receipts: List<SentReceiptDto>,
)

data class SentReceiptDto(
    @Json(name = "message_id") val messageId: String,
    @Json(name = "bubble_id") val bubbleId: String,
    @Json(name = "client_message_id") val clientMessageId: String,
    @Json(name = "recipient_device_id") val recipientDeviceId: String,
    val status: String,
    @Json(name = "delivered_at") val deliveredAt: String,
)

data class P2pSignalCommandDto(
    val type: String = "p2p_signal",
    @Json(name = "bubble_id") val bubbleId: String,
    @Json(name = "recipient_device_id") val recipientDeviceId: String,
    @Json(name = "session_id") val sessionId: String,
    @Json(name = "signal_kind") val signalKind: String,
    val payload: String,
)

data class WsEventDto(
    val type: String,
    @Json(name = "conversation_kind") val conversationKind: String? = null,
    @Json(name = "bubble_id") val bubbleId: String? = null,
    @Json(name = "message_id") val messageId: String? = null,
    @Json(name = "client_message_id") val clientMessageId: String? = null,
    val status: String? = null,
    @Json(name = "group_id") val groupId: String? = null,
    @Json(name = "channel_id") val channelId: String? = null,
    @Json(name = "post_id") val postId: String? = null,
    @Json(name = "call_id") val callId: String? = null,
    @Json(name = "event_kind") val eventKind: String? = null,
    @Json(name = "sender_device_id") val senderDeviceId: String? = null,
    @Json(name = "recipient_device_id") val recipientDeviceId: String? = null,
    @Json(name = "session_id") val sessionId: String? = null,
    @Json(name = "signal_kind") val signalKind: String? = null,
    val payload: String? = null,
)
