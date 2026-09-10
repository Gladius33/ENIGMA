package com.enigma.securechat.network.dto

import com.squareup.moshi.Json

data class CreateGroupRequestDto(
    @Json(name = "bubble_id") val bubbleId: String,
    val title: String,
)

data class AddGroupMemberRequestDto(
    @Json(name = "user_id") val userId: String,
    val role: String = "member",
)

data class GroupDto(
    val id: String,
    @Json(name = "bubble_id") val bubbleId: String,
    val title: String,
    @Json(name = "owner_user_id") val ownerUserId: String,
    @Json(name = "created_at") val createdAt: String,
)

data class GroupMemberDto(
    @Json(name = "user_id") val userId: String,
    @Json(name = "public_id") val publicId: String,
    val role: String,
)

data class GroupDetailResponseDto(
    val group: GroupDto,
    val members: List<GroupMemberDto>,
)

data class GroupsResponseDto(
    val groups: List<GroupDto>,
)

data class SendGroupMessageRequestDto(
    @Json(name = "bubble_id") val bubbleId: String,
    @Json(name = "sender_device_id") val senderDeviceId: String,
    @Json(name = "client_message_id") val clientMessageId: String,
    @Json(name = "message_type") val messageType: String = "opaque",
    val ciphertext: String,
    @Json(name = "attachment_blob_ids") val attachmentBlobIds: List<String> = emptyList(),
)

data class GroupMessageResponseDto(
    val id: String,
    @Json(name = "bubble_id") val bubbleId: String,
    @Json(name = "client_message_id") val clientMessageId: String,
    @Json(name = "created_at") val createdAt: String,
    @Json(name = "expires_at") val expiresAt: String,
)

data class GroupReceiptRequestDto(
    @Json(name = "device_id") val deviceId: String,
    val status: String = "delivered",
)

data class PendingGroupMessagesResponseDto(
    val messages: List<PendingGroupMessageDto>,
)

data class PendingGroupMessageDto(
    val id: String,
    @Json(name = "bubble_id") val bubbleId: String,
    @Json(name = "group_id") val groupId: String,
    @Json(name = "sender_device_id") val senderDeviceId: String,
    @Json(name = "client_message_id") val clientMessageId: String,
    @Json(name = "message_type") val messageType: String,
    val ciphertext: String,
    @Json(name = "created_at") val createdAt: String,
    @Json(name = "expires_at") val expiresAt: String,
)
