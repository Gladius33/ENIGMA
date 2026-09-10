package com.enigma.securechat.network.dto

import com.squareup.moshi.Json

data class CreateChannelRequestDto(
    @Json(name = "bubble_id") val bubbleId: String,
    val title: String,
    val description: String = "",
    @Json(name = "avatar_blob_id") val avatarBlobId: String? = null,
)

data class ChannelDto(
    val id: String,
    @Json(name = "bubble_id") val bubbleId: String,
    val title: String,
    val description: String?,
    @Json(name = "avatar_blob_id") val avatarBlobId: String?,
    @Json(name = "owner_user_id") val ownerUserId: String,
    @Json(name = "created_at") val createdAt: String,
)

data class ChannelsResponseDto(
    val channels: List<ChannelDto>,
)

data class ChannelSubscriberDto(
    @Json(name = "user_id") val userId: String,
    @Json(name = "public_id") val publicId: String,
    val role: String,
)

data class ChannelSubscribersResponseDto(
    val subscribers: List<ChannelSubscriberDto>,
)

data class CreateChannelPostRequestDto(
    @Json(name = "bubble_id") val bubbleId: String,
    @Json(name = "sender_device_id") val senderDeviceId: String,
    @Json(name = "client_post_id") val clientPostId: String,
    @Json(name = "post_type") val postType: String = "opaque",
    val ciphertext: String,
    @Json(name = "attachment_blob_ids") val attachmentBlobIds: List<String> = emptyList(),
)

data class ChannelPostResponseDto(
    val id: String,
    @Json(name = "bubble_id") val bubbleId: String,
    @Json(name = "client_post_id") val clientPostId: String,
    @Json(name = "created_at") val createdAt: String,
    @Json(name = "expires_at") val expiresAt: String,
)

data class PendingChannelPostsResponseDto(
    val posts: List<PendingChannelPostDto>,
)

data class PendingChannelPostDto(
    val id: String,
    @Json(name = "bubble_id") val bubbleId: String,
    @Json(name = "channel_id") val channelId: String,
    @Json(name = "sender_device_id") val senderDeviceId: String,
    @Json(name = "client_post_id") val clientPostId: String,
    @Json(name = "post_type") val postType: String,
    val ciphertext: String,
    @Json(name = "created_at") val createdAt: String,
    @Json(name = "expires_at") val expiresAt: String,
)
