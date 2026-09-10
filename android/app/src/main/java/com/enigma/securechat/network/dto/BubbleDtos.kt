package com.enigma.securechat.network.dto

import com.squareup.moshi.Json

data class BubbleDto(
    val id: String,
    val slug: String,
    val name: String,
    val description: String?,
    val mode: String,
    val visibility: String,
    @Json(name = "join_policy") val joinPolicy: String,
    @Json(name = "index_policy") val indexPolicy: String,
    @Json(name = "owner_identity_id") val ownerIdentityId: String?,
    @Json(name = "public_key") val publicKey: String?,
    @Json(name = "created_at") val createdAt: String,
    @Json(name = "updated_at") val updatedAt: String,
)

data class BubblesResponseDto(
    val bubbles: List<BubbleDto>,
)

data class CreateBubbleRequestDto(
    val slug: String?,
    val name: String,
    val description: String?,
    val mode: String,
    val visibility: String,
    @Json(name = "join_policy") val joinPolicy: String,
    @Json(name = "index_policy") val indexPolicy: String,
)

data class BubbleMemberDto(
    @Json(name = "identity_id") val identityId: String,
    val role: String,
    val status: String,
    @Json(name = "joined_at") val joinedAt: String,
)

data class BubbleMembersResponseDto(
    val members: List<BubbleMemberDto>,
)

data class BubbleRelayDto(
    @Json(name = "bubble_id") val bubbleId: String,
    @Json(name = "relay_id") val relayId: String,
    val role: String,
    val priority: Int,
    val required: Boolean,
    @Json(name = "fallback_allowed") val fallbackAllowed: Boolean,
)

data class BubbleRelaysResponseDto(
    val relays: List<BubbleRelayDto>,
)

data class AddBubbleRelayRequestDto(
    @Json(name = "relay_id") val relayId: String,
    val role: String = "primary",
    val priority: Int = 0,
    val required: Boolean = false,
    @Json(name = "fallback_allowed") val fallbackAllowed: Boolean = true,
)
