package com.enigma.securechat.network.dto

import com.squareup.moshi.Json

data class CreateCallRequestDto(
    @Json(name = "bubble_id") val bubbleId: String,
    @Json(name = "callee_user_id") val calleeUserId: String,
    @Json(name = "call_kind") val callKind: String = "audio",
)

data class CallResponseDto(
    val id: String,
    @Json(name = "bubble_id") val bubbleId: String,
    @Json(name = "call_kind") val callKind: String,
    val state: String,
    @Json(name = "created_at") val createdAt: String,
    @Json(name = "expires_at") val expiresAt: String,
)

data class SdpRequestDto(
    @Json(name = "bubble_id") val bubbleId: String,
    val sdp: String,
)

data class IceCandidatesRequestDto(
    @Json(name = "bubble_id") val bubbleId: String,
    val candidates: List<String>,
)

data class IceCandidatesResponseDto(
    val candidates: List<SignalingEventDto>,
)

data class CallSignalingEventsResponseDto(
    val events: List<SignalingEventDto>,
)

data class SignalingEventDto(
    val id: String,
    @Json(name = "bubble_id") val bubbleId: String,
    @Json(name = "sender_user_id") val senderUserId: String,
    @Json(name = "event_kind") val eventKind: String,
    val payload: String?,
    @Json(name = "created_at") val createdAt: String,
)
