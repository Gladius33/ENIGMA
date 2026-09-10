package com.enigma.securechat.network.dto

import com.squareup.moshi.Json

data class RelayDto(
    val id: String,
    val name: String,
    val url: String,
    @Json(name = "public_key") val publicKey: String?,
    @Json(name = "type") val type: String,
    @Json(name = "trust_level") val trustLevel: String,
    @Json(name = "is_official") val isOfficial: Boolean,
    @Json(name = "created_at") val createdAt: String,
    @Json(name = "last_seen_at") val lastSeenAt: String?,
    val region: String?,
)

data class RelaysResponseDto(
    val relays: List<RelayDto>,
)

data class CreateCustomRelayRequestDto(
    val name: String,
    val url: String,
    @Json(name = "relay_type") val relayType: String = "PRIVATE",
    @Json(name = "public_key") val publicKey: String? = null,
)
