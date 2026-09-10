package com.enigma.securechat.network.dto

import com.squareup.moshi.Json

data class TurnCredentialsResponseDto(
    val username: String,
    val credential: String,
    @Json(name = "ttl_seconds") val ttlSeconds: Long,
    @Json(name = "expires_at") val expiresAt: String,
    val uris: List<String>,
    val realm: String,
)
