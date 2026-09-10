package com.enigma.securechat.network.dto

import com.squareup.moshi.Json

data class AuthRequestDto(
    @Json(name = "public_id") val publicId: String,
    val password: String,
)

data class AuthResponseDto(
    @Json(name = "access_token") val accessToken: String,
    @Json(name = "token_type") val tokenType: String,
    @Json(name = "expires_in") val expiresIn: Long,
    val user: UserDto,
)

data class UserDto(
    val id: String,
    @Json(name = "public_id") val publicId: String,
    @Json(name = "display_name") val displayName: String? = null,
    @Json(name = "canonical_handle") val canonicalHandle: String? = null,
    @Json(name = "public_handle") val publicHandle: String? = null,
)

data class ResolveUserResponseDto(
    val id: String,
    @Json(name = "public_id") val publicId: String,
)
