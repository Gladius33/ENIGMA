package com.enigma.securechat.network.dto

import com.squareup.moshi.Json

data class DeviceRegisterRequestDto(
    @Json(name = "display_name") val displayName: String,
    val platform: String = "android",
    @Json(name = "device_id") val deviceId: String? = null,
)

data class DeviceRegisterResponseDto(
    val device: DeviceDto,
    @Json(name = "access_token") val accessToken: String,
    @Json(name = "token_type") val tokenType: String,
    @Json(name = "expires_in") val expiresIn: Long,
)

data class DeviceAuthorizationDto(
    @Json(name = "authorizing_device_id") val authorizingDeviceId: String,
    @Json(name = "canonical_payload") val canonicalPayload: String,
    @Json(name = "authorizer_signature") val authorizerSignature: String,
)

data class DeviceDto(
    val id: String,
    @Json(name = "display_name") val displayName: String,
    val platform: String,
    @Json(name = "created_at") val createdAt: String,
    val authorization: DeviceAuthorizationDto? = null,
)

data class AuthorizeLinkedDesktopRequestDto(
    @Json(name = "device_id") val deviceId: String,
    @Json(name = "display_name") val displayName: String,
    val platform: String,
    @Json(name = "pairing_session_id") val pairingSessionId: String,
    @Json(name = "protocol_version") val protocolVersion: Int,
    @Json(name = "min_supported_version") val minSupportedVersion: Int,
    val capabilities: Long,
    @Json(name = "issued_at_unix_ms") val issuedAtUnixMs: Long,
    @Json(name = "target_identity_key") val targetIdentityKey: String,
    @Json(name = "authorizer_signature") val authorizerSignature: String,
)

data class LinkedDesktopResponseDto(
    val device: DeviceDto,
    @Json(name = "access_token") val accessToken: String,
    @Json(name = "token_type") val tokenType: String,
    @Json(name = "expires_in") val expiresIn: Long,
)

data class DevicesResponseDto(
    val devices: List<DeviceDto>,
)

data class FcmTokenRequestDto(
    @Json(name = "fcm_token") val fcmToken: String,
    val platform: String = "android",
)

data class StatusResponseDto(
    val status: String,
)
