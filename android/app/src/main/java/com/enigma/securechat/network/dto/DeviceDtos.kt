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

data class DeviceDto(
    val id: String,
    @Json(name = "display_name") val displayName: String,
    val platform: String,
    @Json(name = "created_at") val createdAt: String,
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
