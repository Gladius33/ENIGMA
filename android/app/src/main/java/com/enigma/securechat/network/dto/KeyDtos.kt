package com.enigma.securechat.network.dto

import com.squareup.moshi.Json

data class UploadKeysRequestDto(
    @Json(name = "device_id") val deviceId: String,
    @Json(name = "identity_key") val identityKey: String,
    @Json(name = "registration_id") val registrationId: Int? = null,
    @Json(name = "protocol_device_id") val protocolDeviceId: Int? = null,
    @Json(name = "signed_prekey") val signedPreKey: SignedPreKeyDto,
    @Json(name = "kyber_prekey") val kyberPreKey: KyberPreKeyDto? = null,
    @Json(name = "one_time_prekeys") val oneTimePreKeys: List<OneTimePreKeyDto>,
)

data class SignedPreKeyDto(
    @Json(name = "key_id") val keyId: Long,
    @Json(name = "public_key") val publicKey: String,
    val signature: String,
)

data class OneTimePreKeyDto(
    @Json(name = "key_id") val keyId: Long,
    @Json(name = "public_key") val publicKey: String,
)

data class KyberPreKeyDto(
    @Json(name = "key_id") val keyId: Long,
    @Json(name = "public_key") val publicKey: String,
    val signature: String,
)

data class UploadKeysResponseDto(
    @Json(name = "device_id") val deviceId: String,
    @Json(name = "one_time_prekeys_received") val oneTimePreKeysReceived: Int,
    @Json(name = "one_time_prekey_count") val oneTimePreKeyCount: Int = 0,
    @Json(name = "prekey_low") val prekeyLow: Boolean = false,
)

data class KeyBundleResponseDto(
    @Json(name = "user_id") val userId: String,
    val devices: List<DeviceKeyBundleDto>,
)

data class DeviceKeyBundleDto(
    @Json(name = "device_id") val deviceId: String,
    @Json(name = "identity_key") val identityKey: String,
    @Json(name = "registration_id") val registrationId: Int?,
    @Json(name = "protocol_device_id") val protocolDeviceId: Int?,
    @Json(name = "signed_prekey") val signedPreKey: SignedPreKeyDto,
    @Json(name = "kyber_prekey") val kyberPreKey: KyberPreKeyDto?,
    @Json(name = "one_time_prekey") val oneTimePreKey: OneTimePreKeyDto? = null,
    @Json(name = "one_time_prekey_count") val oneTimePreKeyCount: Int? = null,
    @Json(name = "one_time_prekey_count_after_claim") val oneTimePreKeyCountAfterClaim: Int? = null,
    @Json(name = "prekey_low") val prekeyLow: Boolean = false,
)

data class ClaimPreKeyResponseDto(
    @Json(name = "user_id") val userId: String,
    val device: DeviceKeyBundleDto,
)

data class KeyStatusResponseDto(
    @Json(name = "device_id") val deviceId: String,
    @Json(name = "one_time_prekey_count") val oneTimePreKeyCount: Int,
    @Json(name = "prekey_low") val prekeyLow: Boolean,
    @Json(name = "recommended_upload_count") val recommendedUploadCount: Int,
    @Json(name = "max_upload_count") val maxUploadCount: Int,
)
