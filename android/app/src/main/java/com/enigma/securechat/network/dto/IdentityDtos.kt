package com.enigma.securechat.network.dto

import com.squareup.moshi.Json

data class IdentityCheckResponseDto(
    val handle: String,
    @Json(name = "canonical_handle") val canonicalHandle: String?,
    val available: Boolean,
    val reason: String?,
)

data class CreateIdentityRequestDto(
    @Json(name = "display_name") val displayName: String,
    val password: String,
    @Json(name = "identity_public_key") val identityPublicKey: String,
    @Json(name = "registration_id") val registrationId: Int? = null,
    @Json(name = "protocol_device_id") val protocolDeviceId: Int? = null,
    @Json(name = "signed_prekey_id") val signedPrekeyId: Long? = null,
    @Json(name = "signed_prekey") val signedPrekey: String,
    @Json(name = "signed_prekey_signature") val signedPrekeySignature: String,
    @Json(name = "kyber_prekey") val kyberPrekey: KyberPreKeyDto? = null,
    @Json(name = "one_time_prekeys") val oneTimePrekeys: List<String>,
    @Json(name = "device_name") val deviceName: String,
    val platform: String = "android",
    @Json(name = "device_public_key") val devicePublicKey: String? = null,
    @Json(name = "recovery_key_verifier") val recoveryKeyVerifier: String? = null,
)

data class IdentityResponseDto(
    @Json(name = "identity_id") val identityId: String,
    @Json(name = "display_name") val displayName: String,
    @Json(name = "canonical_handle") val canonicalHandle: String,
    @Json(name = "public_handle") val publicHandle: String,
    @Json(name = "device_id") val deviceId: String,
    @Json(name = "access_token") val accessToken: String,
    @Json(name = "token_type") val tokenType: String,
    @Json(name = "expires_in") val expiresIn: Long,
    @Json(name = "created_at") val createdAt: String,
)

data class RecoverStartRequestDto(
    val handle: String,
)

data class RecoverStartResponseDto(
    @Json(name = "canonical_handle") val canonicalHandle: String,
    @Json(name = "recovery_configured") val recoveryConfigured: Boolean,
)

data class RecoverCompleteRequestDto(
    val handle: String,
    @Json(name = "recovery_secret") val recoverySecret: String,
    @Json(name = "identity_public_key") val identityPublicKey: String,
    @Json(name = "registration_id") val registrationId: Int? = null,
    @Json(name = "protocol_device_id") val protocolDeviceId: Int? = null,
    @Json(name = "signed_prekey_id") val signedPrekeyId: Long? = null,
    @Json(name = "signed_prekey") val signedPrekey: String,
    @Json(name = "signed_prekey_signature") val signedPrekeySignature: String,
    @Json(name = "kyber_prekey") val kyberPrekey: KyberPreKeyDto? = null,
    @Json(name = "one_time_prekeys") val oneTimePrekeys: List<String>,
    @Json(name = "device_name") val deviceName: String,
    val platform: String = "android",
    @Json(name = "device_public_key") val devicePublicKey: String? = null,
)

data class DeleteIdentityResponseDto(
    val status: String,
    @Json(name = "canonical_handle") val canonicalHandle: String,
    @Json(name = "reserved_forever") val reservedForever: Boolean,
)
