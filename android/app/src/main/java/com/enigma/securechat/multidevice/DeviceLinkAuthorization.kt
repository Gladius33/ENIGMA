package com.enigma.securechat.multidevice

import java.util.Base64
import java.util.UUID

data class DesktopLinkCandidate(
    val deviceId: String,
    val displayName: String,
    val platform: String,
    val pairingSessionId: String,
    val protocolVersion: Int,
    val minSupportedVersion: Int,
    val capabilities: Long,
    val targetIdentityKey: String,
)

data class AuthorizedDesktopLink(
    val deviceId: String,
    val displayName: String,
    val platform: String,
    val accessToken: String,
    val canonicalPayload: String,
    val authorizerSignature: String,
)

object DeviceLinkAuthorization {
    const val PROTOCOL_VERSION = 1
    const val MIN_SUPPORTED_VERSION = 1
    const val CAPABILITY_MULTI_DEVICE: Long = 1L shl 2
    private const val MAX_IDENTITY_KEY_BYTES = 4_096

    fun validateCandidate(candidate: DesktopLinkCandidate, authorizingDeviceId: String) {
        require(candidate.displayName.isNotBlank()) { "Desktop display name is required" }
        require(candidate.platform == "windows" || candidate.platform == "linux") {
            "Desktop platform must be windows or linux"
        }
        require(candidate.protocolVersion == PROTOCOL_VERSION) {
            "Unsupported multi-device protocol version"
        }
        require(candidate.minSupportedVersion in MIN_SUPPORTED_VERSION..PROTOCOL_VERSION) {
            "Unsupported minimum multi-device protocol version"
        }
        require(candidate.capabilities >= 0) { "Invalid device capability set" }
        require(candidate.capabilities and CAPABILITY_MULTI_DEVICE != 0L) {
            "Desktop must advertise multi-device support"
        }

        val newDeviceId = canonicalUuid(candidate.deviceId)
        val authorizerId = canonicalUuid(authorizingDeviceId)
        canonicalUuid(candidate.pairingSessionId)
        require(newDeviceId != authorizerId) { "A device cannot authorize itself" }

        val identity = runCatching { Base64.getDecoder().decode(candidate.targetIdentityKey) }
            .getOrElse { throw IllegalArgumentException("Invalid target Signal identity key", it) }
        try {
            require(identity.isNotEmpty() && identity.size <= MAX_IDENTITY_KEY_BYTES) {
                "Invalid target Signal identity key length"
            }
        } finally {
            identity.fill(0)
        }
    }

    fun canonicalPayload(
        accountId: String,
        newDeviceId: String,
        authorizingDeviceId: String,
        pairingSessionId: String,
        platform: String,
        protocolVersion: Int,
        minSupportedVersion: Int,
        capabilities: Long,
        issuedAtUnixMs: Long,
        targetIdentityKey: String,
        authorizerIdentityKey: String,
    ): String {
        val account = canonicalUuid(accountId)
        val newDevice = canonicalUuid(newDeviceId)
        val authorizer = canonicalUuid(authorizingDeviceId)
        val pairing = canonicalUuid(pairingSessionId)
        return buildString {
            append("ENIGMA_DEVICE_LINK_V1\n")
            append("account_id=").append(account).append('\n')
            append("new_device_id=").append(newDevice).append('\n')
            append("authorizing_device_id=").append(authorizer).append('\n')
            append("pairing_session_id=").append(pairing).append('\n')
            append("platform=").append(platform).append('\n')
            append("protocol_version=").append(protocolVersion).append('\n')
            append("min_supported_version=").append(minSupportedVersion).append('\n')
            append("capabilities=").append(capabilities).append('\n')
            append("issued_at_unix_ms=").append(issuedAtUnixMs).append('\n')
            append("target_identity_key=").append(targetIdentityKey).append('\n')
            append("authorizer_identity_key=").append(authorizerIdentityKey).append('\n')
        }
    }

    private fun canonicalUuid(value: String): String = UUID.fromString(value).toString()
}
