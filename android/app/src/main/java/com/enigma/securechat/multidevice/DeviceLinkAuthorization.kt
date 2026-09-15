package com.enigma.securechat.multidevice

import java.security.MessageDigest
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
    val expiresAtUnixMs: Long,
    val pairingPublicKey: String,
    val targetIdentityKey: String,
    val claimSecretHash: String,
    val candidateCommitment: String,
)

data class AuthorizedDesktopLink(
    val deviceId: String,
    val displayName: String,
    val platform: String,
    val canonicalPayload: String,
    val authorizerSignature: String,
)

data class ParsedDeviceAuthorization(
    val accountId: String,
    val newDeviceId: String,
    val authorizingDeviceId: String,
    val pairingSessionId: String,
    val platform: String,
    val protocolVersion: Int,
    val minSupportedVersion: Int,
    val capabilities: Long,
    val issuedAtUnixMs: Long,
    val targetIdentityKey: String,
    val candidateCommitment: String,
    val authorizerIdentityKey: String,
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

        require(candidate.expiresAtUnixMs > System.currentTimeMillis()) {
            "Pairing candidate has expired"
        }
        require(candidate.claimSecretHash.length == 64 &&
            candidate.claimSecretHash.all { it.isDigit() || it in 'a'..'f' }) {
            "Invalid pairing claim secret hash"
        }

        val pairingKey = runCatching { Base64.getDecoder().decode(candidate.pairingPublicKey) }
            .getOrElse { throw IllegalArgumentException("Invalid pairing public key", it) }
        val identity = runCatching { Base64.getDecoder().decode(candidate.targetIdentityKey) }
            .getOrElse { throw IllegalArgumentException("Invalid target Signal identity key", it) }
        val commitment = runCatching { Base64.getDecoder().decode(candidate.candidateCommitment) }
            .getOrElse { throw IllegalArgumentException("Invalid candidate commitment", it) }
        try {
            require(pairingKey.size == 32) { "Invalid pairing public key length" }
            require(identity.isNotEmpty() && identity.size <= MAX_IDENTITY_KEY_BYTES) {
                "Invalid target Signal identity key length"
            }
            require(commitment.size == 32) { "Invalid candidate commitment length" }
            require(candidateCommitment(candidate) == candidate.candidateCommitment) {
                "Pairing candidate commitment mismatch"
            }
        } finally {
            pairingKey.fill(0)
            identity.fill(0)
            commitment.fill(0)
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
        candidateCommitment: String,
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
            append("candidate_commitment=").append(candidateCommitment).append('\n')
            append("authorizer_identity_key=").append(authorizerIdentityKey).append('\n')
        }
    }

    fun parseCanonicalPayload(value: String): ParsedDeviceAuthorization {
        require(value.endsWith('\n')) { "Authorization transcript must end with a newline" }
        val lines = value.removeSuffix("\n").split('\n')
        require(lines.size == 13 && lines.first() == "ENIGMA_DEVICE_LINK_V1") {
            "Invalid authorization transcript shape"
        }
        val expectedKeys = listOf(
            "account_id",
            "new_device_id",
            "authorizing_device_id",
            "pairing_session_id",
            "platform",
            "protocol_version",
            "min_supported_version",
            "capabilities",
            "issued_at_unix_ms",
            "target_identity_key",
            "candidate_commitment",
            "authorizer_identity_key",
        )
        val values = expectedKeys.mapIndexed { index, key ->
            val line = lines[index + 1]
            val prefix = "$key="
            require(line.startsWith(prefix)) { "Authorization transcript field order mismatch" }
            line.removePrefix(prefix).also { fieldValue ->
                require(fieldValue.isNotBlank()) { "Authorization transcript field is empty" }
            }
        }
        val parsed = ParsedDeviceAuthorization(
            accountId = canonicalUuid(values[0]),
            newDeviceId = canonicalUuid(values[1]),
            authorizingDeviceId = canonicalUuid(values[2]),
            pairingSessionId = canonicalUuid(values[3]),
            platform = values[4],
            protocolVersion = values[5].toInt(),
            minSupportedVersion = values[6].toInt(),
            capabilities = values[7].toLong(),
            issuedAtUnixMs = values[8].toLong(),
            targetIdentityKey = values[9],
            candidateCommitment = values[10],
            authorizerIdentityKey = values[11],
        )
        require(parsed.platform == "windows" || parsed.platform == "linux") {
            "Invalid authorized platform"
        }
        require(parsed.protocolVersion == PROTOCOL_VERSION)
        require(parsed.minSupportedVersion in MIN_SUPPORTED_VERSION..PROTOCOL_VERSION)
        require(parsed.capabilities and CAPABILITY_MULTI_DEVICE != 0L)
        require(parsed.issuedAtUnixMs > 0L)
        return parsed
    }

    fun candidateCommitment(candidate: DesktopLinkCandidate): String {
        val canonical = buildString {
            append("ENIGMA_PAIRING_CANDIDATE_V1\n")
            append("pairing_session_id=").append(canonicalUuid(candidate.pairingSessionId)).append('\n')
            append("device_id=").append(canonicalUuid(candidate.deviceId)).append('\n')
            append("display_name=").append(candidate.displayName).append('\n')
            append("platform=").append(candidate.platform).append('\n')
            append("protocol_version=").append(candidate.protocolVersion).append('\n')
            append("min_supported_version=").append(candidate.minSupportedVersion).append('\n')
            append("capabilities=").append(candidate.capabilities).append('\n')
            append("expires_at_unix_ms=").append(candidate.expiresAtUnixMs).append('\n')
            append("pairing_public_key=").append(candidate.pairingPublicKey).append('\n')
            append("target_identity_key=").append(candidate.targetIdentityKey).append('\n')
            append("claim_secret_hash=").append(candidate.claimSecretHash).append('\n')
        }
        val digest = MessageDigest.getInstance("SHA-256")
            .digest(canonical.toByteArray(Charsets.UTF_8))
        return try {
            Base64.getEncoder().withoutPadding().encodeToString(digest)
        } finally {
            digest.fill(0)
        }
    }

    private fun canonicalUuid(value: String): String = UUID.fromString(value).toString()
}
