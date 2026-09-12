package com.enigma.securechat.qr

import com.squareup.moshi.Moshi
import com.squareup.moshi.kotlin.reflect.KotlinJsonAdapterFactory
import java.net.URI
import java.util.Base64

data class EnigmaQrCode(
    val uri: String,
    val payloadJson: String,
)

data class IdentityQrPayload(
    val type: String = "enigma.identity",
    val version: Int = 1,
    val identity_id: String,
    val public_handle: String,
    val display_name: String,
    val public_key: String,
    val signature: String?,
)

data class BubbleInviteQrPayload(
    val type: String = "enigma.bubble_invite",
    val version: Int = 1,
    val bubble_id: String,
    val bubble_name: String,
    val mode: String,
    val relay_hint: String?,
    val invite_hint: String? = null,
    val expires_at: String? = null,
    val signature: String?,
)

data class RelayQrPayload(
    val type: String = "enigma.relay",
    val version: Int = 1,
    val name: String,
    val url: String,
    val public_key: String?,
    val signature: String?,
)

data class PairDeviceQrPayload(
    val type: String = "enigma.pair_device",
    val version: Int = 1,
    val protocol_version: Int = 1,
    val min_supported_version: Int = 1,
    val capabilities: Long,
    val pairing_session_id: String,
    val expires_at_unix_ms: Long,
    val pairing_public_key: String,
)

sealed interface ParsedEnigmaQrPayload {
    data class Identity(val payload: IdentityQrPayload) : ParsedEnigmaQrPayload
    data class Relay(val payload: RelayQrPayload) : ParsedEnigmaQrPayload
    data class BubbleInvite(val payload: BubbleInviteQrPayload) : ParsedEnigmaQrPayload
    data class PairDevice(val payload: PairDeviceQrPayload) : ParsedEnigmaQrPayload
}

object EnigmaQrPayloads {
    private val forbiddenSecretKey = Regex(
        "\"(token|password|private_key|identity_private|download_secret|access_token|refresh_token)\"\\s*:",
        RegexOption.IGNORE_CASE,
    )
    private val forbiddenQueryKeys = setOf(
        "token",
        "password",
        "private_key",
        "identity_private",
        "download_secret",
        "access_token",
        "refresh_token",
    )
    private val moshi = Moshi.Builder().add(KotlinJsonAdapterFactory()).build()
    private val identityAdapter = moshi.adapter(IdentityQrPayload::class.java)
    private val bubbleAdapter = moshi.adapter(BubbleInviteQrPayload::class.java)
    private val relayAdapter = moshi.adapter(RelayQrPayload::class.java)
    private val pairDeviceAdapter = moshi.adapter(PairDeviceQrPayload::class.java)

    fun identity(payload: IdentityQrPayload): EnigmaQrCode =
        encode("enigma://identity", identityAdapter.toJson(payload))

    fun contact(payload: IdentityQrPayload): EnigmaQrCode =
        identity(payload)

    fun bubbleInvite(payload: BubbleInviteQrPayload): EnigmaQrCode =
        encode("enigma://bubble-invite", bubbleAdapter.toJson(payload))

    fun relay(payload: RelayQrPayload): EnigmaQrCode =
        encode("enigma://relay", relayAdapter.toJson(payload))

    fun pairDevice(payload: PairDeviceQrPayload): EnigmaQrCode =
        encode("enigma://pair-device", pairDeviceAdapter.toJson(payload))

    fun parse(value: String): ParsedEnigmaQrPayload? {
        val payloadJson = decodePayloadJson(value.trim()) ?: return null
        if (forbiddenSecretKey.containsMatchIn(payloadJson)) return null
        return runCatching {
            when {
                payloadJson.contains("\"type\":\"enigma.identity\"") ->
                    identityAdapter.fromJson(payloadJson)?.let { ParsedEnigmaQrPayload.Identity(it) }
                payloadJson.contains("\"type\":\"enigma.relay\"") ->
                    relayAdapter.fromJson(payloadJson)
                        ?.takeIf { it.url.isAllowedRelayUrl() }
                        ?.let { ParsedEnigmaQrPayload.Relay(it) }
                payloadJson.contains("\"type\":\"enigma.bubble_invite\"") ->
                    bubbleAdapter.fromJson(payloadJson)
                        ?.takeIf { it.relay_hint?.isAllowedRelayUrl() != false }
                        ?.let { ParsedEnigmaQrPayload.BubbleInvite(it) }
                payloadJson.contains("\"type\":\"enigma.pair_device\"") ->
                    pairDeviceAdapter.fromJson(payloadJson)
                        ?.takeIf { it.isValidPairingBootstrap() }
                        ?.let { ParsedEnigmaQrPayload.PairDevice(it) }
                else -> null
            }
        }.getOrNull()
    }

    private fun encode(prefix: String, payloadJson: String): EnigmaQrCode {
        val payload = Base64.getUrlEncoder()
            .withoutPadding()
            .encodeToString(payloadJson.toByteArray(Charsets.UTF_8))
        return EnigmaQrCode(uri = "$prefix?payload=$payload", payloadJson = payloadJson)
    }

    private fun decodePayloadJson(value: String): String? {
        if (value.startsWith("{")) return value
        val encoded = value.substringAfter("payload=", missingDelimiterValue = "")
            .substringBefore("&")
        if (encoded.isBlank()) return null
        return runCatching {
            Base64.getUrlDecoder().decode(encoded).toString(Charsets.UTF_8)
        }.getOrNull()
    }

    private fun PairDeviceQrPayload.isValidPairingBootstrap(): Boolean {
        if (version != 1 || protocol_version != 1 || min_supported_version != 1) return false
        if (capabilities < 0 || capabilities and (1L shl 2) == 0L) return false
        if (expires_at_unix_ms <= System.currentTimeMillis()) return false
        if (runCatching { java.util.UUID.fromString(pairing_session_id) }.isFailure) return false
        val publicKey = runCatching { Base64.getDecoder().decode(pairing_public_key) }.getOrNull()
            ?: return false
        return try {
            publicKey.isNotEmpty() && publicKey.size <= 4_096
        } finally {
            publicKey.fill(0)
        }
    }

    private fun String.isAllowedRelayUrl(): Boolean {
        val uri = runCatching { URI(this) }.getOrNull() ?: return false
        val scheme = uri.scheme?.lowercase() ?: return false
        if (scheme !in setOf("https", "wss")) return false
        if (uri.host.isNullOrBlank()) return false
        if (!uri.rawUserInfo.isNullOrBlank()) return false
        return uri.rawQuery
            ?.split("&")
            ?.filter { it.isNotBlank() }
            ?.none { it.substringBefore("=").lowercase() in forbiddenQueryKeys }
            ?: true
    }
}
