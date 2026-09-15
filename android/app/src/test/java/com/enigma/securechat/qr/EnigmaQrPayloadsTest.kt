package com.enigma.securechat.qr

import java.io.File
import java.util.Base64
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class EnigmaQrPayloadsTest {
    @Test
    fun identityQrUsesVersionedPayloadUri() {
        val qr = EnigmaQrPayloads.identity(
            IdentityQrPayload(
                identity_id = "identity-id",
                public_handle = "@seb63",
                display_name = "Seb",
                public_key = "public-key",
                signature = "signature",
            ),
        )

        assertTrue(qr.uri.startsWith("enigma://identity?payload="))
        assertTrue(qr.payloadJson.contains("\"type\":\"enigma.identity\""))
        assertTrue(qr.payloadJson.contains("\"version\":1"))
    }

    @Test
    fun relayQrPayloadIsBase64UrlEncoded() {
        val qr = EnigmaQrPayloads.relay(
            RelayQrPayload(
                name = "Relais prive",
                url = "wss://relay.example",
                public_key = "public-key",
                signature = "signature",
            ),
        )
        val encoded = qr.uri.substringAfter("payload=")
        val decoded = Base64.getUrlDecoder().decode(encoded).toString(Charsets.UTF_8)

        assertEquals(qr.payloadJson, decoded)
        assertTrue(decoded.contains("\"type\":\"enigma.relay\""))
    }

    @Test
    fun parsesRelayAndBubbleInviteQrPayloads() {
        val relay = EnigmaQrPayloads.relay(
            RelayQrPayload(
                name = "Relais prive",
                url = "wss://relay.example",
                public_key = null,
                signature = null,
            ),
        )
        val bubble = EnigmaQrPayloads.bubbleInvite(
            BubbleInviteQrPayload(
                bubble_id = "bubble-1",
                bubble_name = "Private",
                mode = "PRIVATE_CONNECTED",
                relay_hint = "wss://relay.example",
                signature = null,
            ),
        )

        assertTrue(EnigmaQrPayloads.parse(relay.uri) is ParsedEnigmaQrPayload.Relay)
        assertTrue(EnigmaQrPayloads.parse(bubble.uri) is ParsedEnigmaQrPayload.BubbleInvite)
        val forbiddenInviteField = listOf("invite", "token").joinToString("_")
        assertTrue(bubble.payloadJson.contains(forbiddenInviteField).not())
    }

    @Test
    fun parsesLivePairDeviceBootstrapAndRejectsExpiredOne() {
        val pairingKey = Base64.getEncoder().withoutPadding()
            .encodeToString(ByteArray(32) { 5 })
        val candidateCommitment = Base64.getEncoder().withoutPadding()
            .encodeToString(ByteArray(32) { 7 })
        val live = EnigmaQrPayloads.pairDevice(
            PairDeviceQrPayload(
                capabilities = 1L shl 2,
                pairing_session_id = "22222222-2222-4222-8222-222222222222",
                expires_at_unix_ms = System.currentTimeMillis() + 60_000,
                pairing_public_key = pairingKey,
                candidate_commitment = candidateCommitment,
            ),
        )

        assertTrue(EnigmaQrPayloads.parse(live.uri) is ParsedEnigmaQrPayload.PairDevice)

        val expired = EnigmaQrPayloads.pairDevice(
            PairDeviceQrPayload(
                capabilities = 1L shl 2,
                pairing_session_id = "22222222-2222-4222-8222-222222222222",
                expires_at_unix_ms = System.currentTimeMillis() - 1,
                pairing_public_key = pairingKey,
                candidate_commitment = candidateCommitment,
            ),
        )
        assertEquals(null, EnigmaQrPayloads.parse(expired.uri))
    }

    @Test
    fun rejectsPairDeviceBootstrapWithInvalidCandidateCommitment() {
        val pairingKey = Base64.getEncoder().withoutPadding()
            .encodeToString(ByteArray(32) { 5 })
        val validCommitment = Base64.getEncoder().withoutPadding()
            .encodeToString(ByteArray(32) { 7 })
        val base = PairDeviceQrPayload(
            capabilities = 1L shl 2,
            pairing_session_id = "22222222-2222-4222-8222-222222222222",
            expires_at_unix_ms = System.currentTimeMillis() + 60_000,
            pairing_public_key = pairingKey,
            candidate_commitment = validCommitment,
        )

        val tooShort = EnigmaQrPayloads.pairDevice(
            base.copy(
                candidate_commitment = Base64.getEncoder().withoutPadding()
                    .encodeToString(ByteArray(31) { 7 }),
            ),
        )
        val invalidBase64 = EnigmaQrPayloads.pairDevice(
            base.copy(candidate_commitment = "%%%invalid%%%"),
        )

        assertEquals(null, EnigmaQrPayloads.parse(tooShort.uri))
        assertEquals(null, EnigmaQrPayloads.parse(invalidBase64.uri))
    }

    @Test
    fun parsesDesktopRustPairingBootstrapFromInteropFixture() {
        val fixturePath = System.getenv("ENIGMA_ANDROID_PAIRING_URI") ?: return
        val uri = File(fixturePath).readText().trim()
        val parsed = EnigmaQrPayloads.parse(uri)

        assertTrue(parsed is ParsedEnigmaQrPayload.PairDevice)
        val pairing = (parsed as ParsedEnigmaQrPayload.PairDevice).payload
        assertEquals(1, pairing.version)
        assertEquals(1, pairing.protocol_version)
        assertEquals(1, pairing.min_supported_version)
        assertTrue(pairing.capabilities and (1L shl 2) != 0L)
        assertTrue(pairing.expires_at_unix_ms > System.currentTimeMillis())
        assertTrue(Base64.getDecoder().decode(pairing.pairing_public_key).isNotEmpty())
        assertEquals(32, Base64.getDecoder().decode(pairing.candidate_commitment).size)
    }

    @Test
    fun rejectsQrPayloadsContainingSecrets() {
        val forbiddenKeys = listOf(
            "token",
            "password",
            "private_key",
            "identity_private",
            "download_secret",
            "access_token",
            "refresh_token",
        )

        forbiddenKeys.forEach { key ->
            val payload = encodedJson(
                """{"type":"enigma.relay","version":1,"name":"Relais","url":"wss://relay.example","$key":"secret"}""",
            )

            assertEquals(null, EnigmaQrPayloads.parse("enigma://relay?payload=$payload"))
        }
    }

    @Test
    fun rejectsRelayQrWithInvalidOrSecretBearingUrl() {
        val invalidUrls = listOf(
            "ftp://relay.example",
            "http://relay.example",
            "wss://user:pass@relay.example",
            "wss://relay.example?token=secret",
            "wss://relay.example?access_token=secret",
            "wss://relay.example?refresh_token=secret",
            "not a url",
        )

        invalidUrls.forEach { url ->
            val payload = encodedJson(
                """{"type":"enigma.relay","version":1,"name":"Relais","url":"$url"}""",
            )

            assertEquals(null, EnigmaQrPayloads.parse("enigma://relay?payload=$payload"))
        }
    }

    @Test
    fun rejectsBubbleInviteWithInvalidRelayHint() {
        val payload = encodedJson(
            """
            {
              "type":"enigma.bubble_invite",
              "version":1,
              "bubble_id":"bubble-1",
              "bubble_name":"Private",
              "mode":"PRIVATE_ISOLATED",
              "relay_hint":"ftp://relay.example"
            }
            """.trimIndent(),
        )

        assertEquals(null, EnigmaQrPayloads.parse("enigma://bubble-invite?payload=$payload"))
    }

    private fun encodedJson(json: String): String =
        Base64.getUrlEncoder()
            .withoutPadding()
            .encodeToString(json.toByteArray(Charsets.UTF_8))
}
