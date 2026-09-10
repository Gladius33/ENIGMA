package com.enigma.securechat.qr

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
