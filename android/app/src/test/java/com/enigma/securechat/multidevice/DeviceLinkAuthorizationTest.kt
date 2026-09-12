package com.enigma.securechat.multidevice

import java.util.Base64
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class DeviceLinkAuthorizationTest {
    @Test
    fun canonicalPayloadMatchesServerWireContract() {
        val payload = DeviceLinkAuthorization.canonicalPayload(
            accountId = "33333333-3333-4333-8333-333333333333",
            newDeviceId = "11111111-1111-4111-8111-111111111111",
            authorizingDeviceId = "44444444-4444-4444-8444-444444444444",
            pairingSessionId = "22222222-2222-4222-8222-222222222222",
            platform = "windows",
            protocolVersion = 1,
            minSupportedVersion = 1,
            capabilities = 127,
            issuedAtUnixMs = 1_700_000_000_000,
            targetIdentityKey = "target-public",
            authorizerIdentityKey = "authorizer-public",
        )

        assertEquals(
            """
            ENIGMA_DEVICE_LINK_V1
            account_id=33333333-3333-4333-8333-333333333333
            new_device_id=11111111-1111-4111-8111-111111111111
            authorizing_device_id=44444444-4444-4444-8444-444444444444
            pairing_session_id=22222222-2222-4222-8222-222222222222
            platform=windows
            protocol_version=1
            min_supported_version=1
            capabilities=127
            issued_at_unix_ms=1700000000000
            target_identity_key=target-public
            authorizer_identity_key=authorizer-public

            """.trimIndent(),
            payload,
        )
    }

    @Test
    fun candidateValidationRequiresMultiDeviceAndDistinctUuidDevices() {
        val identityKey = Base64.getEncoder().withoutPadding()
            .encodeToString(ByteArray(33) { 7 })
        val valid = DesktopLinkCandidate(
            deviceId = "11111111-1111-4111-8111-111111111111",
            displayName = "Windows",
            platform = "windows",
            pairingSessionId = "22222222-2222-4222-8222-222222222222",
            protocolVersion = 1,
            minSupportedVersion = 1,
            capabilities = DeviceLinkAuthorization.CAPABILITY_MULTI_DEVICE,
            targetIdentityKey = identityKey,
        )

        DeviceLinkAuthorization.validateCandidate(
            valid,
            authorizingDeviceId = "44444444-4444-4444-8444-444444444444",
        )

        val missingCapability = valid.copy(capabilities = 0)
        assertThrows(IllegalArgumentException::class.java) {
            DeviceLinkAuthorization.validateCandidate(
                missingCapability,
                "44444444-4444-4444-8444-444444444444",
            )
        }

        assertThrows(IllegalArgumentException::class.java) {
            DeviceLinkAuthorization.validateCandidate(valid, valid.deviceId)
        }
        assertTrue(identityKey.isNotBlank())
    }
}
