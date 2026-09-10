package com.enigma.securechat.network

import com.enigma.securechat.data.db.BubbleEntity
import com.enigma.securechat.data.db.BubbleIndexPolicy
import com.enigma.securechat.data.db.BubbleJoinPolicy
import com.enigma.securechat.data.db.BubbleMode
import com.enigma.securechat.data.db.BubbleVisibility
import com.enigma.securechat.data.db.RelayTrustState
import com.enigma.securechat.data.db.RelayType
import com.enigma.securechat.data.repository.ActiveBubbleContext
import com.enigma.securechat.data.repository.BubbleRelayPolicy
import com.enigma.securechat.data.repository.RelayProfile
import kotlinx.coroutines.test.runTest
import okhttp3.OkHttpClient
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class RelayScopedApiProviderTest {
    @Test
    fun defaultEndpointUsesOfficialRelay() {
        val provider = provider()

        val endpoint = provider.activeEndpoint.value

        assertEquals(OfficialRelayResolver.OFFICIAL_RELAY_ID, endpoint.primaryRelayId)
        assertEquals("https://official.example/", endpoint.primaryBaseUrl)
        assertFalse(endpoint.fallbackOfficialAllowed)
        assertFalse(endpoint.isolated)
    }

    @Test
    fun privateConnectedEndpointUsesPrivateRelayWithOfficialFallback() {
        val provider = provider()
        val privateRelay = relay(
            id = "private-relay",
            url = "wss://private.example/socket",
            official = false,
        )

        provider.updateActiveContext(
            context(
                mode = BubbleMode.PRIVATE_CONNECTED,
                primaryRelay = privateRelay,
                fallbackOfficialAllowed = true,
                isolated = false,
            ),
        )

        val endpoint = provider.activeEndpoint.value
        assertEquals("private-relay", endpoint.primaryRelayId)
        assertEquals("https://private.example/socket/", endpoint.primaryBaseUrl)
        assertEquals("https://official.example/", endpoint.fallbackBaseUrl)
        assertTrue(endpoint.fallbackOfficialAllowed)
        assertFalse(endpoint.isolated)
    }

    @Test
    fun privateIsolatedWithoutPrivateRelayDisablesNetworkEndpoint() {
        val provider = provider()

        provider.updateActiveContext(
            context(
                mode = BubbleMode.PRIVATE_ISOLATED,
                primaryRelay = null,
                fallbackOfficialAllowed = false,
                isolated = true,
            ),
        )

        val endpoint = provider.activeEndpoint.value
        assertNull(endpoint.primaryRelayId)
        assertNull(endpoint.primaryBaseUrl)
        assertNull(endpoint.fallbackBaseUrl)
        assertFalse(endpoint.fallbackOfficialAllowed)
        assertTrue(endpoint.isolated)
    }

    @Test
    fun privateRelayWithoutDedicatedSessionFailsBeforeNetworkOrFallback() = runTest {
        val provider = provider(relaySessionTokenProvider = { null })
        val privateRelay = relay(
            id = "private-relay",
            url = "https://private.example",
            official = false,
        )

        provider.updateActiveContext(
            context(
                mode = BubbleMode.PRIVATE_CONNECTED,
                primaryRelay = privateRelay,
                fallbackOfficialAllowed = true,
                isolated = false,
            ),
        )

        try {
            provider.withActiveApi<Nothing> {
                fail("Network call must not run without a relay-scoped session")
                error("unreachable")
            }
            fail("Expected RelaySessionRequiredException")
        } catch (error: RelaySessionRequiredException) {
            assertEquals("https://private.example/", error.relayBaseUrl)
        }
    }

    private fun provider(
        relaySessionTokenProvider: suspend (String) -> String? = { null },
    ): RelayScopedApiProvider =
        RelayScopedApiProvider(
            officialRelay = relay(
                id = OfficialRelayResolver.OFFICIAL_RELAY_ID,
                url = "https://official.example",
                official = true,
            ),
            okHttpClientForBaseUrl = { OkHttpClient() },
            moshi = NetworkModule.moshi(),
            relaySessionTokenProvider = relaySessionTokenProvider,
        )

    private fun context(
        mode: BubbleMode,
        primaryRelay: RelayProfile?,
        fallbackOfficialAllowed: Boolean,
        isolated: Boolean,
    ): ActiveBubbleContext =
        ActiveBubbleContext(
            bubble = BubbleEntity(
                id = "bubble-${mode.name.lowercase()}",
                slug = mode.name.lowercase(),
                name = mode.name,
                description = null,
                mode = mode.name,
                visibility = BubbleVisibility.PRIVATE.name,
                joinPolicy = BubbleJoinPolicy.INVITE_ONLY.name,
                indexPolicy = BubbleIndexPolicy.PRIVATE_ONLY.name,
                ownerIdentityId = null,
                publicKey = null,
                createdAt = 1L,
                updatedAt = 1L,
                deletedAt = null,
            ),
            relayPolicy = BubbleRelayPolicy(
                bubbleId = "bubble-${mode.name.lowercase()}",
                relayIds = primaryRelay?.let { listOf(it.id) }.orEmpty(),
                fallbackOfficialAllowed = fallbackOfficialAllowed,
                isolated = isolated,
            ),
            primaryRelay = primaryRelay,
            fallbackRelay = relay(
                id = OfficialRelayResolver.OFFICIAL_RELAY_ID,
                url = "https://official.example",
                official = true,
            ).takeIf { fallbackOfficialAllowed },
            showGlobalContacts = !isolated,
        )

    private fun relay(id: String, url: String, official: Boolean): RelayProfile =
        RelayProfile(
            id = id,
            name = if (official) OfficialRelayResolver.OFFICIAL_RELAY_NAME else "Private Relay",
            url = url,
            publicKey = null,
            type = if (official) RelayType.OFFICIAL else RelayType.PRIVATE,
            trustState = if (official) RelayTrustState.VERIFIED else RelayTrustState.UNVERIFIED,
            isOfficial = official,
            connected = official,
        )
}
