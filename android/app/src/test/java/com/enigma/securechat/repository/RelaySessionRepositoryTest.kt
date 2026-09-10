package com.enigma.securechat.repository

import com.enigma.securechat.crypto.CryptoEngine
import com.enigma.securechat.crypto.KyberPreKeyUpload
import com.enigma.securechat.crypto.LocalIdentity
import com.enigma.securechat.crypto.OneTimePreKeyUpload
import com.enigma.securechat.crypto.PreKeyUploadBundle
import com.enigma.securechat.crypto.RemoteDeviceBundle
import com.enigma.securechat.crypto.RemoteDeviceRef
import com.enigma.securechat.crypto.SignedPreKeyUpload
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
import com.enigma.securechat.data.repository.RelaySessionRepository
import com.enigma.securechat.domain.model.AppResult
import com.enigma.securechat.domain.model.UserSession
import com.enigma.securechat.network.AuthInterceptor
import com.enigma.securechat.network.NetworkModule
import com.enigma.securechat.network.OfficialRelayResolver
import com.enigma.securechat.network.RelayEndpoint
import com.enigma.securechat.network.RelayScopedApiProvider
import com.enigma.securechat.storage.DevicePersistence
import com.enigma.securechat.storage.RelaySessionPersistence
import kotlinx.coroutines.test.runTest
import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class RelaySessionRepositoryTest {
    @Test
    fun privateRelaySignInRegistersLocalDeviceAndUploadsKeysWithRelayToken() = runTest {
        MockWebServer().use { server ->
            val baseUrl = RelayEndpoint.apiBaseUrl(server.url("/").toString())
            server.enqueue(
                MockResponse().setBody(
                    """
                    {
                      "access_token":"bootstrap-token",
                      "token_type":"Bearer",
                      "expires_in":3600,
                      "user":{"id":"user-1","public_id":"alice"}
                    }
                    """.trimIndent(),
                ),
            )
            server.enqueue(
                MockResponse().setBody(
                    """
                    {
                      "device":{
                        "id":"00000000-0000-0000-0000-0000000000aa",
                        "display_name":"Pixel",
                        "platform":"android",
                        "created_at":"2026-07-01T10:00:00Z"
                      },
                      "access_token":"device-token",
                      "token_type":"Bearer",
                      "expires_in":3600
                    }
                    """.trimIndent(),
                ),
            )
            server.enqueue(
                MockResponse().setBody(
                    """
                    {
                      "device_id":"00000000-0000-0000-0000-0000000000aa",
                      "one_time_prekeys_received":1,
                      "one_time_prekey_count":1,
                      "prekey_low":false
                    }
                    """.trimIndent(),
                ),
            )
            val sessions = FakeRelaySessionStore()
            val provider = provider(server, sessions)
            provider.updateActiveContext(privateContext(server.url("/").toString()))
            val repository = RelaySessionRepository(
                apiProvider = provider,
                sessionStore = sessions,
                deviceStore = FakeDeviceStore("00000000-0000-0000-0000-0000000000aa"),
                cryptoEngine = FakeCryptoEngine(),
            )

            val result = repository.signInActivePrivateRelay(
                publicId = "alice",
                password = "correct horse battery staple",
                deviceName = "Pixel",
            )

            assertTrue(result is AppResult.Ok)
            assertEquals("device-token", sessions.sessions[baseUrl]?.accessToken)
            val login = server.takeRequest()
            val register = server.takeRequest()
            val uploadKeys = server.takeRequest()
            assertEquals("/v1/auth/login", login.path)
            assertNull(login.getHeader("Authorization"))
            assertEquals("/v1/devices/register", register.path)
            assertEquals("Bearer bootstrap-token", register.getHeader("Authorization"))
            assertTrue(
                register.body.readUtf8()
                    .contains(""""device_id":"00000000-0000-0000-0000-0000000000aa""""),
            )
            assertEquals("/v1/keys/upload", uploadKeys.path)
            assertEquals("Bearer device-token", uploadKeys.getHeader("Authorization"))
        }
    }

    private fun provider(
        server: MockWebServer,
        sessions: FakeRelaySessionStore,
    ): RelayScopedApiProvider =
        RelayScopedApiProvider(
            officialRelay = RelayProfile(
                id = OfficialRelayResolver.OFFICIAL_RELAY_ID,
                name = OfficialRelayResolver.OFFICIAL_RELAY_NAME,
                url = "https://official.example",
                publicKey = null,
                type = RelayType.OFFICIAL,
                trustState = RelayTrustState.VERIFIED,
                isOfficial = true,
                connected = true,
            ),
            okHttpClientForBaseUrl = { baseUrl ->
                OkHttpClient.Builder()
                    .addInterceptor(AuthInterceptor { sessions.relayAccessToken(baseUrl) })
                    .build()
            },
            moshi = NetworkModule.moshi(),
        )

    private fun privateContext(relayUrl: String): ActiveBubbleContext {
        val relay = RelayProfile(
            id = "private-relay",
            name = "Private Relay",
            url = relayUrl,
            publicKey = null,
            type = RelayType.PRIVATE,
            trustState = RelayTrustState.UNVERIFIED,
            isOfficial = false,
            connected = true,
        )
        return ActiveBubbleContext(
            bubble = BubbleEntity(
                id = "bubble-private",
                slug = "private",
                name = "Private",
                description = null,
                mode = BubbleMode.PRIVATE_ISOLATED.name,
                visibility = BubbleVisibility.SECRET.name,
                joinPolicy = BubbleJoinPolicy.INVITE_ONLY.name,
                indexPolicy = BubbleIndexPolicy.INDEX_FORBIDDEN.name,
                ownerIdentityId = null,
                publicKey = null,
                createdAt = 1L,
                updatedAt = 1L,
                deletedAt = null,
            ),
            relayPolicy = BubbleRelayPolicy(
                bubbleId = "bubble-private",
                relayIds = listOf(relay.id),
                fallbackOfficialAllowed = false,
                isolated = true,
            ),
            primaryRelay = relay,
            fallbackRelay = null,
            showGlobalContacts = false,
        )
    }

    private class FakeRelaySessionStore : RelaySessionPersistence {
        val sessions = mutableMapOf<String, UserSession>()

        override suspend fun saveRelaySession(baseUrl: String, value: UserSession) {
            sessions[baseUrl] = value
        }

        override suspend fun relayAccessToken(baseUrl: String): String? =
            sessions[baseUrl]?.accessToken

        override suspend fun clearRelaySession(baseUrl: String) {
            sessions.remove(baseUrl)
        }
    }

    private class FakeDeviceStore(private val localDeviceId: String) : DevicePersistence {
        override suspend fun saveDeviceId(deviceId: String) = Unit
        override suspend fun deviceId(): String = localDeviceId
        override suspend fun clearDeviceId() = Unit
    }

    private class FakeCryptoEngine : CryptoEngine {
        override suspend fun ensureIdentity(): LocalIdentity = unsupported()

        override suspend fun createPreKeyUpload(
            deviceId: String,
            oneTimePreKeyCount: Int,
        ): PreKeyUploadBundle = PreKeyUploadBundle(
            deviceId = deviceId,
            identityKey = "identity-key",
            registrationId = 12345,
            protocolDeviceId = 1,
            signedPreKey = SignedPreKeyUpload(
                keyId = 1,
                publicKey = "signed-prekey",
                signature = "signed-prekey-signature",
            ),
            kyberPreKey = KyberPreKeyUpload(
                keyId = 2,
                publicKey = "kyber-prekey",
                signature = "kyber-prekey-signature",
            ),
            oneTimePreKeys = listOf(
                OneTimePreKeyUpload(
                    keyId = 1,
                    publicKey = "one-time-prekey",
                ),
            ),
        )

        override suspend fun hasSession(recipient: RemoteDeviceRef): Boolean = unsupported()
        override suspend fun ensureSession(recipient: RemoteDeviceBundle): Unit = unsupported()
        override suspend fun encryptText(plaintext: String, recipient: RemoteDeviceRef): String = unsupported()
        override suspend fun encryptText(plaintext: String, recipient: RemoteDeviceBundle): String = unsupported()
        override suspend fun decryptText(ciphertext: String): String = unsupported()
    }
}

private fun unsupported(): Nothing = error("not used")
