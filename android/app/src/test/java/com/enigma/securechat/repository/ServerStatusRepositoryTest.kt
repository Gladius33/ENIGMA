package com.enigma.securechat.repository

import com.enigma.securechat.data.repository.ServerStatusRepository
import com.enigma.securechat.data.repository.RelayProfile
import com.enigma.securechat.data.db.RelayTrustState
import com.enigma.securechat.data.db.RelayType
import com.enigma.securechat.domain.model.AppResult
import com.enigma.securechat.network.NetworkModule
import com.enigma.securechat.network.OfficialRelayResolver
import com.enigma.securechat.network.RelayScopedApiProvider
import kotlinx.coroutines.test.runTest
import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ServerStatusRepositoryTest {
    @Test
    fun checksHealthAndVersionAtRootEndpoints() = runTest {
        MockWebServer().use { server ->
            server.enqueue(MockResponse().setBody("""{"status":"ok"}"""))
            server.enqueue(
                MockResponse().setBody("""{"name":"enigma-e2ee-server","version":"0.1.0"}"""),
            )
            val client = OkHttpClient()
            val moshi = NetworkModule.moshi()
            val provider = RelayScopedApiProvider(
                officialRelay = RelayProfile(
                    id = OfficialRelayResolver.OFFICIAL_RELAY_ID,
                    name = OfficialRelayResolver.OFFICIAL_RELAY_NAME,
                    url = server.url("/").toString(),
                    publicKey = null,
                    type = RelayType.OFFICIAL,
                    trustState = RelayTrustState.VERIFIED,
                    isOfficial = true,
                    connected = true,
                ),
                okHttpClientForBaseUrl = { client },
                moshi = moshi,
            )
            val repository = ServerStatusRepository(provider)

            val result = repository.check()

            assertTrue(result is AppResult.Ok)
            val status = (result as AppResult.Ok).value
            assertEquals("ok", status.status)
            assertEquals("enigma-e2ee-server", status.name)
            assertEquals("0.1.0", status.version)
            assertEquals("/health", server.takeRequest().path)
            assertEquals("/version", server.takeRequest().path)
        }
    }
}
