package com.enigma.securechat.repository

import com.enigma.securechat.calls.CallEngine
import com.enigma.securechat.calls.CallEngineEvent
import com.enigma.securechat.calls.CallIceCandidate
import com.enigma.securechat.calls.CallMediaConfig
import com.enigma.securechat.data.db.CallEventDao
import com.enigma.securechat.data.db.CallEventEntity
import com.enigma.securechat.data.db.RelayTrustState
import com.enigma.securechat.data.db.RelayType
import com.enigma.securechat.data.repository.CallsRepository
import com.enigma.securechat.data.repository.RelayProfile
import com.enigma.securechat.domain.model.AppResult
import com.enigma.securechat.network.NetworkModule
import com.enigma.securechat.network.OfficialRelayResolver
import com.enigma.securechat.network.RelayScopedApiProvider
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.test.runTest
import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class CallsRepositoryTest {
    @Test
    fun webRtcSignalingUsesActiveBubbleIdAndStoresEvents() = runTest {
        MockWebServer().use { server ->
            server.enqueue(MockResponse().setBody(turnJson()))
            server.enqueue(
                MockResponse().setBody(
                    """
                    {
                      "id":"call-1",
                      "bubble_id":"bubble-1",
                      "call_kind":"video",
                      "state":"ringing",
                      "created_at":"2026-07-01T10:00:00Z",
                      "expires_at":"2026-07-01T10:02:00Z"
                    }
                    """.trimIndent(),
                ),
            )
            server.enqueue(MockResponse().setBody("""{"status":"ok"}"""))
            server.enqueue(MockResponse().setBody("""{"status":"ok"}"""))
            server.enqueue(
                MockResponse().setBody(
                    """
                    {
                      "events":[
                        {
                          "id":"answer-remote",
                          "bubble_id":"bubble-1",
                          "sender_user_id":"user-2",
                          "event_kind":"answer",
                          "payload":"remote-answer",
                          "created_at":"2026-07-01T10:01:00Z"
                        },
                        {
                          "id":"ice-remote",
                          "bubble_id":"bubble-1",
                          "sender_user_id":"user-2",
                          "event_kind":"ice",
                          "payload":"opaque-ice",
                          "created_at":"2026-07-01T10:01:01Z"
                        }
                      ]
                    }
                    """.trimIndent(),
                ),
            )
            server.enqueue(MockResponse().setBody(turnJson()))
            val dao = FakeCallEventDao()
            val engine = FakeCallEngine()
            val repository = CallsRepository(
                apiProvider = provider(server),
                callEventDao = dao,
                callEngine = engine,
                activeBubbleIdProvider = { "bubble-1" },
            )

            assertTrue(repository.startCall("user-2", video = true) is AppResult.Ok)
            assertTrue(
                repository.sendLocalIceCandidate(
                    CallEngineEvent.LocalIceCandidate(
                        callId = "call-1",
                        candidate = CallIceCandidate("0", 0, "local-ice"),
                    ),
                ) is AppResult.Ok,
            )
            assertTrue(repository.syncSignaling("call-1") is AppResult.Ok)
            val turn = repository.turnCredentials()

            assertTrue(turn is AppResult.Ok)
            assertEquals("local-offer", engine.createdOffers.single())
            assertEquals("remote-answer", engine.remoteAnswers.single())
            assertEquals("opaque-ice", engine.remoteIce.single().candidate)
            assertEquals(
                listOf(
                    "/v1/turn/credentials",
                    "/v1/calls",
                    "/v1/calls/call-1/offer",
                    "/v1/calls/call-1/ice-candidates",
                    "/v1/calls/call-1/signaling",
                    "/v1/turn/credentials",
                ),
                (0 until server.requestCount).map { server.takeRequest().path },
            )
            assertEquals(true, engine.outgoingConfigs.single().video)
            assertEquals(listOf("turn:relay.example:3478?transport=udp"), engine.outgoingConfigs.single().iceServers.single().urls)
            assertTrue(dao.events.any { it.eventKind == "created" && it.bubbleId == "bubble-1" })
            assertTrue(dao.events.any { it.eventKind == "offer" && it.bubbleId == "bubble-1" })
            assertTrue(dao.events.any { it.eventKind == "ice" && it.bubbleId == "bubble-1" })
            assertTrue(dao.events.any { it.eventKind == "answer" && it.bubbleId == "bubble-1" })
        }
    }

    private fun turnJson(): String =
        """
        {
          "username":"1700000000:user",
          "credential":"redacted",
          "ttl_seconds":600,
          "expires_at":"2026-07-01T10:10:00Z",
          "uris":["turn:relay.example:3478?transport=udp"],
          "realm":"relay.example"
        }
        """.trimIndent()

    private fun provider(server: MockWebServer): RelayScopedApiProvider =
        RelayScopedApiProvider(
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
            okHttpClientForBaseUrl = { OkHttpClient() },
            moshi = NetworkModule.moshi(),
        )

    private class FakeCallEngine : CallEngine {
        override val events: Flow<CallEngineEvent> = MutableSharedFlow()
        val outgoingConfigs = mutableListOf<CallMediaConfig>()
        val createdOffers = mutableListOf<String>()
        val remoteAnswers = mutableListOf<String>()
        val remoteIce = mutableListOf<CallIceCandidate>()

        override suspend fun startOutgoing(config: CallMediaConfig): String {
            outgoingConfigs += config
            return "local-offer".also { createdOffers += it }
        }

        override suspend fun acceptIncoming(config: CallMediaConfig, remoteOfferSdp: String): String =
            "local-answer"

        override suspend fun setRemoteAnswer(callId: String, remoteAnswerSdp: String) {
            remoteAnswers += remoteAnswerSdp
        }

        override suspend fun addRemoteIceCandidate(callId: String, candidate: CallIceCandidate) {
            remoteIce += candidate
        }

        override fun setMicrophoneEnabled(callId: String, enabled: Boolean) = Unit

        override fun setCameraEnabled(callId: String, enabled: Boolean) = Unit

        override fun setSpeakerEnabled(enabled: Boolean) = Unit

        override fun release(callId: String) = Unit

        override fun dispose() = Unit
    }

    private class FakeCallEventDao : CallEventDao {
        val events = mutableListOf<CallEventEntity>()
        private val state = MutableStateFlow<List<CallEventEntity>>(emptyList())

        override fun observeCallEvents(bubbleId: String): Flow<List<CallEventEntity>> = state

        override suspend fun latestForCall(callId: String): CallEventEntity? =
            events.lastOrNull { it.callId == callId }

        override suspend fun upsert(event: CallEventEntity) {
            events.removeAll { it.id == event.id }
            events += event
            state.value = events.toList()
        }
    }
}
