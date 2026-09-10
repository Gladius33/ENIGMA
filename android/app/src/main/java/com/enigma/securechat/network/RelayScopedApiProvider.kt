package com.enigma.securechat.network

import com.enigma.securechat.data.repository.ActiveBubbleContext
import com.enigma.securechat.data.repository.RelayProfile
import com.enigma.securechat.network.dto.P2pSignalCommandDto
import com.squareup.moshi.Moshi
import java.util.concurrent.ConcurrentHashMap
import kotlin.coroutines.cancellation.CancellationException
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.runBlocking
import okhttp3.OkHttpClient

data class ActiveRelayEndpoint(
    val bubbleId: String?,
    val bubbleMode: String?,
    val primaryRelayId: String?,
    val primaryBaseUrl: String?,
    val fallbackOfficialAllowed: Boolean,
    val fallbackBaseUrl: String?,
    val isolated: Boolean,
    val requiresDedicatedSession: Boolean,
) {
    val displayBaseUrl: String = primaryBaseUrl ?: "relay-unavailable"
}

class RelaySessionRequiredException(
    val relayBaseUrl: String,
) : IllegalStateException("Private relay session required")

class RelayScopedApiProvider(
    private val officialRelay: RelayProfile,
    private val okHttpClientForBaseUrl: (String) -> OkHttpClient,
    private val moshi: Moshi,
    private val relaySessionTokenProvider: suspend (String) -> String? = { null },
) {
    private val apiCache = ConcurrentHashMap<String, ChatApiService>()
    private val clientCache = ConcurrentHashMap<String, OkHttpClient>()
    private val realtimeCache = ConcurrentHashMap<String, RealtimeClient>()
    private val scopedRealtimeClient = RelayScopedRealtimeClient(this)
    @Volatile private var activeContext: ActiveBubbleContext? = null
    private val _activeEndpoint = MutableStateFlow(endpointFor(null))
    val activeEndpoint: StateFlow<ActiveRelayEndpoint> = _activeEndpoint.asStateFlow()

    fun officialApi(): ChatApiService = apiFor(RelayEndpoint.apiBaseUrl(officialRelay.url))

    fun sessionSetupApi(baseUrl: String): ChatApiService =
        apiFor(RelayEndpoint.apiBaseUrl(baseUrl))

    fun realtimeClient(): RealtimeClient = scopedRealtimeClient

    fun updateActiveContext(context: ActiveBubbleContext?) {
        activeContext = context
        _activeEndpoint.value = endpointFor(context)
        scopedRealtimeClient.disconnect()
    }

    suspend fun activeApi(): ChatApiService {
        val endpoint = activeEndpoint.value
        val baseUrl = endpoint.primaryBaseUrl
            ?: error("Private isolated bubble requires a private relay before network access")
        ensureRelaySessionIfNeeded(endpoint, baseUrl)
        return apiFor(baseUrl)
    }

    suspend fun <T> withActiveApi(block: suspend (ChatApiService) -> T): T {
        val endpoint = activeEndpoint.value
        val primaryBaseUrl = endpoint.primaryBaseUrl
            ?: error("Private isolated bubble requires a private relay before network access")
        ensureRelaySessionIfNeeded(endpoint, primaryBaseUrl)
        return try {
            block(apiFor(primaryBaseUrl))
        } catch (error: Throwable) {
            if (error is CancellationException) throw error
            val fallbackBaseUrl = endpoint.fallbackBaseUrl
            if (!endpoint.fallbackOfficialAllowed || fallbackBaseUrl == null || fallbackBaseUrl == primaryBaseUrl) {
                throw error
            }
            ensureRelaySessionIfNeeded(endpoint.copy(requiresDedicatedSession = false), fallbackBaseUrl)
            block(apiFor(fallbackBaseUrl))
        }
    }

    internal fun activeRealtimeClient(): RealtimeClient {
        val baseUrl = activeEndpoint.value.primaryBaseUrl ?: return DisabledRealtimeClient
        return realtimeCache.getOrPut(baseUrl) {
            ChatWebSocketClient(baseUrl, clientFor(baseUrl), moshi)
        }
    }

    internal fun realtimeTokenForActiveEndpoint(fallbackOfficialToken: String): String? {
        val endpoint = activeEndpoint.value
        val baseUrl = endpoint.primaryBaseUrl ?: return null
        return if (endpoint.requiresDedicatedSession) {
            runBlocking { relaySessionTokenProvider(baseUrl) }
        } else {
            fallbackOfficialToken
        }
    }

    private fun apiFor(baseUrl: String): ChatApiService {
        return apiCache.getOrPut(baseUrl) {
            NetworkModule.api(baseUrl, clientFor(baseUrl), moshi)
        }
    }

    private fun clientFor(baseUrl: String): OkHttpClient =
        clientCache.getOrPut(baseUrl) { okHttpClientForBaseUrl(baseUrl) }

    private fun endpointFor(context: ActiveBubbleContext?): ActiveRelayEndpoint {
        val officialBaseUrl = RelayEndpoint.apiBaseUrl(officialRelay.url)
        val relay = context?.primaryRelay ?: officialRelay
        val isolatedWithoutPrivateRelay = context?.relayPolicy?.isolated == true && relay.isOfficial
        val primaryBaseUrl = if (isolatedWithoutPrivateRelay) {
            null
        } else {
            RelayEndpoint.apiBaseUrl(relay.url)
        }
        val fallback = context?.fallbackRelay
            ?.takeIf { context.relayPolicy.fallbackOfficialAllowed }
            ?.let { RelayEndpoint.apiBaseUrl(it.url) }
        return ActiveRelayEndpoint(
            bubbleId = context?.bubble?.id,
            bubbleMode = context?.bubble?.mode,
            primaryRelayId = if (isolatedWithoutPrivateRelay) null else relay.id,
            primaryBaseUrl = primaryBaseUrl,
            fallbackOfficialAllowed = context?.relayPolicy?.fallbackOfficialAllowed == true,
            fallbackBaseUrl = fallback ?: officialBaseUrl.takeIf {
                context?.relayPolicy?.fallbackOfficialAllowed == true && primaryBaseUrl != officialBaseUrl
            },
            isolated = context?.relayPolicy?.isolated == true,
            requiresDedicatedSession = primaryBaseUrl != null && primaryBaseUrl != officialBaseUrl,
        )
    }

    private suspend fun ensureRelaySessionIfNeeded(endpoint: ActiveRelayEndpoint, baseUrl: String) {
        if (endpoint.requiresDedicatedSession && relaySessionTokenProvider(baseUrl).isNullOrBlank()) {
            throw RelaySessionRequiredException(baseUrl)
        }
    }
}

private class RelayScopedRealtimeClient(
    private val provider: RelayScopedApiProvider,
) : RealtimeClient {
    @Volatile
    private var delegate: RealtimeClient? = null

    override fun connect(
        token: String,
        deviceId: String,
        onEvent: (com.enigma.securechat.network.dto.WsEventDto) -> Unit,
        onDisconnected: () -> Unit,
    ) {
        disconnect()
        val scopedToken = provider.realtimeTokenForActiveEndpoint(token)
        if (scopedToken.isNullOrBlank()) {
            onDisconnected()
            return
        }
        val client = provider.activeRealtimeClient()
        delegate = client
        client.connect(scopedToken, deviceId, onEvent, onDisconnected)
    }

    override fun sendP2pSignal(command: P2pSignalCommandDto): Boolean =
        delegate?.sendP2pSignal(command) == true

    override fun disconnect() {
        delegate?.disconnect()
        delegate = null
    }
}

private object DisabledRealtimeClient : RealtimeClient {
    override fun connect(
        token: String,
        deviceId: String,
        onEvent: (com.enigma.securechat.network.dto.WsEventDto) -> Unit,
        onDisconnected: () -> Unit,
    ) {
        onDisconnected()
    }

    override fun sendP2pSignal(command: P2pSignalCommandDto): Boolean = false

    override fun disconnect() = Unit
}
