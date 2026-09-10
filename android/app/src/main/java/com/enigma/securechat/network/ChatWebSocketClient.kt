package com.enigma.securechat.network

import com.enigma.securechat.network.dto.P2pSignalCommandDto
import com.enigma.securechat.network.dto.WsEventDto
import com.squareup.moshi.Moshi
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import okio.ByteString

class ChatWebSocketClient(
    private val baseUrl: String,
    private val okHttpClient: OkHttpClient,
    moshi: Moshi,
) : RealtimeClient {
    private val adapter = moshi.adapter(WsEventDto::class.java)
    private val p2pSignalAdapter = moshi.adapter(P2pSignalCommandDto::class.java)
    @Volatile
    private var webSocket: WebSocket? = null

    override fun connect(
        token: String,
        deviceId: String,
        onEvent: (WsEventDto) -> Unit,
        onDisconnected: () -> Unit,
    ) {
        disconnect()
        val httpUrl = RelayEndpoint.apiBaseUrl(baseUrl)
            .toHttpUrl()
            .newBuilder()
            .addPathSegments("v1/ws")
            .addQueryParameter("device_id", deviceId)
            .build()
        val wsUrl = RelayEndpoint.websocketBaseUrl(httpUrl.toString())

        val request = Request.Builder()
            .url(wsUrl)
            .header("Authorization", "Bearer $token")
            .build()
        webSocket = okHttpClient.newWebSocket(
            request,
            object : WebSocketListener() {
                override fun onMessage(webSocket: WebSocket, text: String) {
                    val event = runCatching { adapter.fromJson(text) }.getOrNull()
                    if (event != null) {
                        onEvent(event)
                    }
                }

                override fun onMessage(webSocket: WebSocket, bytes: ByteString) = Unit

                override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                    if (this@ChatWebSocketClient.webSocket === webSocket) {
                        this@ChatWebSocketClient.webSocket = null
                    }
                    SafeLog.warn("WS", "WebSocket disconnected", t)
                    onDisconnected()
                }

                override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
                    if (this@ChatWebSocketClient.webSocket === webSocket) {
                        this@ChatWebSocketClient.webSocket = null
                    }
                    onDisconnected()
                }
            },
        )
    }

    override fun sendP2pSignal(command: P2pSignalCommandDto): Boolean {
        val payload = runCatching { p2pSignalAdapter.toJson(command) }.getOrNull() ?: return false
        return webSocket?.send(payload) == true
    }

    override fun disconnect() {
        webSocket?.close(1000, "closed")
        webSocket = null
    }
}

interface RealtimeClient {
    fun connect(
        token: String,
        deviceId: String,
        onEvent: (WsEventDto) -> Unit,
        onDisconnected: () -> Unit,
    )

    fun sendP2pSignal(command: P2pSignalCommandDto): Boolean = false

    fun disconnect()
}
