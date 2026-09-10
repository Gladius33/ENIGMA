package com.enigma.securechat.network

object RelayEndpoint {
    fun apiBaseUrl(relayUrl: String): String =
        when {
            relayUrl.startsWith("wss://") -> relayUrl.replaceFirst("wss://", "https://")
            relayUrl.startsWith("ws://") -> relayUrl.replaceFirst("ws://", "http://")
            else -> relayUrl
        }.let { if (it.endsWith("/")) it else "$it/" }

    fun websocketBaseUrl(apiBaseUrl: String): String =
        when {
            apiBaseUrl.startsWith("https://") -> apiBaseUrl.replaceFirst("https://", "wss://")
            apiBaseUrl.startsWith("http://") -> apiBaseUrl.replaceFirst("http://", "ws://")
            else -> apiBaseUrl
        }.let { if (it.endsWith("/")) it else "$it/" }
}
