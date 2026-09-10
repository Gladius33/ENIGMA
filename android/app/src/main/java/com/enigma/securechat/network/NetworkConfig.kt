package com.enigma.securechat.network

data class NetworkConfig(
    val baseUrl: String,
    val cleartextAllowed: Boolean,
    val pinningEnabled: Boolean,
    val pinnedHost: String,
    val pinnedSha256: String,
) {
    init {
        val usesHttps = baseUrl.startsWith("https://")
        val usesHttp = baseUrl.startsWith("http://")
        require(usesHttps || usesHttp) {
            "baseUrl must start with http:// or https://"
        }
        require(baseUrl.endsWith("/")) { "baseUrl must end with /" }
        require(usesHttps || cleartextAllowed) {
            "cleartext HTTP is rejected for this build"
        }
        if (pinningEnabled) {
            require(usesHttps) { "certificate pinning requires HTTPS" }
            require(pinnedHost.isNotBlank())
            require(pinnedSha256.startsWith("sha256/"))
        }
    }
}
