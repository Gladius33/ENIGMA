package com.enigma.securechat.network

import org.junit.Test

class NetworkConfigTest {
    @Test(expected = IllegalArgumentException::class)
    fun rejectsCleartextWhenDisabled() {
        NetworkConfig(
            baseUrl = "http://relay.example.org/",
            cleartextAllowed = false,
            pinningEnabled = false,
            pinnedHost = "",
            pinnedSha256 = "",
        )
    }

    @Test
    fun acceptsCleartextWhenAllowed() {
        NetworkConfig(
            baseUrl = "http://10.0.2.2:8080/",
            cleartextAllowed = true,
            pinningEnabled = false,
            pinnedHost = "",
            pinnedSha256 = "",
        )
    }

    @Test
    fun acceptsHttpsWithoutPinning() {
        NetworkConfig(
            baseUrl = "https://relay.example.org/",
            cleartextAllowed = false,
            pinningEnabled = false,
            pinnedHost = "",
            pinnedSha256 = "",
        )
    }
}
