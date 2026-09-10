package com.enigma.securechat.calls

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Test

class CallSignalingCodecTest {
    @Test
    fun iceCandidateRoundTripsAsOpaqueJson() {
        val candidate = CallIceCandidate(
            sdpMid = "0",
            sdpMLineIndex = 1,
            candidate = "candidate:1 1 UDP 2122252543 192.0.2.1 54321 typ host",
        )

        val wire = CallSignalingCodec.encodeIceCandidate(candidate)
        val decoded = CallSignalingCodec.decodeIceCandidate(wire)

        assertNotNull(decoded)
        assertEquals(candidate, decoded)
    }
}
