package com.enigma.securechat.calls

import com.squareup.moshi.Json
import com.squareup.moshi.Moshi
import com.squareup.moshi.kotlin.reflect.KotlinJsonAdapterFactory

object CallSignalingCodec {
    private val adapter = Moshi.Builder()
        .add(KotlinJsonAdapterFactory())
        .build()
        .adapter(WireIceCandidate::class.java)

    fun encodeIceCandidate(candidate: CallIceCandidate): String =
        adapter.toJson(
            WireIceCandidate(
                sdpMid = candidate.sdpMid,
                sdpMLineIndex = candidate.sdpMLineIndex,
                candidate = candidate.candidate,
            ),
        )

    fun decodeIceCandidate(value: String): CallIceCandidate? {
        val parsed = runCatching { adapter.fromJson(value) }.getOrNull()
        return if (parsed != null) {
            CallIceCandidate(
                sdpMid = parsed.sdpMid,
                sdpMLineIndex = parsed.sdpMLineIndex,
                candidate = parsed.candidate,
            )
        } else {
            value.takeIf { it.isNotBlank() }?.let {
                CallIceCandidate(sdpMid = "0", sdpMLineIndex = 0, candidate = it)
            }
        }
    }

    private data class WireIceCandidate(
        @Json(name = "sdp_mid") val sdpMid: String?,
        @Json(name = "sdp_m_line_index") val sdpMLineIndex: Int,
        val candidate: String,
    )
}
