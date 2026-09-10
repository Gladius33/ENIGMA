package com.enigma.securechat.crypto

import com.squareup.moshi.Json
import com.squareup.moshi.Moshi
import com.squareup.moshi.kotlin.reflect.KotlinJsonAdapterFactory
import java.util.Base64

data class RecipientCiphertext(
    @Json(name = "device_id") val deviceId: String,
    val ciphertext: String,
)

data class RecipientEncryptedEnvelope(
    val version: Int = 1,
    @Json(name = "content_type") val contentType: String = "text/plain",
    val recipients: List<RecipientCiphertext>,
)

object RecipientEnvelopeCodec {
    private val adapter = Moshi.Builder()
        .add(KotlinJsonAdapterFactory())
        .build()
        .adapter(RecipientEncryptedEnvelope::class.java)

    fun encode(envelope: RecipientEncryptedEnvelope): String =
        Base64.getEncoder().encodeToString(adapter.toJson(envelope).toByteArray(Charsets.UTF_8))

    fun decode(value: String): RecipientEncryptedEnvelope =
        requireNotNull(
            adapter.fromJson(
                Base64.getDecoder().decode(value).toString(Charsets.UTF_8),
            ),
        ) { "Invalid recipient envelope" }

    fun ciphertextForDevice(value: String, deviceId: String): String? =
        decode(value).recipients.firstOrNull { it.deviceId == deviceId }?.ciphertext
}
