package com.enigma.securechat.network

import com.enigma.securechat.domain.model.UserVisibleError
import com.squareup.moshi.Json
import com.squareup.moshi.Moshi
import com.squareup.moshi.kotlin.reflect.KotlinJsonAdapterFactory
import retrofit2.HttpException

object ApiErrorMapper {
    private val adapter = Moshi.Builder()
        .add(KotlinJsonAdapterFactory())
        .build()
        .adapter(ApiErrorBody::class.java)

    fun toUserVisibleError(
        error: Throwable,
        fallbackMessage: String,
    ): UserVisibleError {
        if (error is RelaySessionRequiredException) {
            return UserVisibleError(
                message = "Connexion au relais privé requise",
                recoverable = true,
                errorCode = "RELAY_SESSION_REQUIRED",
            )
        }
        if (error is BubbleSyncRequiredException) {
            return UserVisibleError(
                message = "Bulle non synchronisée avec le relais",
                recoverable = true,
                errorCode = "BUBBLE_SYNC_REQUIRED",
            )
        }

        val body = (error as? HttpException)
            ?.response()
            ?.errorBody()
            ?.string()
            ?.let { runCatching { adapter.fromJson(it) }.getOrNull() }

        val code = body?.errorCode
        return UserVisibleError(
            message = body?.message?.takeUnless { it == code } ?: fallbackMessage,
            recoverable = code !in NON_RECOVERABLE,
            errorCode = code,
            requestId = body?.requestId,
        )
    }

    private data class ApiErrorBody(
        @Json(name = "error_code") val errorCode: String?,
        val message: String?,
        @Json(name = "request_id") val requestId: String?,
    )

    private val NON_RECOVERABLE = setOf(
        "HANDLE_RESERVED",
    )
}

fun Throwable.toUserVisibleError(fallbackMessage: String): UserVisibleError =
    ApiErrorMapper.toUserVisibleError(this, fallbackMessage)

class BubbleSyncRequiredException : IllegalStateException("Bubble must be synchronized with the relay")
