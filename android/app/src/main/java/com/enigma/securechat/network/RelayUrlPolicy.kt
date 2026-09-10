package com.enigma.securechat.network

object RelayUrlPolicy {
    enum class Error {
        MISSING_SCHEME,
        CLEARTEXT_NOT_ALLOWED,
    }

    data class Validation(
        val normalizedUrl: String? = null,
        val error: Error? = null,
    )

    fun validate(value: String, cleartextAllowed: Boolean): Validation {
        val normalized = normalize(value)
        return when {
            normalized.startsWith("https://") -> Validation(normalizedUrl = normalized)
            normalized.startsWith("wss://") -> Validation(normalizedUrl = normalized)
            normalized.startsWith("http://") && cleartextAllowed -> Validation(normalizedUrl = normalized)
            normalized.startsWith("ws://") && cleartextAllowed -> Validation(normalizedUrl = normalized)
            normalized.startsWith("http://") -> Validation(error = Error.CLEARTEXT_NOT_ALLOWED)
            normalized.startsWith("ws://") -> Validation(error = Error.CLEARTEXT_NOT_ALLOWED)
            else -> Validation(error = Error.MISSING_SCHEME)
        }
    }

    fun normalize(value: String): String {
        val trimmed = value.trim()
        return if (trimmed.endsWith("/")) trimmed else "$trimmed/"
    }
}
