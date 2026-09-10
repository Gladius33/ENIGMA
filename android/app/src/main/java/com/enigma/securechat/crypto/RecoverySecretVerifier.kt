package com.enigma.securechat.crypto

import java.security.SecureRandom
import java.util.Base64
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

data class GeneratedRecoverySecret(
    val secret: String,
    val verifier: String,
)

object RecoverySecretVerifier {
    private const val ITERATIONS = 120_000
    private const val KEY_BITS = 256
    private val random = SecureRandom()
    private val encoder = Base64.getUrlEncoder().withoutPadding()

    fun generate(): GeneratedRecoverySecret {
        val secretBytes = ByteArray(24).also(random::nextBytes)
        val secret = encoder.encodeToString(secretBytes)
        secretBytes.fill(0)
        return GeneratedRecoverySecret(secret, verifier(secret))
    }

    fun verifier(secret: String): String {
        val salt = ByteArray(16).also(random::nextBytes)
        val hash = pbkdf2(secret.toCharArray(), salt)
        return buildString {
            append("pbkdf2-sha256$")
            append(ITERATIONS)
            append('$')
            append(encoder.encodeToString(salt))
            append('$')
            append(encoder.encodeToString(hash))
        }.also {
            salt.fill(0)
            hash.fill(0)
        }
    }

    private fun pbkdf2(secret: CharArray, salt: ByteArray): ByteArray {
        val spec = PBEKeySpec(secret, salt, ITERATIONS, KEY_BITS)
        return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).encoded
            .also { secret.fill('\u0000') }
    }
}
