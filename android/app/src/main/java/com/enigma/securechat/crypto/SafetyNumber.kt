package com.enigma.securechat.crypto

import java.security.MessageDigest

object SafetyNumber {
    fun localFingerprint(identityPublicKey: String): String =
        digest("enigma-local-identity-v1", identityPublicKey).toGroupedCode()

    fun pairFingerprint(
        localIdentityPublicKey: String,
        remoteIdentityPublicKey: String,
    ): String {
        val ordered = listOf(localIdentityPublicKey, remoteIdentityPublicKey).sorted()
        return digest("enigma-safety-number-v1", ordered[0], ordered[1]).toGroupedCode()
    }

    private fun digest(vararg parts: String): ByteArray {
        val digest = MessageDigest.getInstance("SHA-256")
        parts.forEach { part ->
            digest.update(part.toByteArray(Charsets.UTF_8))
            digest.update(0.toByte())
        }
        return digest.digest()
    }

    private fun ByteArray.toGroupedCode(): String =
        take(15)
            .joinToString(separator = "") { "%02X".format(it) }
            .chunked(5)
            .joinToString(separator = " ")
}
