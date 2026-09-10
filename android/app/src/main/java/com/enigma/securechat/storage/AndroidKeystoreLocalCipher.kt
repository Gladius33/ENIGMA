package com.enigma.securechat.storage

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

class AndroidKeystoreLocalCipher(
    private val alias: String = "enigma_local_aes_v1",
) : LocalCipher {
    override fun encryptToString(plaintext: ByteArray): String {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKey())
        val nonce = cipher.iv
        val ciphertext = cipher.doFinal(plaintext)
        return listOf("v1", encode(nonce), encode(ciphertext)).joinToString(":").also {
            nonce.fill(0)
            ciphertext.fill(0)
        }
    }

    override fun decryptFromString(encoded: String): ByteArray {
        val parts = encoded.split(":")
        require(parts.size == 3 && parts[0] == "v1") { "Unsupported local ciphertext" }
        val nonce = decode(parts[1])
        val ciphertext = decode(parts[2])
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, getOrCreateKey(), GCMParameterSpec(128, nonce))
        return cipher.doFinal(ciphertext).also {
            nonce.fill(0)
            ciphertext.fill(0)
        }
    }

    private fun getOrCreateKey(): SecretKey {
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        keyStore.getKey(alias, null)?.let { return it as SecretKey }

        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        val spec = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setRandomizedEncryptionRequired(true)
            .setUserAuthenticationRequired(false)
            .build()
        generator.init(spec)
        return generator.generateKey()
    }

    private fun encode(bytes: ByteArray): String =
        Base64.getEncoder().withoutPadding().encodeToString(bytes)

    private fun decode(value: String): ByteArray =
        Base64.getDecoder().decode(value)

    private companion object {
        const val TRANSFORMATION = "AES/GCM/NoPadding"
    }
}
