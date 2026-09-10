package com.enigma.securechat.storage

interface LocalCipher {
    fun encryptToString(plaintext: ByteArray): String
    fun decryptFromString(encoded: String): ByteArray
}

