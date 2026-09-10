package com.enigma.securechat.media

data class EncryptedMediaDraft(
    val contentType: String,
    val ciphertextPath: String,
    val thumbnailCiphertextPath: String?,
    val sizeBytes: Long,
)

interface MediaEncryptor {
    suspend fun encryptForUpload(uri: String, contentType: String): EncryptedMediaDraft
}
