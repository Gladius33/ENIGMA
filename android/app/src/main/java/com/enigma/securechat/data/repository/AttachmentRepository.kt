package com.enigma.securechat.data.repository

import com.enigma.securechat.crypto.AttachmentStreamCipher
import com.enigma.securechat.domain.model.AppResult
import com.enigma.securechat.domain.model.AttachmentDescriptor
import com.enigma.securechat.network.AttachmentHttpClient
import com.enigma.securechat.network.RelayScopedApiProvider
import com.enigma.securechat.network.dto.CompleteUploadRequestDto
import com.enigma.securechat.network.dto.PresignDownloadRequestDto
import com.enigma.securechat.network.dto.PresignUploadRequestDto
import com.enigma.securechat.network.dto.RepresignUploadRequestDto
import com.enigma.securechat.network.toUserVisibleError
import com.enigma.securechat.storage.RelaySettingsStore
import com.enigma.securechat.storage.SecureFileStore
import java.io.File
import java.io.InputStream
import java.io.OutputStream
import java.security.MessageDigest
import java.util.UUID
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext

class AttachmentRepository(
    private val apiProvider: RelayScopedApiProvider,
    private val httpClient: AttachmentHttpClient,
    private val tempDirectory: File,
    private val fileStore: SecureFileStore,
    private val streamCipher: AttachmentStreamCipher = AttachmentStreamCipher(),
    private val activeBubbleIdProvider: suspend () -> String = {
        RelaySettingsStore.DEFAULT_MAIN_BUBBLE_ID
    },
) {
    /** Relay-backed upload used by groups/channels and any non-P2P container. */
    suspend fun uploadEncrypted(source: InputStream, contentType: String): AppResult<AttachmentDescriptor> =
        runCatching {
            val descriptor = prepareReservation(source, contentType)
            uploadPreparedForRelayOrThrow(descriptor)
            descriptor
        }.fold(
            onSuccess = { AppResult.Ok(it) },
            onFailure = { AppResult.Err(it.toUserVisibleError("Pièce jointe non envoyée")) },
        )

    /**
     * Direct-message preparation. This encrypts locally and reserves the blob id,
     * but deliberately does not upload the ciphertext to object storage.
     */
    suspend fun prepareDirectEncrypted(
        source: InputStream,
        contentType: String,
    ): AppResult<AttachmentDescriptor> = runCatching {
        prepareReservation(source, contentType)
    }.fold(
        onSuccess = { AppResult.Ok(it) },
        onFailure = { AppResult.Err(it.toUserVisibleError("Pièce jointe non préparée")) },
    )

    suspend fun uploadPreparedForRelay(descriptor: AttachmentDescriptor): AppResult<Unit> = runCatching {
        uploadPreparedForRelayOrThrow(descriptor)
    }.fold(
        onSuccess = { AppResult.Ok(Unit) },
        onFailure = { AppResult.Err(it.toUserVisibleError("Pièce jointe non envoyée au relais")) },
    )

    fun hasVerifiedLocalCiphertext(descriptor: AttachmentDescriptor): Boolean {
        val file = fileStore.encryptedAttachment(descriptor.blobId) ?: return false
        if (file.length() != descriptor.sizeBytes) return false
        return runCatching { sha256(file).equals(descriptor.sha256, ignoreCase = true) }
            .getOrDefault(false)
    }

    suspend fun downloadAndDecryptTo(
        descriptor: AttachmentDescriptor,
        destination: OutputStream,
    ): AppResult<Unit> = runCatching {
        require(streamCipher.isStreamingV1Nonce(descriptor.nonce)) {
            "Unsupported attachment format"
        }

        val encryptedFile = withContext(Dispatchers.IO) {
            val cached = fileStore.encryptedAttachment(descriptor.blobId)
            if (cached != null) {
                if (
                    cached.length() == descriptor.sizeBytes &&
                    sha256(cached).equals(descriptor.sha256, ignoreCase = true)
                ) {
                    cached
                } else {
                    fileStore.deleteAttachment(descriptor.blobId)
                    null
                }
            } else {
                null
            }
        } ?: downloadAndCache(descriptor)

        withContext(Dispatchers.IO) {
            val context = currentCoroutineContext()
            encryptedFile.inputStream().use { encryptedSource ->
                streamCipher.decryptTo(
                    encryptedSource = encryptedSource,
                    keyBase64 = descriptor.key,
                    expectedNonceBase64 = descriptor.nonce,
                    destination = DISCARD_OUTPUT,
                    cancellationCheck = { context.ensureActive() },
                )
            }
            encryptedFile.inputStream().use { encryptedSource ->
                streamCipher.decryptTo(
                    encryptedSource = encryptedSource,
                    keyBase64 = descriptor.key,
                    expectedNonceBase64 = descriptor.nonce,
                    destination = destination,
                    cancellationCheck = { context.ensureActive() },
                )
            }
        }
    }.fold(
        onSuccess = { AppResult.Ok(Unit) },
        onFailure = { AppResult.Err(it.toUserVisibleError("Pièce jointe illisible")) },
    )

    private suspend fun prepareReservation(source: InputStream, contentType: String): AttachmentDescriptor {
        val bubbleId = activeBubbleIdProvider()
        val tempFile = fileStore.createPreparedTempFile()
        val prepared = try {
            withContext(Dispatchers.IO) {
                val context = currentCoroutineContext()
                streamCipher.encryptToFile(source, tempFile) { context.ensureActive() }
            }
        } catch (error: Throwable) {
            withContext(NonCancellable + Dispatchers.IO) { tempFile.delete() }
            throw error
        }

        try {
            val presigned = apiProvider.withActiveApi { api ->
                api.presignUpload(
                    PresignUploadRequestDto(
                        bubbleId = bubbleId,
                        sizeBytes = prepared.sizeBytes,
                        sha256 = prepared.sha256,
                        contentType = contentType,
                    ),
                )
            }
            val descriptor = AttachmentDescriptor(
                blobId = presigned.blobId,
                bubbleId = presigned.bubbleId,
                contentType = contentType,
                sizeBytes = prepared.sizeBytes,
                sha256 = prepared.sha256,
                key = prepared.key,
                nonce = prepared.nonce,
                downloadSecret = presigned.downloadSecret,
            )
            withContext(Dispatchers.IO) {
                fileStore.promotePrepared(descriptor.blobId, prepared.file)
            }
            return descriptor
        } catch (error: Throwable) {
            withContext(NonCancellable + Dispatchers.IO) { prepared.file.delete() }
            throw error
        }
    }

    private suspend fun uploadPreparedForRelayOrThrow(descriptor: AttachmentDescriptor) {
        require(streamCipher.isStreamingV1Nonce(descriptor.nonce)) { "Unsupported attachment format" }
        val encryptedFile = withContext(Dispatchers.IO) {
            requireNotNull(fileStore.encryptedAttachment(descriptor.blobId)) {
                "Prepared attachment ciphertext missing"
            }.also { file ->
                require(file.length() == descriptor.sizeBytes) { "Prepared attachment size mismatch" }
                require(sha256(file).equals(descriptor.sha256, ignoreCase = true)) {
                    "Prepared attachment hash mismatch"
                }
            }
        }

        apiProvider.withActiveApi { api ->
            val presigned = api.represignUpload(
                blobId = descriptor.blobId,
                body = RepresignUploadRequestDto(
                    bubbleId = descriptor.bubbleId,
                    downloadSecret = descriptor.downloadSecret,
                ),
            )
            require(presigned.blobId == descriptor.blobId) { "Re-presigned blob mismatch" }
            require(presigned.bubbleId == descriptor.bubbleId) { "Re-presigned bubble mismatch" }

            when (presigned.status) {
                "pending" -> {
                    require(presigned.method == "PUT") { "Unsupported attachment upload method" }
                    val url = requireNotNull(presigned.url) { "Missing attachment upload URL" }
                    httpClient.uploadEncryptedFile(
                        url = url,
                        headers = presigned.headers,
                        contentType = descriptor.contentType,
                        encryptedFile = encryptedFile,
                    )
                }
                "verified" -> Unit
                else -> error("Unsupported attachment re-presign state")
            }

            val completed = api.completeUpload(
                blobId = descriptor.blobId,
                body = CompleteUploadRequestDto(
                    downloadSecret = descriptor.downloadSecret,
                    sizeBytes = descriptor.sizeBytes,
                    sha256 = descriptor.sha256,
                ),
            )
            require(completed.status == "verified") { "Attachment upload was not verified" }
            require(completed.sizeBytes == descriptor.sizeBytes) { "Verified attachment size mismatch" }
            require(completed.sha256.equals(descriptor.sha256, ignoreCase = true)) {
                "Verified attachment hash mismatch"
            }
        }
    }

    private suspend fun downloadAndCache(descriptor: AttachmentDescriptor): File {
        val presigned = apiProvider.withActiveApi { api ->
            api.presignDownload(
                PresignDownloadRequestDto(
                    blobId = descriptor.blobId,
                    bubbleId = descriptor.bubbleId,
                    downloadSecret = descriptor.downloadSecret,
                ),
            )
        }
        val tempFile = newTempFile("download", ".eatt")
        val downloaded = httpClient.downloadEncryptedFile(presigned.url, tempFile)
        try {
            require(downloaded.sizeBytes == descriptor.sizeBytes) { "Attachment ciphertext size mismatch" }
            require(downloaded.sha256.equals(descriptor.sha256, ignoreCase = true)) {
                "Attachment ciphertext hash mismatch"
            }
            return withContext(Dispatchers.IO) {
                fileStore.promotePrepared(descriptor.blobId, downloaded.file)
            }
        } catch (error: Throwable) {
            withContext(NonCancellable + Dispatchers.IO) { downloaded.file.delete() }
            throw error
        }
    }

    private fun sha256(file: File): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val buffer = ByteArray(64 * 1024)
        try {
            file.inputStream().buffered().use { input ->
                while (true) {
                    val read = input.read(buffer)
                    if (read == -1) break
                    if (read == 0) continue
                    digest.update(buffer, 0, read)
                }
            }
        } finally {
            buffer.fill(0)
        }
        return digest.digest().joinToString("") { "%02x".format(it) }
    }

    private fun newTempFile(prefix: String, suffix: String): File {
        tempDirectory.mkdirs()
        return File(tempDirectory, "$prefix-${UUID.randomUUID()}$suffix")
    }

    private companion object {
        val DISCARD_OUTPUT = object : OutputStream() {
            override fun write(value: Int) = Unit
            override fun write(buffer: ByteArray, offset: Int, length: Int) = Unit
        }
    }
}
