package com.enigma.securechat.network

import java.io.File
import java.security.MessageDigest
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.job
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.asRequestBody
import okhttp3.RequestBody.Companion.toRequestBody

class AttachmentHttpClient(
    private val okHttpClient: OkHttpClient,
) {
    data class DownloadedAttachment(
        val file: File,
        val sizeBytes: Long,
        val sha256: String,
    )

    suspend fun uploadEncryptedFile(
        url: String,
        headers: Map<String, String>,
        contentType: String,
        encryptedFile: File,
    ) = withContext(Dispatchers.IO) {
        require(encryptedFile.isFile) { "Encrypted attachment file is missing" }
        val requestBuilder = Request.Builder()
            .url(url)
            .put(encryptedFile.asRequestBody(contentType.toMediaType()))
        headers.forEach { (name, value) -> requestBuilder.header(name, value) }
        val call = okHttpClient.newCall(requestBuilder.build())
        val cancellationHandle = currentCoroutineContext().job.invokeOnCompletion { cause ->
            if (cause is CancellationException) call.cancel()
        }
        try {
            call.execute().use { response ->
                currentCoroutineContext().ensureActive()
                if (!response.isSuccessful) error("Attachment upload failed: HTTP ${response.code}")
            }
        } finally {
            cancellationHandle.dispose()
        }
    }

    suspend fun downloadEncryptedFile(url: String, destination: File): DownloadedAttachment =
        withContext(Dispatchers.IO) {
            destination.parentFile?.mkdirs()
            val request = Request.Builder().url(url).get().build()
            val call = okHttpClient.newCall(request)
            val cancellationHandle = currentCoroutineContext().job.invokeOnCompletion { cause ->
                if (cause is CancellationException) call.cancel()
            }
            try {
                call.execute().use { response ->
                    if (!response.isSuccessful) error("Attachment download failed: HTTP ${response.code}")
                    val body = requireNotNull(response.body) { "Attachment download returned no body" }
                    val digest = MessageDigest.getInstance("SHA-256")
                    var size = 0L
                    body.byteStream().use { input ->
                        destination.outputStream().buffered().use { output ->
                            val buffer = ByteArray(IO_BUFFER_SIZE)
                            try {
                                while (true) {
                                    currentCoroutineContext().ensureActive()
                                    val read = input.read(buffer)
                                    if (read == -1) break
                                    if (read == 0) continue
                                    output.write(buffer, 0, read)
                                    digest.update(buffer, 0, read)
                                    size += read
                                }
                            } finally {
                                buffer.fill(0)
                            }
                        }
                    }
                    DownloadedAttachment(
                        file = destination,
                        sizeBytes = size,
                        sha256 = digest.digest().toHex(),
                    )
                }
            } catch (error: Throwable) {
                destination.delete()
                throw error
            } finally {
                cancellationHandle.dispose()
            }
        }

    /** Legacy helper retained only for decrypting pre-stream-v1 attachments. */
    @Deprecated("Use streaming attachment transfers")
    fun uploadEncryptedBytes(
        url: String,
        headers: Map<String, String>,
        contentType: String,
        encryptedBytes: ByteArray,
    ) {
        val requestBuilder = Request.Builder()
            .url(url)
            .put(encryptedBytes.toRequestBody(contentType.toMediaType()))
        headers.forEach { (name, value) -> requestBuilder.header(name, value) }
        okHttpClient.newCall(requestBuilder.build()).execute().use { response ->
            if (!response.isSuccessful) error("Attachment upload failed: HTTP ${response.code}")
        }
    }

    /** Legacy helper retained only for decrypting pre-stream-v1 attachments. */
    @Deprecated("Use streaming attachment transfers")
    fun downloadEncryptedBytes(url: String): ByteArray {
        val request = Request.Builder().url(url).get().build()
        return okHttpClient.newCall(request).execute().use { response ->
            if (!response.isSuccessful) error("Attachment download failed: HTTP ${response.code}")
            requireNotNull(response.body).bytes()
        }
    }

    private fun ByteArray.toHex(): String = joinToString("") { byte -> "%02x".format(byte) }

    private companion object {
        const val IO_BUFFER_SIZE = 64 * 1024
    }
}
