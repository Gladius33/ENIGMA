package com.enigma.securechat.crypto

import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.EOFException
import java.io.File
import java.io.InputStream
import java.io.OutputStream
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Versioned, bounded-memory attachment encryption.
 *
 * Format v1:
 *   magic[8] | chunk_size:u32 | nonce_prefix[8]
 *   repeated: plaintext_len:u32 | AES-GCM(ciphertext || tag)
 *   final: 0:u32 | AES-GCM(empty || tag)
 *
 * Every record authenticates the complete header, its chunk index and its plaintext length.
 * The authenticated empty final record makes truncation at a chunk boundary detectable.
 */
class AttachmentStreamCipher(
    private val random: SecureRandom = SecureRandom(),
    private val chunkSize: Int = DEFAULT_CHUNK_SIZE,
) {
    init {
        require(chunkSize in MIN_CHUNK_SIZE..MAX_CHUNK_SIZE) { "Invalid attachment chunk size" }
    }

    data class PreparedAttachment(
        val file: File,
        val sizeBytes: Long,
        val sha256: String,
        val key: String,
        val nonce: String,
    )

    fun encryptToFile(
        source: InputStream,
        destination: File,
        cancellationCheck: () -> Unit = {},
    ): PreparedAttachment {
        destination.parentFile?.mkdirs()
        val key = randomBytes(KEY_SIZE)
        val noncePrefix = randomBytes(NONCE_PREFIX_SIZE)
        val header = headerBytes(chunkSize, noncePrefix)
        val digest = MessageDigest.getInstance("SHA-256")

        try {
            destination.outputStream().buffered().use { rawOutput ->
                val output = DigestingOutputStream(rawOutput, digest)
                DataOutputStream(BufferedOutputStream(output, IO_BUFFER_SIZE)).use { data ->
                    data.write(header)
                    val buffer = ByteArray(chunkSize)
                    var chunkIndex = 0
                    try {
                        while (true) {
                            cancellationCheck()
                            val read = readChunk(source, buffer)
                            if (read == 0) break
                            require(chunkIndex < MAX_CHUNKS) { "Attachment exceeds streaming format chunk limit" }
                            data.writeInt(read)
                            val ciphertext = encryptRecord(
                                key = key,
                                noncePrefix = noncePrefix,
                                chunkIndex = chunkIndex,
                                plaintextLength = read,
                                plaintext = buffer,
                                plaintextOffset = 0,
                                header = header,
                                finalRecord = false,
                            )
                            try {
                                data.write(ciphertext)
                            } finally {
                                ciphertext.fill(0)
                                buffer.fill(0, 0, read)
                            }
                            chunkIndex += 1
                        }

                        cancellationCheck()
                        data.writeInt(0)
                        val finalTag = encryptRecord(
                            key = key,
                            noncePrefix = noncePrefix,
                            chunkIndex = chunkIndex,
                            plaintextLength = 0,
                            plaintext = EMPTY,
                            plaintextOffset = 0,
                            header = header,
                            finalRecord = true,
                        )
                        try {
                            data.write(finalTag)
                        } finally {
                            finalTag.fill(0)
                        }
                    } finally {
                        buffer.fill(0)
                    }
                }
            }

            return PreparedAttachment(
                file = destination,
                sizeBytes = destination.length(),
                sha256 = digest.digest().toHex(),
                key = Base64.getEncoder().withoutPadding().encodeToString(key),
                nonce = Base64.getEncoder().withoutPadding().encodeToString(noncePrefix),
            )
        } catch (error: Throwable) {
            destination.delete()
            throw error
        } finally {
            key.fill(0)
            noncePrefix.fill(0)
        }
    }

    fun decryptTo(
        encryptedSource: InputStream,
        keyBase64: String,
        expectedNonceBase64: String,
        destination: OutputStream,
        cancellationCheck: () -> Unit = {},
    ) {
        val key = Base64.getDecoder().decode(keyBase64)
        require(key.size == KEY_SIZE) { "Invalid attachment key" }

        val data = DataInputStream(BufferedInputStream(encryptedSource, IO_BUFFER_SIZE))
        val magic = ByteArray(MAGIC.size)
        val noncePrefix = ByteArray(NONCE_PREFIX_SIZE)
        try {
            data.readFully(magic)
            require(magic.contentEquals(MAGIC)) { "Unsupported attachment ciphertext format" }
            val encodedChunkSize = data.readInt()
            require(encodedChunkSize in MIN_CHUNK_SIZE..MAX_CHUNK_SIZE) { "Invalid attachment chunk size" }
            data.readFully(noncePrefix)

            val expectedNonce = Base64.getDecoder().decode(expectedNonceBase64)
            try {
                require(expectedNonce.size == NONCE_PREFIX_SIZE && expectedNonce.contentEquals(noncePrefix)) {
                    "Attachment nonce metadata mismatch"
                }
            } finally {
                expectedNonce.fill(0)
            }

            val header = headerBytes(encodedChunkSize, noncePrefix)
            val output = BufferedOutputStream(destination, IO_BUFFER_SIZE)
            var chunkIndex = 0
            while (true) {
                cancellationCheck()
                val plaintextLength = try {
                    data.readInt()
                } catch (_: EOFException) {
                    error("Truncated attachment ciphertext")
                }
                require(plaintextLength in 0..encodedChunkSize) { "Invalid encrypted attachment record length" }
                require(chunkIndex < MAX_CHUNKS) { "Attachment exceeds streaming format chunk limit" }

                val ciphertextLength = plaintextLength + GCM_TAG_SIZE
                val ciphertext = ByteArray(ciphertextLength)
                try {
                    data.readFully(ciphertext)
                    val finalRecord = plaintextLength == 0
                    val plaintext = decryptRecord(
                        key = key,
                        noncePrefix = noncePrefix,
                        chunkIndex = chunkIndex,
                        plaintextLength = plaintextLength,
                        ciphertext = ciphertext,
                        header = header,
                        finalRecord = finalRecord,
                    )
                    try {
                        if (finalRecord) {
                            require(plaintext.isEmpty()) { "Invalid attachment final record" }
                            require(data.read() == -1) { "Trailing data after attachment final record" }
                            output.flush()
                            return
                        }
                        output.write(plaintext)
                    } finally {
                        plaintext.fill(0)
                    }
                } catch (error: AEADBadTagException) {
                    throw IllegalArgumentException("Attachment authentication failed", error)
                } finally {
                    ciphertext.fill(0)
                }
                chunkIndex += 1
            }
        } finally {
            key.fill(0)
            magic.fill(0)
            noncePrefix.fill(0)
        }
    }

    fun isStreamingV1Nonce(nonceBase64: String): Boolean {
        val decoded = runCatching { Base64.getDecoder().decode(nonceBase64) }.getOrNull() ?: return false
        return try {
            decoded.size == NONCE_PREFIX_SIZE
        } finally {
            decoded.fill(0)
        }
    }

    private fun encryptRecord(
        key: ByteArray,
        noncePrefix: ByteArray,
        chunkIndex: Int,
        plaintextLength: Int,
        plaintext: ByteArray,
        plaintextOffset: Int,
        header: ByteArray,
        finalRecord: Boolean,
    ): ByteArray {
        val cipher = cipher(Cipher.ENCRYPT_MODE, key, noncePrefix, chunkIndex)
        cipher.updateAAD(recordAad(header, chunkIndex, plaintextLength, finalRecord))
        return cipher.doFinal(plaintext, plaintextOffset, plaintextLength)
    }

    private fun decryptRecord(
        key: ByteArray,
        noncePrefix: ByteArray,
        chunkIndex: Int,
        plaintextLength: Int,
        ciphertext: ByteArray,
        header: ByteArray,
        finalRecord: Boolean,
    ): ByteArray {
        val cipher = cipher(Cipher.DECRYPT_MODE, key, noncePrefix, chunkIndex)
        cipher.updateAAD(recordAad(header, chunkIndex, plaintextLength, finalRecord))
        return cipher.doFinal(ciphertext)
    }

    private fun cipher(mode: Int, key: ByteArray, noncePrefix: ByteArray, chunkIndex: Int): Cipher {
        val nonce = ByteBuffer.allocate(GCM_NONCE_SIZE)
            .put(noncePrefix)
            .putInt(chunkIndex)
            .array()
        return try {
            Cipher.getInstance("AES/GCM/NoPadding").apply {
                init(mode, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
            }
        } finally {
            nonce.fill(0)
        }
    }

    private fun recordAad(
        header: ByteArray,
        chunkIndex: Int,
        plaintextLength: Int,
        finalRecord: Boolean,
    ): ByteArray = ByteBuffer.allocate(header.size + 4 + 4 + 1)
        .put(header)
        .putInt(chunkIndex)
        .putInt(plaintextLength)
        .put(if (finalRecord) FINAL_MARKER else CHUNK_MARKER)
        .array()

    private fun headerBytes(chunkSize: Int, noncePrefix: ByteArray): ByteArray =
        ByteBuffer.allocate(MAGIC.size + 4 + NONCE_PREFIX_SIZE)
            .put(MAGIC)
            .putInt(chunkSize)
            .put(noncePrefix)
            .array()

    private fun readChunk(source: InputStream, buffer: ByteArray): Int {
        var total = 0
        while (total < buffer.size) {
            val read = source.read(buffer, total, buffer.size - total)
            if (read == -1) break
            if (read == 0) continue
            total += read
        }
        return total
    }

    private fun randomBytes(size: Int): ByteArray = ByteArray(size).also(random::nextBytes)

    private class DigestingOutputStream(
        private val delegate: OutputStream,
        private val digest: MessageDigest,
    ) : OutputStream() {
        override fun write(value: Int) {
            delegate.write(value)
            digest.update(value.toByte())
        }

        override fun write(buffer: ByteArray, offset: Int, length: Int) {
            delegate.write(buffer, offset, length)
            digest.update(buffer, offset, length)
        }

        override fun flush() = delegate.flush()
        override fun close() = delegate.close()
    }

    private fun ByteArray.toHex(): String = joinToString("") { byte -> "%02x".format(byte) }

    companion object {
        private val MAGIC = byteArrayOf(0x45, 0x4e, 0x49, 0x47, 0x4d, 0x41, 0x41, 0x31) // ENIGMAA1
        private val EMPTY = ByteArray(0)
        private const val KEY_SIZE = 32
        private const val NONCE_PREFIX_SIZE = 8
        private const val GCM_NONCE_SIZE = 12
        private const val GCM_TAG_SIZE = 16
        private const val DEFAULT_CHUNK_SIZE = 256 * 1024
        private const val MIN_CHUNK_SIZE = 4 * 1024
        private const val MAX_CHUNK_SIZE = 4 * 1024 * 1024
        private const val IO_BUFFER_SIZE = 64 * 1024
        private const val MAX_CHUNKS = Int.MAX_VALUE
        private const val CHUNK_MARKER: Byte = 0x01
        private const val FINAL_MARKER: Byte = 0x7f
    }
}
