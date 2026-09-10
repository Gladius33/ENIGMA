package com.enigma.securechat.crypto

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.nio.file.Files
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class AttachmentStreamCipherTest {
    @Test
    fun roundTripAcrossMultipleChunks() {
        val cipher = AttachmentStreamCipher(chunkSize = 4 * 1024)
        val plaintext = ByteArray(13_777) { index -> (index * 31).toByte() }
        val directory = Files.createTempDirectory("enigma-attachment-test").toFile()
        val encrypted = directory.resolve("roundtrip.eatt")

        try {
            val prepared = cipher.encryptToFile(ByteArrayInputStream(plaintext), encrypted)
            assertTrue(prepared.sizeBytes > plaintext.size)
            assertTrue(prepared.sha256.matches(Regex("[0-9a-f]{64}")))
            assertTrue(cipher.isStreamingV1Nonce(prepared.nonce))

            val output = ByteArrayOutputStream()
            encrypted.inputStream().use { source ->
                cipher.decryptTo(source, prepared.key, prepared.nonce, output)
            }
            assertArrayEquals(plaintext, output.toByteArray())
        } finally {
            encrypted.delete()
            directory.deleteRecursively()
            plaintext.fill(0)
        }
    }

    @Test
    fun tamperedCiphertextIsRejected() {
        val cipher = AttachmentStreamCipher(chunkSize = 4 * 1024)
        val plaintext = ByteArray(9_000) { index -> index.toByte() }
        val directory = Files.createTempDirectory("enigma-attachment-test").toFile()
        val encrypted = directory.resolve("tampered.eatt")

        try {
            val prepared = cipher.encryptToFile(ByteArrayInputStream(plaintext), encrypted)
            val bytes = encrypted.readBytes()
            bytes[bytes.lastIndex - 8] = (bytes[bytes.lastIndex - 8].toInt() xor 0x01).toByte()
            encrypted.writeBytes(bytes)
            bytes.fill(0)

            expectFailure {
                encrypted.inputStream().use { source ->
                    cipher.decryptTo(source, prepared.key, prepared.nonce, ByteArrayOutputStream())
                }
            }
        } finally {
            encrypted.delete()
            directory.deleteRecursively()
            plaintext.fill(0)
        }
    }

    @Test
    fun truncationAtRecordBoundaryIsRejected() {
        val cipher = AttachmentStreamCipher(chunkSize = 4 * 1024)
        val plaintext = ByteArray(4 * 1024) { 0x5a.toByte() }
        val directory = Files.createTempDirectory("enigma-attachment-test").toFile()
        val encrypted = directory.resolve("truncated.eatt")

        try {
            val prepared = cipher.encryptToFile(ByteArrayInputStream(plaintext), encrypted)
            val full = encrypted.readBytes()
            val finalRecordSize = 4 + 16
            encrypted.writeBytes(full.copyOf(full.size - finalRecordSize))
            full.fill(0)

            expectFailure {
                encrypted.inputStream().use { source ->
                    cipher.decryptTo(source, prepared.key, prepared.nonce, ByteArrayOutputStream())
                }
            }
        } finally {
            encrypted.delete()
            directory.deleteRecursively()
            plaintext.fill(0)
        }
    }

    @Test
    fun nonceMetadataMismatchIsRejected() {
        val cipher = AttachmentStreamCipher(chunkSize = 4 * 1024)
        val plaintext = "secret attachment".toByteArray()
        val directory = Files.createTempDirectory("enigma-attachment-test").toFile()
        val encrypted = directory.resolve("nonce.eatt")

        try {
            val prepared = cipher.encryptToFile(ByteArrayInputStream(plaintext), encrypted)
            val other = cipher.encryptToFile(
                ByteArrayInputStream("other".toByteArray()),
                directory.resolve("other.eatt"),
            )
            expectFailure {
                encrypted.inputStream().use { source ->
                    cipher.decryptTo(source, prepared.key, other.nonce, ByteArrayOutputStream())
                }
            }
        } finally {
            encrypted.delete()
            directory.deleteRecursively()
            plaintext.fill(0)
        }
    }

    private fun expectFailure(block: () -> Unit) {
        try {
            block()
        } catch (_: Exception) {
            return
        }
        fail("Expected attachment operation to fail")
    }
}
