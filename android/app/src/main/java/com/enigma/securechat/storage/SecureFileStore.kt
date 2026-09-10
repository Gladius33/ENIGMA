package com.enigma.securechat.storage

import android.content.Context
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.InputStream
import java.util.UUID

class SecureFileStore(context: Context) {
    private val attachmentDir = File(context.filesDir, "attachments").apply { mkdirs() }
    private val partialDir = File(attachmentDir, "p2p-partials").apply { mkdirs() }

    fun createPreparedTempFile(): File =
        File.createTempFile("prepared-", ".eatt", attachmentDir)

    fun promotePrepared(blobId: String, preparedFile: File): File {
        requireBlobId(blobId)
        require(preparedFile.isFile && preparedFile.length() > 0L) { "Prepared attachment missing" }
        val destination = attachmentFile(blobId)
        if (destination.exists() && !destination.delete()) {
            error("Unable to replace local attachment")
        }
        if (!preparedFile.renameTo(destination)) {
            preparedFile.inputStream().use { source ->
                FileOutputStream(destination, false).buffered().use { output -> source.copyTo(output) }
            }
            if (!preparedFile.delete()) {
                destination.delete()
                error("Unable to remove prepared attachment")
            }
        }
        return destination
    }

    fun encryptedAttachment(blobId: String): File? {
        requireBlobId(blobId)
        return attachmentFile(blobId).takeIf { it.isFile && it.length() > 0L }
    }

    fun openEncryptedAttachment(blobId: String): InputStream? =
        encryptedAttachment(blobId)?.let(::FileInputStream)

    fun partialLength(blobId: String, sha256: String): Long {
        val file = partialFile(blobId, sha256)
        return file.takeIf(File::isFile)?.length() ?: 0L
    }

    fun openPartial(blobId: String, sha256: String): InputStream? =
        partialFile(blobId, sha256).takeIf(File::isFile)?.let(::FileInputStream)

    fun openPartialForAppend(blobId: String, sha256: String, expectedOffset: Long): FileOutputStream {
        require(expectedOffset >= 0L) { "Invalid P2P attachment offset" }
        val file = partialFile(blobId, sha256)
        val actual = file.takeIf(File::exists)?.length() ?: 0L
        require(actual == expectedOffset) { "P2P attachment offset mismatch" }
        file.parentFile?.mkdirs()
        return FileOutputStream(file, true)
    }

    fun discardPartial(blobId: String, sha256: String) {
        partialFile(blobId, sha256).delete()
    }

    fun commitPartial(blobId: String, sha256: String, expectedSize: Long): File {
        require(expectedSize > 0L) { "Invalid P2P attachment size" }
        val partial = partialFile(blobId, sha256)
        require(partial.isFile && partial.length() == expectedSize) { "Incomplete P2P attachment" }
        val destination = attachmentFile(blobId)
        if (destination.exists() && !destination.delete()) {
            error("Unable to replace local attachment")
        }
        if (!partial.renameTo(destination)) {
            partial.inputStream().use { source ->
                FileOutputStream(destination, false).buffered().use { output -> source.copyTo(output) }
            }
            require(destination.length() == expectedSize) { "P2P attachment copy truncated" }
            if (!partial.delete()) {
                destination.delete()
                error("Unable to remove P2P partial")
            }
        }
        return destination
    }

    fun deleteAttachment(blobId: String) {
        requireBlobId(blobId)
        attachmentFile(blobId).delete()
        partialDir.listFiles()
            ?.filter { it.name.startsWith("$blobId-") }
            ?.forEach(File::delete)
    }

    fun clearEncryptedAttachments() {
        attachmentDir.deleteRecursively()
        attachmentDir.mkdirs()
        partialDir.mkdirs()
    }

    private fun attachmentFile(blobId: String): File = File(attachmentDir, "$blobId.eatt")

    private fun partialFile(blobId: String, sha256: String): File {
        requireBlobId(blobId)
        require(SHA256.matches(sha256)) { "Invalid attachment SHA-256" }
        return File(partialDir, "$blobId-$sha256.part")
    }

    private fun requireBlobId(blobId: String) {
        require(runCatching { UUID.fromString(blobId) }.isSuccess) { "Invalid attachment blob id" }
    }

    private companion object {
        val SHA256 = Regex("^[0-9a-f]{64}$")
    }
}
