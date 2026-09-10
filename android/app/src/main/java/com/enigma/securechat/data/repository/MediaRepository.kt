package com.enigma.securechat.data.repository

import com.enigma.securechat.data.db.AttachmentDao
import com.enigma.securechat.data.db.AttachmentEntity
import com.enigma.securechat.domain.model.AppResult
import com.enigma.securechat.domain.model.AttachmentDescriptor
import java.io.InputStream
import java.io.OutputStream

class MediaRepository(
    private val attachmentRepository: AttachmentRepository,
    private val attachmentDao: AttachmentDao,
) {
    suspend fun uploadEncrypted(source: InputStream, contentType: String): AppResult<AttachmentDescriptor> {
        val result = attachmentRepository.uploadEncrypted(source, contentType)
        persistDescriptor(result)
        return result
    }

    suspend fun prepareDirectEncrypted(
        source: InputStream,
        contentType: String,
    ): AppResult<AttachmentDescriptor> {
        val result = attachmentRepository.prepareDirectEncrypted(source, contentType)
        persistDescriptor(result)
        return result
    }

    suspend fun downloadAndDecryptTo(
        descriptor: AttachmentDescriptor,
        destination: OutputStream,
    ): AppResult<Unit> = attachmentRepository.downloadAndDecryptTo(descriptor, destination)

    private suspend fun persistDescriptor(result: AppResult<AttachmentDescriptor>) {
        if (result is AppResult.Ok) {
            val descriptor = result.value
            attachmentDao.upsert(
                AttachmentEntity(
                    blobId = descriptor.blobId,
                    bubbleId = descriptor.bubbleId,
                    contentType = descriptor.contentType,
                    sizeBytes = descriptor.sizeBytes,
                    sha256 = descriptor.sha256,
                    key = descriptor.key,
                    nonce = descriptor.nonce,
                    downloadSecret = descriptor.downloadSecret,
                ),
            )
        }
    }
}
