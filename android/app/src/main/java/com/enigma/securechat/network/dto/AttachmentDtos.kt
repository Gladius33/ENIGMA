package com.enigma.securechat.network.dto

import com.squareup.moshi.Json

data class PresignUploadRequestDto(
    @Json(name = "bubble_id") val bubbleId: String,
    @Json(name = "size_bytes") val sizeBytes: Long,
    val sha256: String,
    @Json(name = "content_type") val contentType: String,
)

data class PresignUploadResponseDto(
    @Json(name = "blob_id") val blobId: String,
    @Json(name = "bubble_id") val bubbleId: String,
    @Json(name = "download_secret") val downloadSecret: String,
    val url: String,
    val method: String,
    val headers: Map<String, String>,
    @Json(name = "expires_at") val expiresAt: String,
)

data class RepresignUploadRequestDto(
    @Json(name = "bubble_id") val bubbleId: String,
    @Json(name = "download_secret") val downloadSecret: String,
)

data class RepresignUploadResponseDto(
    @Json(name = "blob_id") val blobId: String,
    @Json(name = "bubble_id") val bubbleId: String,
    val status: String,
    val url: String?,
    val method: String?,
    val headers: Map<String, String> = emptyMap(),
    @Json(name = "expires_at") val expiresAt: String?,
)

data class PresignDownloadRequestDto(
    @Json(name = "blob_id") val blobId: String,
    @Json(name = "bubble_id") val bubbleId: String,
    @Json(name = "download_secret") val downloadSecret: String,
)

data class PresignDownloadResponseDto(
    @Json(name = "blob_id") val blobId: String,
    @Json(name = "bubble_id") val bubbleId: String,
    val url: String,
    val method: String,
    @Json(name = "expires_at") val expiresAt: String,
)

data class CompleteUploadRequestDto(
    @Json(name = "download_secret") val downloadSecret: String,
    @Json(name = "size_bytes") val sizeBytes: Long,
    val sha256: String,
)

data class CompleteUploadResponseDto(
    @Json(name = "blob_id") val blobId: String,
    @Json(name = "bubble_id") val bubbleId: String,
    val status: String,
    @Json(name = "size_bytes") val sizeBytes: Long,
    val sha256: String,
    @Json(name = "verified_at") val verifiedAt: String,
)

data class P2pAttachmentGrantRequestDto(
    @Json(name = "bubble_id") val bubbleId: String,
    @Json(name = "sender_device_id") val senderDeviceId: String,
    @Json(name = "recipient_device_id") val recipientDeviceId: String,
    @Json(name = "client_message_id") val clientMessageId: String,
    @Json(name = "attachment_blob_ids") val attachmentBlobIds: List<String>,
)

data class P2pAttachmentGrantResponseDto(
    val status: String,
    @Json(name = "attachment_count") val attachmentCount: Int,
)

data class P2pAttachmentCommitRequestDto(
    @Json(name = "bubble_id") val bubbleId: String,
    @Json(name = "sender_device_id") val senderDeviceId: String,
    @Json(name = "recipient_device_id") val recipientDeviceId: String,
    @Json(name = "client_message_id") val clientMessageId: String,
    @Json(name = "attachment_blob_ids") val attachmentBlobIds: List<String>,
)

data class P2pAttachmentCommitResponseDto(
    val status: String,
    @Json(name = "attachment_count") val attachmentCount: Int,
    @Json(name = "released_bytes") val releasedBytes: Long,
)
