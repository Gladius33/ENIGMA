package com.enigma.securechat.network

import com.enigma.securechat.network.dto.CreateChannelRequestDto
import com.enigma.securechat.network.dto.CreateCallRequestDto
import com.enigma.securechat.network.dto.CreateGroupRequestDto
import com.enigma.securechat.network.dto.CreateChannelPostRequestDto
import com.enigma.securechat.network.dto.ChannelSubscribersResponseDto
import com.enigma.securechat.network.dto.DeviceRegisterRequestDto
import com.enigma.securechat.network.dto.IceCandidatesRequestDto
import com.enigma.securechat.network.dto.PresignDownloadRequestDto
import com.enigma.securechat.network.dto.PresignUploadRequestDto
import com.enigma.securechat.network.dto.PendingChannelPostDto
import com.enigma.securechat.network.dto.PendingGroupMessageDto
import com.enigma.securechat.network.dto.PendingMessageDto
import com.enigma.securechat.network.dto.SendGroupMessageRequestDto
import com.enigma.securechat.network.dto.SendMessageRequestDto
import com.enigma.securechat.network.dto.SdpRequestDto
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class MessageDtosTest {
    private val moshi = NetworkModule.moshi()

    @Test
    fun sendMessageSerializesBubbleId() {
        val json = moshi.adapter(SendMessageRequestDto::class.java).toJson(
            SendMessageRequestDto(
                bubbleId = "00000000-0000-0000-0000-000000000010",
                senderDeviceId = "00000000-0000-0000-0000-000000000001",
                recipientDeviceId = "00000000-0000-0000-0000-000000000002",
                clientMessageId = "00000000-0000-0000-0000-000000000003",
                messageType = "text",
                ciphertext = "opaque",
            ),
        )

        assertTrue(json.contains("\"bubble_id\":\"00000000-0000-0000-0000-000000000010\""))
    }

    @Test
    fun deviceRegisterSerializesOptionalDeviceId() {
        val json = moshi.adapter(DeviceRegisterRequestDto::class.java).toJson(
            DeviceRegisterRequestDto(
                displayName = "Pixel",
                deviceId = "00000000-0000-0000-0000-0000000000aa",
            ),
        )

        assertTrue(json.contains("\"device_id\":\"00000000-0000-0000-0000-0000000000aa\""))
    }

    @Test
    fun pendingMessageParsesBubbleId() {
        val pending = moshi.adapter(PendingMessageDto::class.java).fromJson(
            """
            {
              "id":"00000000-0000-0000-0000-000000000004",
              "bubble_id":"00000000-0000-0000-0000-000000000010",
              "sender_device_id":"00000000-0000-0000-0000-000000000001",
              "sender_user_id":"00000000-0000-0000-0000-000000000011",
              "sender_public_id":"alice",
              "recipient_device_id":"00000000-0000-0000-0000-000000000002",
              "client_message_id":"00000000-0000-0000-0000-000000000003",
              "message_type":"text",
              "ciphertext":"opaque",
              "created_at":"2026-07-01T10:00:00Z",
              "expires_at":"2026-07-08T10:00:00Z"
            }
            """.trimIndent(),
        )

        assertEquals("00000000-0000-0000-0000-000000000010", pending?.bubbleId)
    }

    @Test
    fun createGroupSerializesBubbleId() {
        val json = moshi.adapter(CreateGroupRequestDto::class.java).toJson(
            CreateGroupRequestDto(
                bubbleId = "00000000-0000-0000-0000-000000000010",
                title = "Projet",
            ),
        )

        assertTrue(json.contains("\"bubble_id\":\"00000000-0000-0000-0000-000000000010\""))
    }

    @Test
    fun pendingGroupMessageParsesBubbleId() {
        val pending = moshi.adapter(PendingGroupMessageDto::class.java).fromJson(
            """
            {
              "id":"00000000-0000-0000-0000-000000000004",
              "bubble_id":"00000000-0000-0000-0000-000000000010",
              "group_id":"00000000-0000-0000-0000-000000000012",
              "sender_device_id":"00000000-0000-0000-0000-000000000001",
              "client_message_id":"00000000-0000-0000-0000-000000000003",
              "message_type":"opaque",
              "ciphertext":"opaque",
              "created_at":"2026-07-01T10:00:00Z",
              "expires_at":"2026-07-08T10:00:00Z"
            }
            """.trimIndent(),
        )

        assertEquals("00000000-0000-0000-0000-000000000010", pending?.bubbleId)
    }

    @Test
    fun sendGroupMessageSerializesBubbleId() {
        val json = moshi.adapter(SendGroupMessageRequestDto::class.java).toJson(
            SendGroupMessageRequestDto(
                bubbleId = "00000000-0000-0000-0000-000000000010",
                senderDeviceId = "00000000-0000-0000-0000-000000000001",
                clientMessageId = "00000000-0000-0000-0000-000000000003",
                messageType = "opaque",
                ciphertext = "b3BhcXVl",
            ),
        )

        assertTrue(json.contains("\"bubble_id\":\"00000000-0000-0000-0000-000000000010\""))
    }

    @Test
    fun createChannelSerializesBubbleId() {
        val json = moshi.adapter(CreateChannelRequestDto::class.java).toJson(
            CreateChannelRequestDto(
                bubbleId = "00000000-0000-0000-0000-000000000010",
                title = "Annonces",
            ),
        )

        assertTrue(json.contains("\"bubble_id\":\"00000000-0000-0000-0000-000000000010\""))
    }

    @Test
    fun channelSubscribersParseAudience() {
        val response = moshi.adapter(ChannelSubscribersResponseDto::class.java).fromJson(
            """
            {
              "subscribers":[{
                "user_id":"00000000-0000-0000-0000-000000000020",
                "public_id":"alice",
                "role":"owner"
              }]
            }
            """.trimIndent(),
        )

        assertEquals("alice", response?.subscribers?.single()?.publicId)
    }

    @Test
    fun createChannelPostSerializesBubbleId() {
        val json = moshi.adapter(CreateChannelPostRequestDto::class.java).toJson(
            CreateChannelPostRequestDto(
                bubbleId = "00000000-0000-0000-0000-000000000010",
                senderDeviceId = "00000000-0000-0000-0000-000000000001",
                clientPostId = "00000000-0000-0000-0000-000000000003",
                postType = "opaque",
                ciphertext = "b3BhcXVl",
            ),
        )

        assertTrue(json.contains("\"bubble_id\":\"00000000-0000-0000-0000-000000000010\""))
    }

    @Test
    fun pendingChannelPostParsesBubbleId() {
        val pending = moshi.adapter(PendingChannelPostDto::class.java).fromJson(
            """
            {
              "id":"00000000-0000-0000-0000-000000000004",
              "bubble_id":"00000000-0000-0000-0000-000000000010",
              "channel_id":"00000000-0000-0000-0000-000000000013",
              "sender_device_id":"00000000-0000-0000-0000-000000000001",
              "client_post_id":"00000000-0000-0000-0000-000000000003",
              "post_type":"opaque",
              "ciphertext":"opaque",
              "created_at":"2026-07-01T10:00:00Z",
              "expires_at":"2026-07-08T10:00:00Z"
            }
            """.trimIndent(),
        )

        assertEquals("00000000-0000-0000-0000-000000000010", pending?.bubbleId)
    }

    @Test
    fun callSignalingSerializesBubbleId() {
        val createJson = moshi.adapter(CreateCallRequestDto::class.java).toJson(
            CreateCallRequestDto(
                bubbleId = "00000000-0000-0000-0000-000000000010",
                calleeUserId = "00000000-0000-0000-0000-000000000020",
                callKind = "audio",
            ),
        )
        val sdpJson = moshi.adapter(SdpRequestDto::class.java).toJson(
            SdpRequestDto(
                bubbleId = "00000000-0000-0000-0000-000000000010",
                sdp = "opaque-sdp",
            ),
        )
        val iceJson = moshi.adapter(IceCandidatesRequestDto::class.java).toJson(
            IceCandidatesRequestDto(
                bubbleId = "00000000-0000-0000-0000-000000000010",
                candidates = listOf("opaque-ice"),
            ),
        )

        listOf(createJson, sdpJson, iceJson).forEach {
            assertTrue(it.contains("\"bubble_id\":\"00000000-0000-0000-0000-000000000010\""))
        }
    }

    @Test
    fun attachmentPresignRequestsSerializeBubbleId() {
        val uploadJson = moshi.adapter(PresignUploadRequestDto::class.java).toJson(
            PresignUploadRequestDto(
                bubbleId = "00000000-0000-0000-0000-000000000010",
                sizeBytes = 64,
                sha256 = "a".repeat(64),
                contentType = "application/octet-stream",
            ),
        )
        val downloadJson = moshi.adapter(PresignDownloadRequestDto::class.java).toJson(
            PresignDownloadRequestDto(
                blobId = "00000000-0000-0000-0000-000000000021",
                bubbleId = "00000000-0000-0000-0000-000000000010",
                downloadSecret = "secret",
            ),
        )

        listOf(uploadJson, downloadJson).forEach {
            assertTrue(it.contains("\"bubble_id\":\"00000000-0000-0000-0000-000000000010\""))
        }
    }
}
