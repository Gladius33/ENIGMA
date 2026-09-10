package com.enigma.securechat.data.db

import androidx.room.ColumnInfo
import androidx.room.Entity
import androidx.room.Index
import androidx.room.PrimaryKey

@Entity(tableName = "contacts", indices = [Index(value = ["public_id"], unique = true)])
data class ContactEntity(
    @PrimaryKey @ColumnInfo(name = "user_id") val userId: String,
    @ColumnInfo(name = "public_id") val publicId: String,
    @ColumnInfo(name = "display_name") val displayName: String,
)

@Entity(tableName = "contact_devices", indices = [Index(value = ["contact_user_id"])])
data class ContactDeviceEntity(
    @PrimaryKey @ColumnInfo(name = "device_id") val deviceId: String,
    @ColumnInfo(name = "contact_user_id") val contactUserId: String,
    @ColumnInfo(name = "identity_key") val identityKey: String? = null,
    @ColumnInfo(name = "registration_id") val registrationId: Int? = null,
    @ColumnInfo(name = "protocol_device_id") val protocolDeviceId: Int? = null,
    @ColumnInfo(name = "trust_state") val trustState: String = ContactDeviceTrustState.UNVERIFIED.name,
    @ColumnInfo(name = "identity_first_seen_at") val identityFirstSeenAt: Long? = null,
    @ColumnInfo(name = "identity_last_changed_at") val identityLastChangedAt: Long? = null,
    @ColumnInfo(name = "blocked_at") val blockedAt: Long? = null,
    @ColumnInfo(name = "verified_safety_number") val verifiedSafetyNumber: String? = null,
    @ColumnInfo(name = "verified_at") val verifiedAt: Long? = null,
)

enum class ContactDeviceTrustState {
    UNVERIFIED,
    VERIFIED,
    CHANGED,
    BLOCKED,
}

enum class RelayType {
    OFFICIAL,
    CUSTOM,
    COMMUNITY,
    PRIVATE,
    ORGANIZATION,
    LOCAL,
}

enum class RelayTrustState {
    UNVERIFIED,
    VERIFIED,
    BLOCKED,
}

@Entity(
    tableName = "relays",
    indices = [
        Index(value = ["type"]),
        Index(value = ["is_official"]),
    ],
)
data class RelayEntity(
    @PrimaryKey val id: String,
    val name: String,
    val url: String,
    @ColumnInfo(name = "public_key") val publicKey: String?,
    val type: String,
    @ColumnInfo(name = "trust_state") val trustState: String,
    @ColumnInfo(name = "is_official") val isOfficial: Boolean,
    @ColumnInfo(name = "created_at") val createdAt: Long,
    @ColumnInfo(name = "last_seen_at") val lastSeenAt: Long?,
)

enum class BubbleMode {
    MAIN_GLOBAL,
    PRIVATE_CONNECTED,
    PRIVATE_ISOLATED,
    COMMUNITY,
    ORGANIZATION,
}

enum class BubbleVisibility {
    PUBLIC,
    UNLISTED,
    PRIVATE,
    SECRET,
}

enum class BubbleIndexPolicy {
    INDEX_ALLOWED_BY_DEFAULT,
    INDEX_OPT_IN,
    INDEX_OPT_OUT,
    INDEX_FORBIDDEN,
    PRIVATE_ONLY,
}

enum class BubbleJoinPolicy {
    OPEN,
    REQUEST_APPROVAL,
    INVITE_ONLY,
    ADMIN_MANAGED,
    CLOSED,
}

@Entity(
    tableName = "bubbles",
    indices = [
        Index(value = ["slug"], unique = true),
        Index(value = ["mode"]),
    ],
)
data class BubbleEntity(
    @PrimaryKey val id: String,
    val slug: String,
    val name: String,
    val description: String?,
    val mode: String,
    val visibility: String,
    @ColumnInfo(name = "join_policy") val joinPolicy: String,
    @ColumnInfo(name = "index_policy") val indexPolicy: String,
    @ColumnInfo(name = "owner_identity_id") val ownerIdentityId: String?,
    @ColumnInfo(name = "public_key") val publicKey: String?,
    @ColumnInfo(name = "created_at") val createdAt: Long,
    @ColumnInfo(name = "updated_at") val updatedAt: Long,
    @ColumnInfo(name = "deleted_at") val deletedAt: Long?,
)

@Entity(tableName = "bubble_members", primaryKeys = ["bubble_id", "identity_id"])
data class BubbleMemberEntity(
    @ColumnInfo(name = "bubble_id") val bubbleId: String,
    @ColumnInfo(name = "identity_id") val identityId: String,
    val role: String,
    val status: String,
    @ColumnInfo(name = "joined_at") val joinedAt: Long,
)

@Entity(tableName = "bubble_relays", primaryKeys = ["bubble_id", "relay_id"])
data class BubbleRelayEntity(
    @ColumnInfo(name = "bubble_id") val bubbleId: String,
    @ColumnInfo(name = "relay_id") val relayId: String,
    val role: String,
    val priority: Int,
    val required: Boolean,
    @ColumnInfo(name = "fallback_allowed") val fallbackAllowed: Boolean,
)

@Entity(
    tableName = "bubble_services",
    indices = [
        Index(value = ["bubble_id", "slug"], unique = true),
    ],
)
data class BubbleServiceEntity(
    @PrimaryKey val id: String,
    @ColumnInfo(name = "bubble_id") val bubbleId: String,
    @ColumnInfo(name = "service_type") val serviceType: String,
    val name: String,
    val slug: String,
    val visibility: String,
    @ColumnInfo(name = "index_policy") val indexPolicy: String,
    @ColumnInfo(name = "created_at") val createdAt: Long,
)

@Entity(
    tableName = "contact_device_identity_events",
    indices = [
        Index(value = ["contact_user_id", "device_id", "created_at"]),
    ],
)
data class ContactDeviceIdentityEventEntity(
    @PrimaryKey val id: String,
    @ColumnInfo(name = "contact_user_id") val contactUserId: String,
    @ColumnInfo(name = "device_id") val deviceId: String,
    @ColumnInfo(name = "event_type") val eventType: String,
    @ColumnInfo(name = "old_identity_key_hash") val oldIdentityKeyHash: String?,
    @ColumnInfo(name = "new_identity_key_hash") val newIdentityKeyHash: String?,
    @ColumnInfo(name = "created_at") val createdAt: Long,
)

@Entity(
    tableName = "conversations",
    indices = [
        Index(value = ["bubble_id", "updated_at"]),
        Index(value = ["contact_user_id", "bubble_id"], unique = true),
    ],
)
data class ConversationEntity(
    @PrimaryKey val id: String,
    @ColumnInfo(name = "contact_user_id") val contactUserId: String,
    @ColumnInfo(name = "contact_public_id") val contactPublicId: String,
    @ColumnInfo(name = "bubble_id") val bubbleId: String,
    @ColumnInfo(name = "updated_at") val updatedAt: Long,
)

@Entity(
    tableName = "messages",
    indices = [
        Index(value = ["conversation_id", "created_at"]),
        Index(value = ["remote_message_id"], unique = true),
        Index(value = ["sender_device_id", "client_message_id"], unique = true),
    ],
)
data class MessageEntity(
    @PrimaryKey val id: String,
    @ColumnInfo(name = "remote_message_id") val remoteMessageId: String?,
    @ColumnInfo(name = "client_message_id") val clientMessageId: String,
    @ColumnInfo(name = "conversation_id") val conversationId: String,
    @ColumnInfo(name = "sender_device_id") val senderDeviceId: String?,
    @ColumnInfo(name = "recipient_device_id") val recipientDeviceId: String?,
    val direction: String,
    val status: String,
    @ColumnInfo(name = "encrypted_local_body") val encryptedLocalBody: String,
    @ColumnInfo(name = "transport_ciphertext") val transportCiphertext: String?,
    val transport: String,
    @ColumnInfo(name = "peer_identity_state") val peerIdentityState: String,
    @ColumnInfo(name = "created_at") val createdAt: Long,
)

@Entity(
    tableName = "groups",
    indices = [Index(value = ["bubble_id", "created_at"])],
)
data class GroupEntity(
    @PrimaryKey val id: String,
    @ColumnInfo(name = "bubble_id") val bubbleId: String,
    val title: String,
    @ColumnInfo(name = "owner_user_id") val ownerUserId: String,
    @ColumnInfo(name = "created_at") val createdAt: String,
)

@Entity(tableName = "group_members", primaryKeys = ["group_id", "user_id"])
data class GroupMemberEntity(
    @ColumnInfo(name = "group_id") val groupId: String,
    @ColumnInfo(name = "user_id") val userId: String,
    @ColumnInfo(name = "public_id") val publicId: String,
    val role: String,
)

@Entity(
    tableName = "group_messages",
    indices = [
        Index(value = ["group_id", "created_at"]),
        Index(value = ["bubble_id", "group_id", "created_at"]),
    ],
)
data class GroupMessageEntity(
    @PrimaryKey val id: String,
    @ColumnInfo(name = "bubble_id") val bubbleId: String,
    @ColumnInfo(name = "group_id") val groupId: String,
    @ColumnInfo(name = "sender_device_id") val senderDeviceId: String,
    @ColumnInfo(name = "message_type") val messageType: String,
    val ciphertext: String,
    @ColumnInfo(name = "encrypted_local_body") val encryptedLocalBody: String,
    @ColumnInfo(name = "created_at") val createdAt: String,
)

@Entity(
    tableName = "channels",
    indices = [Index(value = ["bubble_id", "created_at"])],
)
data class ChannelEntity(
    @PrimaryKey val id: String,
    @ColumnInfo(name = "bubble_id") val bubbleId: String,
    val title: String,
    val description: String?,
    @ColumnInfo(name = "owner_user_id") val ownerUserId: String,
    @ColumnInfo(name = "created_at") val createdAt: String,
)

@Entity(
    tableName = "channel_posts",
    indices = [
        Index(value = ["channel_id", "created_at"]),
        Index(value = ["bubble_id", "channel_id", "created_at"]),
    ],
)
data class ChannelPostEntity(
    @PrimaryKey val id: String,
    @ColumnInfo(name = "bubble_id") val bubbleId: String,
    @ColumnInfo(name = "channel_id") val channelId: String,
    @ColumnInfo(name = "sender_device_id") val senderDeviceId: String,
    @ColumnInfo(name = "post_type") val postType: String,
    val ciphertext: String,
    @ColumnInfo(name = "created_at") val createdAt: String,
)

@Entity(
    tableName = "call_events",
    indices = [
        Index(value = ["call_id", "created_at"]),
        Index(value = ["bubble_id", "created_at"]),
    ],
)
data class CallEventEntity(
    @PrimaryKey val id: String,
    @ColumnInfo(name = "bubble_id") val bubbleId: String,
    @ColumnInfo(name = "call_id") val callId: String,
    @ColumnInfo(name = "call_kind") val callKind: String,
    val state: String,
    @ColumnInfo(name = "event_kind") val eventKind: String,
    @ColumnInfo(name = "created_at") val createdAt: String,
)

@Entity(tableName = "attachments")
data class AttachmentEntity(
    @PrimaryKey @ColumnInfo(name = "blob_id") val blobId: String,
    @ColumnInfo(name = "bubble_id") val bubbleId: String,
    @ColumnInfo(name = "content_type") val contentType: String,
    @ColumnInfo(name = "size_bytes") val sizeBytes: Long,
    val sha256: String,
    val key: String,
    val nonce: String,
    @ColumnInfo(name = "download_secret") val downloadSecret: String,
)
