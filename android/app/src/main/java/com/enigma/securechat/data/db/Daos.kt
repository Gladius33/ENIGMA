package com.enigma.securechat.data.db

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.Transaction
import java.security.MessageDigest
import java.util.UUID
import kotlinx.coroutines.flow.Flow

enum class RemoteIdentityUpdate {
    NEW_DEVICE,
    UNCHANGED,
    IDENTITY_CHANGED,
}

@Dao
interface ContactDao {
    @Query("SELECT * FROM contacts ORDER BY display_name ASC")
    fun observeContacts(): Flow<List<ContactEntity>>

    @Query(
        "SELECT contacts.* FROM contacts " +
            "JOIN conversations ON conversations.contact_user_id = contacts.user_id " +
            "WHERE conversations.bubble_id = :bubbleId " +
            "ORDER BY contacts.display_name ASC",
    )
    fun observeContactsForBubble(bubbleId: String): Flow<List<ContactEntity>>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsert(contact: ContactEntity)

    @Query("SELECT * FROM contacts WHERE user_id = :userId LIMIT 1")
    suspend fun findByUserId(userId: String): ContactEntity?
}

@Dao
interface ContactDeviceDao {
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsert(device: ContactDeviceEntity)

    @Query("SELECT * FROM contact_devices WHERE device_id = :deviceId LIMIT 1")
    suspend fun findByDevice(deviceId: String): ContactDeviceEntity?

    @Query("SELECT * FROM contact_devices WHERE contact_user_id = :contactUserId ORDER BY device_id ASC")
    suspend fun findByContact(contactUserId: String): List<ContactDeviceEntity>

    @Query(
        "UPDATE contact_devices " +
            "SET verified_safety_number = :safetyNumber, verified_at = :verifiedAt, trust_state = 'VERIFIED', blocked_at = NULL " +
            "WHERE device_id = :deviceId",
    )
    suspend fun markVerified(deviceId: String, safetyNumber: String, verifiedAt: Long)

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertIdentityEvent(event: ContactDeviceIdentityEventEntity)

    @Query("SELECT * FROM contact_device_identity_events WHERE device_id = :deviceId ORDER BY created_at DESC")
    suspend fun identityEvents(deviceId: String): List<ContactDeviceIdentityEventEntity>

    @Transaction
    suspend fun upsertRemoteIdentity(
        deviceId: String,
        contactUserId: String,
        identityKey: String,
        registrationId: Int? = null,
        protocolDeviceId: Int? = null,
    ): RemoteIdentityUpdate {
        val existing = findByDevice(deviceId)
        val sameIdentity = existing?.identityKey == identityKey
        val now = System.currentTimeMillis()
        val update = when {
            existing == null -> RemoteIdentityUpdate.NEW_DEVICE
            sameIdentity -> RemoteIdentityUpdate.UNCHANGED
            else -> RemoteIdentityUpdate.IDENTITY_CHANGED
        }
        if (update == RemoteIdentityUpdate.IDENTITY_CHANGED) {
            insertIdentityEvent(
                ContactDeviceIdentityEventEntity(
                    id = UUID.randomUUID().toString(),
                    contactUserId = contactUserId,
                    deviceId = deviceId,
                    eventType = "IDENTITY_CHANGED",
                    oldIdentityKeyHash = existing?.identityKey?.sha256Hex(),
                    newIdentityKeyHash = identityKey.sha256Hex(),
                    createdAt = now,
                ),
            )
        }
        val nextTrustState = if (existing?.trustState == ContactDeviceTrustState.BLOCKED.name) {
            ContactDeviceTrustState.BLOCKED.name
        } else {
            when (update) {
                RemoteIdentityUpdate.NEW_DEVICE -> ContactDeviceTrustState.UNVERIFIED.name
                RemoteIdentityUpdate.UNCHANGED -> existing?.trustState
                    ?: ContactDeviceTrustState.UNVERIFIED.name
                RemoteIdentityUpdate.IDENTITY_CHANGED -> ContactDeviceTrustState.CHANGED.name
            }
        }
        upsert(
            ContactDeviceEntity(
                deviceId = deviceId,
                contactUserId = contactUserId,
                identityKey = identityKey,
                registrationId = registrationId ?: existing?.registrationId,
                protocolDeviceId = protocolDeviceId ?: existing?.protocolDeviceId,
                trustState = nextTrustState,
                identityFirstSeenAt = existing?.identityFirstSeenAt ?: now,
                identityLastChangedAt = existing?.identityLastChangedAt
                    ?.takeIf { sameIdentity }
                    ?: if (update == RemoteIdentityUpdate.IDENTITY_CHANGED) now else existing?.identityLastChangedAt,
                blockedAt = existing?.blockedAt?.takeIf {
                    nextTrustState == ContactDeviceTrustState.BLOCKED.name
                },
                verifiedSafetyNumber = existing?.verifiedSafetyNumber?.takeIf { sameIdentity },
                verifiedAt = existing?.verifiedAt?.takeIf { sameIdentity },
            ),
        )
        return update
    }
}

private fun String.sha256Hex(): String =
    MessageDigest.getInstance("SHA-256")
        .digest(toByteArray(Charsets.UTF_8))
        .joinToString("") { "%02x".format(it) }

@Dao
interface RelayDao {
    @Query("SELECT * FROM relays ORDER BY is_official DESC, name ASC")
    fun observeRelays(): Flow<List<RelayEntity>>

    @Query("SELECT * FROM relays WHERE is_official = 1 LIMIT 1")
    suspend fun officialRelay(): RelayEntity?

    @Query("SELECT * FROM relays WHERE is_official = 0 ORDER BY created_at DESC")
    fun observeCustomRelays(): Flow<List<RelayEntity>>

    @Query("SELECT * FROM relays WHERE id = :relayId LIMIT 1")
    suspend fun findRelay(relayId: String): RelayEntity?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsert(relay: RelayEntity)
}

@Dao
interface BubbleDao {
    @Query("SELECT * FROM bubbles WHERE deleted_at IS NULL ORDER BY updated_at DESC")
    fun observeBubbles(): Flow<List<BubbleEntity>>

    @Query("SELECT * FROM bubbles WHERE id = :bubbleId AND deleted_at IS NULL LIMIT 1")
    suspend fun findBubble(bubbleId: String): BubbleEntity?

    @Query("SELECT * FROM bubbles WHERE slug = :slug AND deleted_at IS NULL LIMIT 1")
    suspend fun findBySlug(slug: String): BubbleEntity?

    @Query(
        "SELECT bubbles.* FROM bubbles " +
            "JOIN bubble_relays ON bubble_relays.bubble_id = bubbles.id " +
            "WHERE bubbles.mode = 'MAIN_GLOBAL' " +
            "AND bubbles.owner_identity_id IS NOT NULL " +
            "AND bubbles.deleted_at IS NULL " +
            "AND bubble_relays.relay_id = :officialRelayId " +
            "ORDER BY bubbles.updated_at DESC LIMIT 1",
    )
    suspend fun findServerMainBubble(officialRelayId: String): BubbleEntity?

    @Query(
        "UPDATE conversations SET bubble_id = :serverBubbleId " +
            "WHERE bubble_id = :localBubbleId " +
            "AND NOT EXISTS (" +
            "SELECT 1 FROM conversations existing " +
            "WHERE existing.contact_user_id = conversations.contact_user_id " +
            "AND existing.bubble_id = :serverBubbleId" +
            ")",
    )
    suspend fun promoteConversationBubbleAlias(localBubbleId: String, serverBubbleId: String)

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertBubble(bubble: BubbleEntity)

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertMember(member: BubbleMemberEntity)

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertRelay(relay: BubbleRelayEntity)

    @Query("DELETE FROM bubble_relays WHERE bubble_id = :bubbleId AND role = 'primary'")
    suspend fun clearPrimaryRelays(bubbleId: String)

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertService(service: BubbleServiceEntity)

    @Query("SELECT * FROM bubble_members WHERE bubble_id = :bubbleId ORDER BY joined_at ASC")
    fun observeMembers(bubbleId: String): Flow<List<BubbleMemberEntity>>

    @Query("SELECT * FROM bubble_relays WHERE bubble_id = :bubbleId ORDER BY priority ASC")
    fun observeBubbleRelays(bubbleId: String): Flow<List<BubbleRelayEntity>>

    @Query("SELECT * FROM bubble_services WHERE bubble_id = :bubbleId ORDER BY created_at ASC")
    fun observeServices(bubbleId: String): Flow<List<BubbleServiceEntity>>

    @Query("SELECT * FROM bubble_relays WHERE bubble_id = :bubbleId ORDER BY priority ASC")
    suspend fun bubbleRelays(bubbleId: String): List<BubbleRelayEntity>
}

@Dao
interface ConversationDao {
    @Query("SELECT * FROM conversations ORDER BY updated_at DESC")
    fun observeConversations(): Flow<List<ConversationEntity>>

    @Query("SELECT * FROM conversations WHERE bubble_id = :bubbleId ORDER BY updated_at DESC")
    fun observeConversations(bubbleId: String): Flow<List<ConversationEntity>>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsert(conversation: ConversationEntity)

    @Query("SELECT * FROM conversations WHERE id = :conversationId LIMIT 1")
    suspend fun findById(conversationId: String): ConversationEntity?

    @Query("SELECT * FROM conversations WHERE contact_user_id = :contactUserId AND bubble_id = :bubbleId LIMIT 1")
    suspend fun findByContact(contactUserId: String, bubbleId: String): ConversationEntity?
}

@Dao
interface MessageDao {
    @Query(
        "SELECT * FROM messages WHERE conversation_id = :conversationId " +
            "AND status != 'RECEIVING' ORDER BY created_at ASC",
    )
    fun observeMessages(conversationId: String): Flow<List<MessageEntity>>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsert(message: MessageEntity)

    @Query(
        "SELECT * FROM messages " +
            "WHERE sender_device_id = :senderDeviceId AND client_message_id = :clientMessageId " +
            "LIMIT 1",
    )
    suspend fun findByClientMessageId(senderDeviceId: String, clientMessageId: String): MessageEntity?

    @Query("UPDATE messages SET status = :status WHERE id = :localId")
    suspend fun updateStatus(localId: String, status: String)

    @Query(
        "UPDATE messages SET status = :status, transport = :transport, peer_identity_state = :peerIdentityState " +
            "WHERE id = :localId",
    )
    suspend fun markTransport(
        localId: String,
        status: String,
        transport: String,
        peerIdentityState: String,
    )

    @Query(
        "UPDATE messages SET status = :status, remote_message_id = :remoteMessageId, " +
            "transport = 'RELAY', peer_identity_state = :peerIdentityState WHERE id = :localId",
    )
    suspend fun markRelaySent(
        localId: String,
        remoteMessageId: String,
        status: String,
        peerIdentityState: String,
    )

    @Query("UPDATE messages SET status = :status, remote_message_id = :remoteMessageId WHERE id = :localId")
    suspend fun markSent(localId: String, remoteMessageId: String, status: String)

    @Query(
        "UPDATE messages SET status = :status " +
            "WHERE direction = 'OUTBOUND' " +
            "AND (client_message_id = :clientMessageId OR remote_message_id = :remoteMessageId) " +
            "AND status != 'READ'",
    )
    suspend fun markOutboundReceipt(clientMessageId: String, remoteMessageId: String, status: String)

    @Query(
        "UPDATE messages SET status = :status " +
            "WHERE direction = 'OUTBOUND' " +
            "AND client_message_id = :clientMessageId " +
            "AND recipient_device_id = :receiptSenderDeviceId " +
            "AND status != 'READ'",
    )
    suspend fun markOutboundP2pReceipt(
        clientMessageId: String,
        receiptSenderDeviceId: String,
        status: String,
    )

    @Query("SELECT * FROM messages WHERE status = 'QUEUED' OR status = 'FAILED' ORDER BY created_at ASC")
    suspend fun retryableMessages(): List<MessageEntity>

    @Query(
        "SELECT * FROM messages " +
            "WHERE conversation_id = :conversationId " +
            "AND direction = 'INBOUND' " +
            "AND status != 'READ' AND status != 'RECEIVING' " +
            "ORDER BY created_at ASC",
    )
    suspend fun unreadInboundMessages(conversationId: String): List<MessageEntity>
}

@Dao
interface GroupDao {
    @Query("SELECT * FROM groups WHERE bubble_id = :bubbleId ORDER BY created_at DESC")
    fun observeGroups(bubbleId: String): Flow<List<GroupEntity>>

    @Query("SELECT * FROM groups WHERE id = :groupId")
    suspend fun findById(groupId: String): GroupEntity?

    @Query("SELECT * FROM group_members WHERE group_id = :groupId ORDER BY role DESC, public_id ASC")
    fun observeMembers(groupId: String): Flow<List<GroupMemberEntity>>

    @Query("SELECT * FROM group_members WHERE group_id = :groupId ORDER BY role DESC, public_id ASC")
    suspend fun membersForGroup(groupId: String): List<GroupMemberEntity>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsert(group: GroupEntity)

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertMembers(members: List<GroupMemberEntity>)
}

@Dao
interface GroupMessageDao {
    @Query("SELECT * FROM group_messages WHERE group_id = :groupId ORDER BY created_at ASC")
    fun observeMessages(groupId: String): Flow<List<GroupMessageEntity>>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsert(message: GroupMessageEntity)
}

@Dao
interface ChannelDao {
    @Query("SELECT * FROM channels WHERE bubble_id = :bubbleId ORDER BY created_at DESC")
    fun observeChannels(bubbleId: String): Flow<List<ChannelEntity>>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsert(channel: ChannelEntity)
}

@Dao
interface ChannelPostDao {
    @Query("SELECT * FROM channel_posts WHERE channel_id = :channelId ORDER BY created_at ASC")
    fun observePosts(channelId: String): Flow<List<ChannelPostEntity>>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsert(post: ChannelPostEntity)
}

@Dao
interface CallEventDao {
    @Query("SELECT * FROM call_events WHERE bubble_id = :bubbleId ORDER BY created_at DESC")
    fun observeCallEvents(bubbleId: String): Flow<List<CallEventEntity>>

    @Query("SELECT * FROM call_events WHERE call_id = :callId ORDER BY created_at DESC LIMIT 1")
    suspend fun latestForCall(callId: String): CallEventEntity?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsert(event: CallEventEntity)
}

@Dao
interface AttachmentDao {
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsert(attachment: AttachmentEntity)
}
