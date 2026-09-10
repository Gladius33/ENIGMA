package com.enigma.securechat.data.repository

import com.enigma.securechat.crypto.CryptoEngine
import com.enigma.securechat.crypto.RemoteDeviceRef
import com.enigma.securechat.crypto.SafetyNumber
import com.enigma.securechat.data.db.ContactDao
import com.enigma.securechat.data.db.ContactDeviceDao
import com.enigma.securechat.data.db.ContactDeviceEntity
import com.enigma.securechat.data.db.ContactDeviceTrustState
import com.enigma.securechat.data.db.ConversationDao
import com.enigma.securechat.data.db.MessageDao
import com.enigma.securechat.data.db.RemoteIdentityUpdate
import com.enigma.securechat.data.mapper.toDomain
import com.enigma.securechat.data.mapper.toEntity
import com.enigma.securechat.data.mapper.toRemoteBundle
import com.enigma.securechat.domain.model.AppResult
import com.enigma.securechat.domain.model.ChatMessage
import com.enigma.securechat.domain.model.Contact
import com.enigma.securechat.domain.model.Conversation
import com.enigma.securechat.domain.model.MessageDirection
import com.enigma.securechat.domain.model.MessagePeerIdentityState
import com.enigma.securechat.domain.model.MessageStatus
import com.enigma.securechat.domain.model.MessageTransport
import com.enigma.securechat.network.RelayScopedApiProvider
import com.enigma.securechat.network.dto.DeviceKeyBundleDto
import com.enigma.securechat.network.dto.P2pAttachmentCommitRequestDto
import com.enigma.securechat.network.dto.P2pAttachmentGrantRequestDto
import com.enigma.securechat.network.dto.PendingMessageDto
import com.enigma.securechat.network.dto.ReceiptRequestDto
import com.enigma.securechat.network.dto.SendMessageRequestDto
import com.enigma.securechat.network.dto.WsEventDto
import com.enigma.securechat.network.toUserVisibleError
import com.enigma.securechat.p2p.P2pAttachmentCommitOutboxStore
import com.enigma.securechat.p2p.P2pAttachmentSpec
import com.enigma.securechat.p2p.P2pDelivery
import com.enigma.securechat.p2p.P2pIncomingMessage
import com.enigma.securechat.p2p.P2pIncomingMessageResult
import com.enigma.securechat.p2p.P2pIncomingReceipt
import com.enigma.securechat.p2p.P2pMessagingCoordinator
import com.enigma.securechat.p2p.P2pPeerIdentityState
import com.enigma.securechat.p2p.P2pReceiptOutboxStore
import com.enigma.securechat.p2p.P2pReceiptStatus
import com.enigma.securechat.p2p.P2pRoute
import com.enigma.securechat.p2p.PendingP2pAttachmentCommit
import com.enigma.securechat.p2p.PendingP2pReadReceipt
import com.enigma.securechat.storage.DeviceStore
import com.enigma.securechat.storage.LocalCipher
import com.enigma.securechat.storage.RelaySettingsStore
import java.time.Instant
import java.util.UUID
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map

data class SafetyNumberState(
    val code: String,
    val verified: Boolean,
    val verifiedAt: Instant?,
    val trustState: ContactDeviceTrustState,
    val identityLastChangedAt: Instant?,
)

class MessagesRepository(
    private val apiProvider: RelayScopedApiProvider,
    private val cryptoEngine: CryptoEngine,
    private val localCipher: LocalCipher,
    private val deviceStore: DeviceStore,
    private val contactDao: ContactDao,
    private val contactDeviceDao: ContactDeviceDao,
    private val conversationDao: ConversationDao,
    private val messageDao: MessageDao,
    private val p2pCoordinator: P2pMessagingCoordinator? = null,
    private val p2pReceiptOutboxStore: P2pReceiptOutboxStore? = null,
    private val attachmentRepository: AttachmentRepository? = null,
    private val p2pAttachmentCommitOutboxStore: P2pAttachmentCommitOutboxStore? = null,
    private val highSecurityModeProvider: suspend () -> Boolean = { false },
    private val activeBubbleIdProvider: suspend () -> String = {
        RelaySettingsStore.DEFAULT_MAIN_BUBBLE_ID
    },
) {
    fun observeMessages(conversationId: String): Flow<List<ChatMessage>> =
        messageDao.observeMessages(conversationId).map { rows -> rows.map { it.toDomain() } }

    suspend fun sendText(
        contact: Contact,
        plaintext: String,
        conversationId: String? = null,
    ): AppResult<Unit> = sendPayload(
        contact = contact,
        payload = MessagePayload(body = plaintext),
        conversationId = conversationId,
    )

    suspend fun sendPayload(
        contact: Contact,
        payload: MessagePayload,
        conversationId: String? = null,
    ): AppResult<Unit> = runCatching {
        require(payload.body.isNotBlank() || payload.attachments.isNotEmpty()) { "Empty message payload" }
        val senderDeviceId = requireNotNull(deviceStore.deviceId()) { "Device is not registered" }
        val activeBubbleId = activeBubbleIdProvider()
        val conversation = conversationId?.let { conversationDao.findById(it) }
            ?: conversationDao.findByContact(contact.userId, activeBubbleId)
            ?: error("Conversation missing")
        payload.attachments.forEach { attachment ->
            require(attachment.descriptor.bubbleId == conversation.bubbleId) {
                "Attachment bubble does not match conversation bubble"
            }
        }

        var recipientDevice = primaryRemoteDevice(contact)
        enforceSendPolicy(recipientDevice)

        var remoteRef = recipientDevice.toRemoteRef()
        if (remoteRef == null || !cryptoEngine.hasSession(remoteRef)) {
            val claimed = apiProvider.withActiveApi {
                it.claimPreKey(contact.userId, recipientDevice.deviceId)
            }.device
            storeRemoteBundle(contact.userId, claimed)
            recipientDevice = requireNotNull(contactDeviceDao.findByDevice(claimed.deviceId)) {
                "Claimed recipient device was not stored"
            }
            enforceSendPolicy(recipientDevice)
            cryptoEngine.ensureSession(claimed.toRemoteBundle())
            remoteRef = requireNotNull(recipientDevice.toRemoteRef()) {
                "Recipient device is missing libsignal protocol metadata"
            }
        }

        val finalRemoteRef = requireNotNull(remoteRef) {
            "Recipient device is missing libsignal protocol metadata"
        }
        val encodedPayload = MessagePayloadCodec.encode(payload.body, payload.attachments)
        val transportCiphertext = cryptoEngine.encryptText(encodedPayload, finalRemoteRef)
        val localCiphertext = localCipher.encryptToString(encodedPayload.toByteArray(Charsets.UTF_8))

        val localId = UUID.randomUUID().toString()
        val localPeerState = recipientDevice.toMessagePeerIdentityState()
        val queued = ChatMessage(
            id = localId,
            clientMessageId = localId,
            conversationId = conversation.id,
            senderDeviceId = senderDeviceId,
            recipientDeviceId = finalRemoteRef.deviceId,
            direction = MessageDirection.OUTBOUND,
            status = MessageStatus.QUEUED,
            encryptedLocalBody = localCiphertext,
            transportCiphertext = transportCiphertext,
            createdAt = Instant.now(),
            transport = MessageTransport.RELAY,
            peerIdentityState = localPeerState,
        )
        messageDao.upsert(queued.toEntity())
        messageDao.updateStatus(localId, MessageStatus.SENDING.name)

        val p2pDelivery = attemptP2pDelivery(
            bubbleId = conversation.bubbleId,
            senderDeviceId = senderDeviceId,
            recipientDeviceId = finalRemoteRef.deviceId,
            clientMessageId = localId,
            payload = payload,
            ciphertext = transportCiphertext,
        )
        if (p2pDelivery != null) {
            messageDao.markTransport(
                localId = localId,
                status = MessageStatus.DELIVERED.name,
                transport = p2pDelivery.route.toMessageTransport().name,
                peerIdentityState = p2pDelivery.peerIdentityState.toMessagePeerIdentityState().name,
            )
            if (payload.attachments.isNotEmpty()) {
                scheduleP2pAttachmentCommit(
                    bubbleId = conversation.bubbleId,
                    senderDeviceId = senderDeviceId,
                    recipientDeviceId = finalRemoteRef.deviceId,
                    clientMessageId = localId,
                    blobIds = payload.attachments.map { it.descriptor.blobId },
                )
            }
            return@runCatching
        }

        ensureAttachmentsRelayBacked(payload)
        val sent = try {
            apiProvider.withActiveApi {
                it.sendMessage(
                    SendMessageRequestDto(
                        bubbleId = conversation.bubbleId,
                        senderDeviceId = senderDeviceId,
                        recipientDeviceId = finalRemoteRef.deviceId,
                        clientMessageId = localId,
                        messageType = payload.messageType(),
                        ciphertext = transportCiphertext,
                        attachmentBlobIds = payload.attachments.map { it.descriptor.blobId },
                    ),
                )
            }
        } catch (error: Throwable) {
            messageDao.updateStatus(localId, MessageStatus.FAILED.name)
            throw error
        }
        messageDao.markRelaySent(
            localId = localId,
            remoteMessageId = sent.id,
            status = MessageStatus.SENT.name,
            peerIdentityState = localPeerState.name,
        )
    }.fold(
        onSuccess = { AppResult.Ok(Unit) },
        onFailure = { AppResult.Err(it.toUserVisibleError("Message non envoyé")) },
    )

    suspend fun handleP2pIncoming(message: P2pIncomingMessage): P2pIncomingMessageResult {
        val localDeviceId = deviceStore.deviceId() ?: return P2pIncomingMessageResult.Rejected
        if (message.recipientDeviceId != localDeviceId) return P2pIncomingMessageResult.Rejected

        val existing = messageDao.findByClientMessageId(message.senderDeviceId, message.clientMessageId)
        if (existing != null) {
            if (
                existing.recipientDeviceId != localDeviceId ||
                existing.direction != MessageDirection.INBOUND.name ||
                existing.transportCiphertext != message.ciphertext
            ) return P2pIncomingMessageResult.Rejected
            val conversation = conversationDao.findById(existing.conversationId)
                ?: return P2pIncomingMessageResult.Rejected
            if (conversation.bubbleId != message.bubbleId) return P2pIncomingMessageResult.Rejected
            val payload = decryptLocalPayload(existing.toDomain())
            if (payload.messageType() != message.messageType) return P2pIncomingMessageResult.Rejected
            return if (payload.attachments.isEmpty()) {
                if (existing.status == MessageStatus.RECEIVING.name) {
                    P2pIncomingMessageResult.Rejected
                } else {
                    P2pIncomingMessageResult.Delivered
                }
            } else {
                P2pIncomingMessageResult.AwaitingAttachments(payload.toP2pAttachmentSpecs())
            }
        }

        val contactDevice = contactDeviceDao.findByDevice(message.senderDeviceId)
            ?: return P2pIncomingMessageResult.Rejected
        val contact = contactDao.findByUserId(contactDevice.contactUserId)
            ?: return P2pIncomingMessageResult.Rejected
        val conversation = conversationDao.findByContact(contact.userId, message.bubbleId)
            ?: Conversation(
                id = UUID.randomUUID().toString(),
                contactUserId = contact.userId,
                contactPublicId = contact.publicId,
                bubbleId = message.bubbleId,
                updatedAt = Instant.now(),
            ).toEntity().also { conversationDao.upsert(it) }

        val encodedPayload = cryptoEngine.decryptText(message.ciphertext)
        val decoded = MessagePayloadCodec.decode(encodedPayload)
        if (decoded.body.isBlank() && decoded.attachments.isEmpty()) return P2pIncomingMessageResult.Rejected
        if (decoded.messageType() != message.messageType) return P2pIncomingMessageResult.Rejected
        if (decoded.attachments.any { it.descriptor.bubbleId != message.bubbleId }) {
            return P2pIncomingMessageResult.Rejected
        }
        val localCiphertext = localCipher.encryptToString(encodedPayload.toByteArray(Charsets.UTF_8))
        val awaitingAttachments = decoded.attachments.isNotEmpty()
        val local = ChatMessage(
            id = UUID.randomUUID().toString(),
            clientMessageId = message.clientMessageId,
            conversationId = conversation.id,
            senderDeviceId = message.senderDeviceId,
            recipientDeviceId = message.recipientDeviceId,
            direction = MessageDirection.INBOUND,
            status = if (awaitingAttachments) MessageStatus.RECEIVING else MessageStatus.DELIVERED,
            encryptedLocalBody = localCiphertext,
            transportCiphertext = message.ciphertext,
            createdAt = Instant.now(),
            transport = message.route.toMessageTransport(),
            peerIdentityState = message.peerIdentityState.toMessagePeerIdentityState(),
        )
        messageDao.upsert(local.toEntity())
        return if (awaitingAttachments) {
            P2pIncomingMessageResult.AwaitingAttachments(decoded.toP2pAttachmentSpecs())
        } else {
            P2pIncomingMessageResult.Delivered
        }
    }

    suspend fun completeP2pIncomingAttachments(message: P2pIncomingMessage): Boolean {
        val localDeviceId = deviceStore.deviceId() ?: return false
        if (message.recipientDeviceId != localDeviceId) return false
        val existing = messageDao.findByClientMessageId(message.senderDeviceId, message.clientMessageId)
            ?: return false
        if (
            existing.direction != MessageDirection.INBOUND.name ||
            existing.recipientDeviceId != localDeviceId ||
            existing.transportCiphertext != message.ciphertext
        ) return false
        val conversation = conversationDao.findById(existing.conversationId) ?: return false
        if (conversation.bubbleId != message.bubbleId) return false
        val payload = decryptLocalPayload(existing.toDomain())
        if (payload.attachments.isEmpty() || payload.messageType() != message.messageType) return false
        val repository = attachmentRepository ?: return false
        if (payload.attachments.any { !repository.hasVerifiedLocalCiphertext(it.descriptor) }) return false

        if (existing.status == MessageStatus.RECEIVING.name) {
            messageDao.markTransport(
                localId = existing.id,
                status = MessageStatus.DELIVERED.name,
                transport = message.route.toMessageTransport().name,
                peerIdentityState = message.peerIdentityState.toMessagePeerIdentityState().name,
            )
        }
        return true
    }

    suspend fun handleP2pReceipt(receipt: P2pIncomingReceipt): Boolean {
        val localDeviceId = deviceStore.deviceId() ?: return false
        if (receipt.recipientDeviceId != localDeviceId) return false
        val message = messageDao.findByClientMessageId(localDeviceId, receipt.clientMessageId) ?: return false
        if (message.direction != MessageDirection.OUTBOUND.name) return false
        if (message.recipientDeviceId != receipt.senderDeviceId) return false
        val conversation = conversationDao.findById(message.conversationId) ?: return false
        if (conversation.bubbleId != receipt.bubbleId) return false
        val status = receipt.status.toMessageStatus()
        messageDao.markOutboundP2pReceipt(
            clientMessageId = receipt.clientMessageId,
            receiptSenderDeviceId = receipt.senderDeviceId,
            status = status.name,
        )
        return true
    }

    suspend fun syncPending(): AppResult<Unit> = runCatching {
        val deviceId = requireNotNull(deviceStore.deviceId())
        val pending = apiProvider.withActiveApi { it.pendingMessages(deviceId) }
        for (message in pending.messages) {
            val existing = messageDao.findByClientMessageId(
                senderDeviceId = message.senderDeviceId,
                clientMessageId = message.clientMessageId,
            )
            if (existing != null) {
                require(existing.transportCiphertext == message.ciphertext) {
                    "Relay/P2P client message ciphertext mismatch"
                }
                val conversation = conversationDao.findById(existing.conversationId)
                    ?: error("Conversation missing for deduplicated message")
                require(conversation.bubbleId == message.bubbleId) { "Relay/P2P bubble mismatch" }
                require(existing.recipientDeviceId == deviceId) { "Relay/P2P recipient mismatch" }
                if (existing.status == MessageStatus.RECEIVING.name) {
                    val contactDevice = contactDeviceDao.findByDevice(message.senderDeviceId)
                    messageDao.upsert(
                        existing.copy(
                            remoteMessageId = message.id,
                            status = MessageStatus.DELIVERED.name,
                            transport = MessageTransport.RELAY.name,
                            peerIdentityState = contactDevice?.toMessagePeerIdentityState()?.name
                                ?: MessagePeerIdentityState.UNVERIFIED.name,
                        ),
                    )
                } else if (existing.remoteMessageId == null) {
                    messageDao.upsert(existing.copy(remoteMessageId = message.id))
                }
                apiProvider.withActiveApi { it.receipt(message.id, ReceiptRequestDto(deviceId)) }
                continue
            }

            val conversation = conversationForPending(message) ?: continue
            val contactDevice = contactDeviceDao.findByDevice(message.senderDeviceId)
            val encodedPayload = cryptoEngine.decryptText(message.ciphertext)
            MessagePayloadCodec.decode(encodedPayload)
            val localCiphertext = localCipher.encryptToString(encodedPayload.toByteArray(Charsets.UTF_8))
            val local = ChatMessage(
                id = UUID.randomUUID().toString(),
                clientMessageId = message.clientMessageId,
                conversationId = conversation.id,
                senderDeviceId = message.senderDeviceId,
                recipientDeviceId = message.recipientDeviceId,
                direction = MessageDirection.INBOUND,
                status = MessageStatus.DELIVERED,
                encryptedLocalBody = localCiphertext,
                transportCiphertext = message.ciphertext,
                createdAt = Instant.parse(message.createdAt),
                transport = MessageTransport.RELAY,
                peerIdentityState = contactDevice?.toMessagePeerIdentityState()
                    ?: MessagePeerIdentityState.UNVERIFIED,
            )
            messageDao.upsert(local.toEntity(remoteMessageId = message.id))
            apiProvider.withActiveApi { it.receipt(message.id, ReceiptRequestDto(deviceId)) }
        }
    }.fold(
        onSuccess = { AppResult.Ok(Unit) },
        onFailure = { AppResult.Err(it.toUserVisibleError("Synchronisation impossible")) },
    )

    suspend fun syncReceipts(): AppResult<Unit> = runCatching {
        val deviceId = requireNotNull(deviceStore.deviceId())
        flushPendingP2pAttachmentCommits()
        flushPendingP2pReadReceipts(deviceId)
        val receipts = apiProvider.withActiveApi { it.sentReceipts(deviceId) }
        for (receipt in receipts.receipts) {
            val status = receipt.status.toMessageStatusOrNull() ?: continue
            if (status == MessageStatus.DELIVERED || status == MessageStatus.READ) {
                messageDao.markOutboundReceipt(
                    clientMessageId = receipt.clientMessageId,
                    remoteMessageId = receipt.messageId,
                    status = status.name,
                )
            }
        }
    }.fold(
        onSuccess = { AppResult.Ok(Unit) },
        onFailure = { AppResult.Err(it.toUserVisibleError("Reçus non synchronisés")) },
    )

    suspend fun handleRealtimeEvent(event: WsEventDto): AppResult<Unit> = runCatching {
        val receiptStatus = event.status?.toMessageStatusOrNull()
        if (event.type == "receipt_updated" && event.messageId != null && receiptStatus != null) {
            messageDao.markOutboundReceipt(
                clientMessageId = event.clientMessageId ?: event.messageId,
                remoteMessageId = event.messageId,
                status = receiptStatus.name,
            )
        }
    }.fold(
        onSuccess = { AppResult.Ok(Unit) },
        onFailure = { AppResult.Err(it.toUserVisibleError("Événement non appliqué")) },
    )

    suspend fun retryPendingOutbound(): AppResult<Unit> = runCatching {
        flushPendingP2pAttachmentCommits()
        for (message in messageDao.retryableMessages()) {
            val senderDeviceId = message.senderDeviceId ?: continue
            val recipientDeviceId = message.recipientDeviceId ?: continue
            val ciphertext = message.transportCiphertext ?: continue
            val bubbleId = conversationDao.findById(message.conversationId)?.bubbleId ?: continue
            val payload = decryptLocalPayload(message.toDomain())
            messageDao.updateStatus(message.id, MessageStatus.SENDING.name)

            val p2pDelivery = attemptP2pDelivery(
                bubbleId = bubbleId,
                senderDeviceId = senderDeviceId,
                recipientDeviceId = recipientDeviceId,
                clientMessageId = message.clientMessageId,
                payload = payload,
                ciphertext = ciphertext,
            )
            if (p2pDelivery != null) {
                messageDao.markTransport(
                    localId = message.id,
                    status = MessageStatus.DELIVERED.name,
                    transport = p2pDelivery.route.toMessageTransport().name,
                    peerIdentityState = p2pDelivery.peerIdentityState.toMessagePeerIdentityState().name,
                )
                if (payload.attachments.isNotEmpty()) {
                    scheduleP2pAttachmentCommit(
                        bubbleId = bubbleId,
                        senderDeviceId = senderDeviceId,
                        recipientDeviceId = recipientDeviceId,
                        clientMessageId = message.clientMessageId,
                        blobIds = payload.attachments.map { it.descriptor.blobId },
                    )
                }
                continue
            }

            try {
                ensureAttachmentsRelayBacked(payload)
                val sent = apiProvider.withActiveApi {
                    it.sendMessage(
                        SendMessageRequestDto(
                            bubbleId = bubbleId,
                            senderDeviceId = senderDeviceId,
                            recipientDeviceId = recipientDeviceId,
                            clientMessageId = message.clientMessageId,
                            messageType = payload.messageType(),
                            ciphertext = ciphertext,
                            attachmentBlobIds = payload.attachments.map { it.descriptor.blobId },
                        ),
                    )
                }
                messageDao.markRelaySent(
                    localId = message.id,
                    remoteMessageId = sent.id,
                    status = MessageStatus.SENT.name,
                    peerIdentityState = message.peerIdentityState,
                )
            } catch (_: Throwable) {
                messageDao.updateStatus(message.id, MessageStatus.FAILED.name)
            }
        }
    }.fold(
        onSuccess = { AppResult.Ok(Unit) },
        onFailure = { AppResult.Err(it.toUserVisibleError("Retry impossible")) },
    )

    suspend fun markConversationRead(conversationId: String): AppResult<Unit> = runCatching {
        val deviceId = requireNotNull(deviceStore.deviceId())
        val conversation = requireNotNull(conversationDao.findById(conversationId)) { "Conversation missing" }
        for (message in messageDao.unreadInboundMessages(conversationId)) {
            val senderDeviceId = message.senderDeviceId ?: continue
            val outbox = p2pReceiptOutboxStore
            if (outbox == null) {
                val remoteMessageId = message.remoteMessageId
                    ?: error("P2P receipt outbox unavailable")
                apiProvider.withActiveApi {
                    it.receipt(remoteMessageId, ReceiptRequestDto(deviceId = deviceId, status = "read"))
                }
                messageDao.updateStatus(message.id, MessageStatus.READ.name)
                continue
            }

            val pending = outbox.enqueue(
                bubbleId = conversation.bubbleId,
                recipientDeviceId = senderDeviceId,
                clientMessageId = message.clientMessageId,
                remoteMessageId = message.remoteMessageId,
            )
            messageDao.updateStatus(message.id, MessageStatus.READ.name)
            deliverPendingReadReceipt(pending, deviceId)
        }
    }.fold(
        onSuccess = { AppResult.Ok(Unit) },
        onFailure = { AppResult.Err(it.toUserVisibleError("Messages non marqués comme lus")) },
    )

    fun decryptLocalPayload(message: ChatMessage): MessagePayload {
        val decrypted = localCipher.decryptFromString(message.encryptedLocalBody)
        return try {
            MessagePayloadCodec.decode(decrypted.toString(Charsets.UTF_8))
        } finally {
            decrypted.fill(0)
        }
    }

    fun decryptLocalBody(message: ChatMessage): String = decryptLocalPayload(message).body

    suspend fun safetyNumber(contact: Contact): AppResult<String> = runCatching {
        safetyNumberStateOrThrow(contact).code
    }.fold(
        onSuccess = { AppResult.Ok(it) },
        onFailure = { AppResult.Err(it.toUserVisibleError("Safety number indisponible")) },
    )

    suspend fun safetyNumberState(contact: Contact): AppResult<SafetyNumberState> = runCatching {
        safetyNumberStateOrThrow(contact)
    }.fold(
        onSuccess = { AppResult.Ok(it) },
        onFailure = { AppResult.Err(it.toUserVisibleError("Safety number indisponible")) },
    )

    suspend fun markSafetyNumberVerified(contact: Contact): AppResult<SafetyNumberState> = runCatching {
        val state = safetyNumberStateOrThrow(contact)
        val remoteDevice = primaryRemoteDevice(contact)
        val verifiedAt = Instant.now()
        contactDeviceDao.markVerified(
            deviceId = remoteDevice.deviceId,
            safetyNumber = state.code,
            verifiedAt = verifiedAt.toEpochMilli(),
        )
        state.copy(
            verified = true,
            verifiedAt = verifiedAt,
            trustState = ContactDeviceTrustState.VERIFIED,
        )
    }.fold(
        onSuccess = { AppResult.Ok(it) },
        onFailure = { AppResult.Err(it.toUserVisibleError("Safety number non vérifié")) },
    )

    private suspend fun attemptP2pDelivery(
        bubbleId: String,
        senderDeviceId: String,
        recipientDeviceId: String,
        clientMessageId: String,
        payload: MessagePayload,
        ciphertext: String,
    ): P2pDelivery? {
        val coordinator = p2pCoordinator ?: return null
        val specs = payload.toP2pAttachmentSpecs()
        if (specs.isNotEmpty()) {
            val repository = attachmentRepository ?: return null
            if (payload.attachments.any { !repository.hasVerifiedLocalCiphertext(it.descriptor) }) return null
            val granted = try {
                apiProvider.withActiveApi {
                    it.grantP2pAttachments(
                        P2pAttachmentGrantRequestDto(
                            bubbleId = bubbleId,
                            senderDeviceId = senderDeviceId,
                            recipientDeviceId = recipientDeviceId,
                            clientMessageId = clientMessageId,
                            attachmentBlobIds = specs.map(P2pAttachmentSpec::blobId),
                        ),
                    )
                }
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (_: Throwable) {
                null
            }
            if (granted?.status != "granted" || granted.attachmentCount != specs.size) return null
        }

        return try {
            coordinator.trySend(
                bubbleId = bubbleId,
                recipientDeviceId = recipientDeviceId,
                clientMessageId = clientMessageId,
                messageType = payload.messageType(),
                ciphertext = ciphertext,
                attachments = specs,
            )
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (_: Throwable) {
            null
        }
    }

    private suspend fun ensureAttachmentsRelayBacked(payload: MessagePayload) {
        if (payload.attachments.isEmpty()) return
        val repository = attachmentRepository ?: error("Attachment repository unavailable")
        for (attachment in payload.attachments) {
            when (val result = repository.uploadPreparedForRelay(attachment.descriptor)) {
                is AppResult.Ok -> Unit
                is AppResult.Err -> error(result.error.message)
            }
        }
    }

    private suspend fun scheduleP2pAttachmentCommit(
        bubbleId: String,
        senderDeviceId: String,
        recipientDeviceId: String,
        clientMessageId: String,
        blobIds: List<String>,
    ) {
        try {
            val outbox = p2pAttachmentCommitOutboxStore
            if (outbox == null) {
                runCatching {
                    apiProvider.withActiveApi {
                        it.commitP2pAttachments(
                            P2pAttachmentCommitRequestDto(
                                bubbleId = bubbleId,
                                senderDeviceId = senderDeviceId,
                                recipientDeviceId = recipientDeviceId,
                                clientMessageId = clientMessageId,
                                attachmentBlobIds = blobIds,
                            ),
                        )
                    }
                }
                return
            }
            val pending = outbox.enqueue(
                bubbleId = bubbleId,
                senderDeviceId = senderDeviceId,
                recipientDeviceId = recipientDeviceId,
                clientMessageId = clientMessageId,
                attachmentBlobIds = blobIds,
            )
            deliverPendingAttachmentCommit(pending)
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (_: Throwable) {
            // The P2P delivery is already durably recorded locally. Cleanup is
            // best-effort here; stale pending reservations are also server-purged.
        }
    }

    private suspend fun flushPendingP2pAttachmentCommits() {
        val outbox = p2pAttachmentCommitOutboxStore ?: return
        for (pending in outbox.pending()) deliverPendingAttachmentCommit(pending)
    }

    private suspend fun deliverPendingAttachmentCommit(pending: PendingP2pAttachmentCommit) {
        val outbox = p2pAttachmentCommitOutboxStore ?: return
        val committed = try {
            val response = apiProvider.withActiveApi {
                it.commitP2pAttachments(
                    P2pAttachmentCommitRequestDto(
                        bubbleId = pending.bubbleId,
                        senderDeviceId = pending.senderDeviceId,
                        recipientDeviceId = pending.recipientDeviceId,
                        clientMessageId = pending.clientMessageId,
                        attachmentBlobIds = pending.attachmentBlobIds,
                    ),
                )
            }
            response.status == "released" && response.attachmentCount == pending.attachmentBlobIds.size
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (_: Throwable) {
            false
        }
        if (committed) outbox.remove(pending.commitId)
    }

    private suspend fun flushPendingP2pReadReceipts(deviceId: String) {
        val outbox = p2pReceiptOutboxStore ?: return
        for (pending in outbox.pending()) {
            deliverPendingReadReceipt(pending, deviceId)
        }
    }

    private suspend fun deliverPendingReadReceipt(
        pending: PendingP2pReadReceipt,
        deviceId: String,
    ) {
        val outbox = p2pReceiptOutboxStore ?: return
        val p2pDelivered = try {
            p2pCoordinator?.trySendReceipt(
                receiptId = pending.receiptId,
                bubbleId = pending.bubbleId,
                recipientDeviceId = pending.recipientDeviceId,
                clientMessageId = pending.clientMessageId,
                status = P2pReceiptStatus.READ,
            ) != null
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (_: Throwable) {
            false
        }
        if (p2pDelivered) {
            outbox.remove(pending.receiptId)
            return
        }

        val remoteMessageId = pending.remoteMessageId
            ?: messageDao.findByClientMessageId(
                senderDeviceId = pending.recipientDeviceId,
                clientMessageId = pending.clientMessageId,
            )?.remoteMessageId
            ?: return
        val relayDelivered = try {
            apiProvider.withActiveApi {
                it.receipt(
                    remoteMessageId,
                    ReceiptRequestDto(deviceId = deviceId, status = "read"),
                )
            }
            true
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (_: Throwable) {
            false
        }
        if (relayDelivered) {
            outbox.remove(pending.receiptId)
        }
    }

    private suspend fun safetyNumberStateOrThrow(contact: Contact): SafetyNumberState {
        val localIdentity = cryptoEngine.ensureIdentity().identityPublicKey
        val remoteDevice = primaryRemoteDevice(contact)
        val remoteIdentity = requireNotNull(remoteDevice.identityKey) { "Remote identity missing" }
        val code = SafetyNumber.pairFingerprint(localIdentity, remoteIdentity)
        return SafetyNumberState(
            code = code,
            verified = remoteDevice.verifiedSafetyNumber == code,
            verifiedAt = remoteDevice.verifiedAt?.let(Instant::ofEpochMilli),
            trustState = remoteDevice.trustStateValue(),
            identityLastChangedAt = remoteDevice.identityLastChangedAt?.let(Instant::ofEpochMilli),
        )
    }

    private suspend fun primaryRemoteDevice(contact: Contact): ContactDeviceEntity =
        contactDeviceDao.findByContact(contact.userId)
            .firstOrNull { !it.identityKey.isNullOrBlank() }
            ?: fetchAndStoreRemoteDevice(contact)

    private suspend fun conversationForPending(message: PendingMessageDto): com.enigma.securechat.data.db.ConversationEntity? {
        val contactDevice = contactDeviceDao.findByDevice(message.senderDeviceId)
        val contact = contactDevice?.let { contactDao.findByUserId(it.contactUserId) }
            ?: createUnknownContact(message)
            ?: return null
        val bubbleId = message.bubbleId
        conversationDao.findByContact(contact.userId, bubbleId)?.let { return it }
        val conversation = Conversation(
            id = UUID.randomUUID().toString(),
            contactUserId = contact.userId,
            contactPublicId = contact.publicId,
            bubbleId = bubbleId,
            updatedAt = Instant.now(),
        ).toEntity()
        conversationDao.upsert(conversation)
        return conversation
    }

    private suspend fun createUnknownContact(message: PendingMessageDto): com.enigma.securechat.data.db.ContactEntity? {
        val senderUserId = message.senderUserId ?: return null
        val senderPublicId = message.senderPublicId ?: return null
        val contact = Contact(
            userId = senderUserId,
            publicId = senderPublicId,
            displayName = senderPublicId,
        )
        contactDao.upsert(contact.toEntity())
        storeUnknownDevice(message, senderUserId)
        return contact.toEntity()
    }

    private suspend fun fetchAndStoreRemoteDevice(contact: Contact): ContactDeviceEntity {
        val bundle = apiProvider.withActiveApi { it.discoverKeys(contact.userId) }.devices.firstOrNull()
            ?: error("No remote device")
        storeRemoteBundle(contact.userId, bundle)
        return requireNotNull(contactDeviceDao.findByDevice(bundle.deviceId)) {
            "Remote device was not stored"
        }
    }

    private suspend fun storeUnknownDevice(message: PendingMessageDto, senderUserId: String) {
        contactDeviceDao.upsert(
            ContactDeviceEntity(
                deviceId = message.senderDeviceId,
                contactUserId = senderUserId,
            ),
        )
    }

    private suspend fun storeRemoteBundle(contactUserId: String, bundle: DeviceKeyBundleDto): RemoteIdentityUpdate =
        contactDeviceDao.upsertRemoteIdentity(
            deviceId = bundle.deviceId,
            contactUserId = contactUserId,
            identityKey = bundle.identityKey,
            registrationId = bundle.registrationId,
            protocolDeviceId = bundle.protocolDeviceId,
        )

    private suspend fun enforceSendPolicy(device: ContactDeviceEntity) {
        val trustState = device.trustStateValue()
        when (trustState) {
            ContactDeviceTrustState.BLOCKED -> error("Remote device is blocked")
            ContactDeviceTrustState.UNVERIFIED,
            ContactDeviceTrustState.CHANGED -> {
                if (highSecurityModeProvider()) {
                    error("High security mode requires a verified safety number before sending")
                }
            }
            ContactDeviceTrustState.VERIFIED -> Unit
        }
    }

    private fun ContactDeviceEntity.toRemoteRef(): RemoteDeviceRef? =
        protocolDeviceId?.let { RemoteDeviceRef(deviceId = deviceId, protocolDeviceId = it) }

    private fun ContactDeviceEntity.trustStateValue(): ContactDeviceTrustState =
        runCatching { ContactDeviceTrustState.valueOf(trustState) }
            .getOrDefault(ContactDeviceTrustState.UNVERIFIED)

    private fun ContactDeviceEntity.toMessagePeerIdentityState(): MessagePeerIdentityState =
        when (trustStateValue()) {
            ContactDeviceTrustState.VERIFIED -> MessagePeerIdentityState.VERIFIED
            ContactDeviceTrustState.CHANGED -> MessagePeerIdentityState.CHANGED
            ContactDeviceTrustState.UNVERIFIED -> MessagePeerIdentityState.UNVERIFIED
            ContactDeviceTrustState.BLOCKED -> MessagePeerIdentityState.CHANGED
        }

    private fun P2pPeerIdentityState.toMessagePeerIdentityState(): MessagePeerIdentityState = when (this) {
        P2pPeerIdentityState.VERIFIED -> MessagePeerIdentityState.VERIFIED
        P2pPeerIdentityState.UNVERIFIED -> MessagePeerIdentityState.UNVERIFIED
        P2pPeerIdentityState.CHANGED -> MessagePeerIdentityState.CHANGED
    }

    private fun P2pRoute.toMessageTransport(): MessageTransport = when (this) {
        P2pRoute.DIRECT -> MessageTransport.P2P_DIRECT
        P2pRoute.TURN -> MessageTransport.P2P_TURN
    }

    private fun P2pReceiptStatus.toMessageStatus(): MessageStatus = when (this) {
        P2pReceiptStatus.DELIVERED -> MessageStatus.DELIVERED
        P2pReceiptStatus.READ -> MessageStatus.READ
    }

    private fun MessagePayload.toP2pAttachmentSpecs(): List<P2pAttachmentSpec> = attachments.map {
        P2pAttachmentSpec(
            blobId = it.descriptor.blobId,
            sizeBytes = it.descriptor.sizeBytes,
            sha256 = it.descriptor.sha256.lowercase(),
        )
    }

    private fun MessagePayload.messageType(): String = when {
        attachments.isEmpty() -> "text"
        body.isBlank() && attachments.size == 1 -> "file"
        else -> "opaque"
    }

    private fun String.toMessageStatusOrNull(): MessageStatus? = when (this) {
        "delivered" -> MessageStatus.DELIVERED
        "read" -> MessageStatus.READ
        else -> null
    }
}
