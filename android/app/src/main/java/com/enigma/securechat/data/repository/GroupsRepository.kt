package com.enigma.securechat.data.repository

import com.enigma.securechat.crypto.CryptoEngine
import com.enigma.securechat.crypto.RecipientCiphertext
import com.enigma.securechat.crypto.RecipientEncryptedEnvelope
import com.enigma.securechat.crypto.RecipientEnvelopeCodec
import com.enigma.securechat.crypto.toRef
import com.enigma.securechat.data.db.GroupDao
import com.enigma.securechat.data.db.GroupEntity
import com.enigma.securechat.data.db.GroupMemberEntity
import com.enigma.securechat.data.db.GroupMessageDao
import com.enigma.securechat.data.db.GroupMessageEntity
import com.enigma.securechat.data.mapper.toRemoteBundle
import com.enigma.securechat.domain.model.AppResult
import com.enigma.securechat.network.RelayScopedApiProvider
import com.enigma.securechat.network.toUserVisibleError
import com.enigma.securechat.network.dto.AddGroupMemberRequestDto
import com.enigma.securechat.network.dto.CreateGroupRequestDto
import com.enigma.securechat.network.dto.GroupDetailResponseDto
import com.enigma.securechat.network.dto.GroupMemberDto
import com.enigma.securechat.network.dto.GroupReceiptRequestDto
import com.enigma.securechat.network.dto.SendGroupMessageRequestDto
import com.enigma.securechat.storage.DeviceStore
import com.enigma.securechat.storage.LocalCipher
import com.enigma.securechat.storage.RelaySettingsStore
import java.util.UUID
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flatMapLatest
import kotlinx.coroutines.flow.flowOf

class GroupsRepository(
    private val apiProvider: RelayScopedApiProvider,
    private val cryptoEngine: CryptoEngine,
    private val localCipher: LocalCipher,
    private val deviceStore: DeviceStore,
    private val groupDao: GroupDao,
    private val groupMessageDao: GroupMessageDao,
    private val activeBubbleId: Flow<String> = flowOf(RelaySettingsStore.DEFAULT_MAIN_BUBBLE_ID),
    private val activeBubbleIdProvider: suspend () -> String = {
        RelaySettingsStore.DEFAULT_MAIN_BUBBLE_ID
    },
) {
    @OptIn(ExperimentalCoroutinesApi::class)
    fun observeGroups(): Flow<List<GroupEntity>> =
        activeBubbleId.flatMapLatest { bubbleId -> groupDao.observeGroups(bubbleId) }

    fun observeMessages(groupId: String): Flow<List<GroupMessageEntity>> =
        groupMessageDao.observeMessages(groupId)

    fun observeMembers(groupId: String): Flow<List<GroupMemberEntity>> =
        groupDao.observeMembers(groupId)

    suspend fun syncGroups(): AppResult<Unit> = runCatching {
        val bubbleId = activeBubbleIdProvider()
        apiProvider.withActiveApi { it.groups(bubbleId) }.groups.forEach { group ->
            groupDao.upsert(
                GroupEntity(
                    id = group.id,
                    bubbleId = group.bubbleId,
                    title = group.title,
                    ownerUserId = group.ownerUserId,
                    createdAt = group.createdAt,
                ),
            )
        }
    }.fold(
        onSuccess = { AppResult.Ok(Unit) },
        onFailure = { AppResult.Err(it.toUserVisibleError("Groupes non synchronisés")) },
    )

    suspend fun syncGroupDetail(groupId: String): AppResult<Unit> = runCatching {
        upsertGroupDetail(apiProvider.withActiveApi { it.group(groupId) })
    }.fold(
        onSuccess = { AppResult.Ok(Unit) },
        onFailure = { AppResult.Err(it.toUserVisibleError("Groupe non synchronisé")) },
    )

    suspend fun createGroup(title: String): AppResult<Unit> = runCatching {
        val bubbleId = activeBubbleIdProvider()
        val detail = apiProvider.withActiveApi {
            it.createGroup(CreateGroupRequestDto(bubbleId = bubbleId, title = title))
        }
        upsertGroupDetail(detail)
    }.fold(
        onSuccess = { AppResult.Ok(Unit) },
        onFailure = { AppResult.Err(it.toUserVisibleError("Groupe non créé")) },
    )

    suspend fun addMember(groupId: String, userId: String, role: String = "member"): AppResult<Unit> = runCatching {
        val member = apiProvider.withActiveApi {
            it.addGroupMember(
                groupId = groupId,
                body = AddGroupMemberRequestDto(userId = userId, role = role),
            )
        }
        groupDao.upsertMembers(listOf(member.toEntity(groupId)))
    }.fold(
        onSuccess = { AppResult.Ok(Unit) },
        onFailure = { AppResult.Err(it.toUserVisibleError("Membre non ajouté")) },
    )

    suspend fun sendText(groupId: String, body: String): AppResult<Unit> =
        sendPayload(groupId, MessagePayload(body = body))

    suspend fun sendPayload(groupId: String, payload: MessagePayload): AppResult<Unit> = runCatching {
        require(payload.body.isNotBlank() || payload.attachments.isNotEmpty()) { "Empty group payload" }
        val senderDeviceId = requireNotNull(deviceStore.deviceId()) { "Device is not registered" }
        val group = groupDao.findById(groupId) ?: run {
            upsertGroupDetail(apiProvider.withActiveApi { it.group(groupId) })
            requireNotNull(groupDao.findById(groupId)) { "Group is not synchronized" }
        }
        payload.attachments.forEach { attachment ->
            require(attachment.descriptor.bubbleId == group.bubbleId) {
                "Attachment bubble does not match group bubble"
            }
        }
        val detail = apiProvider.withActiveApi { it.group(groupId) }
        upsertGroupDetail(detail)
        val memberIds = detail.members.map { it.userId }.distinct()
        require(memberIds.isNotEmpty()) { "Group has no members" }

        val encodedPayload = MessagePayloadCodec.encode(payload.body, payload.attachments)
        val recipientCiphertexts = mutableListOf<RecipientCiphertext>()
        apiProvider.withActiveApi { api ->
            for (memberId in memberIds) {
                val devices = api.discoverKeys(memberId).devices
                for (device in devices.distinctBy { it.deviceId }) {
                    val discovered = device.toRemoteBundle()
                    val remote = if (
                        discovered.protocolDeviceId != null &&
                        cryptoEngine.hasSession(discovered.toRef())
                    ) {
                        discovered
                    } else {
                        api.claimPreKey(memberId, device.deviceId).device.toRemoteBundle()
                    }
                    val ciphertext = cryptoEngine.encryptText(encodedPayload, remote)
                    recipientCiphertexts += RecipientCiphertext(
                        deviceId = device.deviceId,
                        ciphertext = ciphertext,
                    )
                }
            }
        }
        require(recipientCiphertexts.isNotEmpty()) { "No recipient devices available" }

        val transportEnvelope = RecipientEnvelopeCodec.encode(
            RecipientEncryptedEnvelope(recipients = recipientCiphertexts.distinctBy { it.deviceId }),
        )
        val localBody = localCipher.encryptToString(encodedPayload.toByteArray(Charsets.UTF_8))
        val sent = apiProvider.withActiveApi {
            it.sendGroupMessage(
                groupId = groupId,
                body = SendGroupMessageRequestDto(
                    bubbleId = group.bubbleId,
                    senderDeviceId = senderDeviceId,
                    clientMessageId = UUID.randomUUID().toString(),
                    messageType = payload.messageType(),
                    ciphertext = transportEnvelope,
                    attachmentBlobIds = payload.attachments.map { it.descriptor.blobId },
                ),
            )
        }
        groupMessageDao.upsert(
            GroupMessageEntity(
                id = sent.id,
                bubbleId = sent.bubbleId,
                groupId = groupId,
                senderDeviceId = senderDeviceId,
                messageType = payload.messageType(),
                ciphertext = transportEnvelope,
                encryptedLocalBody = localBody,
                createdAt = sent.createdAt,
            ),
        )
    }.fold(
        onSuccess = { AppResult.Ok(Unit) },
        onFailure = { AppResult.Err(it.toUserVisibleError("Message de groupe non envoyé")) },
    )

    suspend fun syncPending(groupId: String): AppResult<Unit> = runCatching {
        val deviceId = requireNotNull(deviceStore.deviceId()) { "Device is not registered" }
        val pending = apiProvider.withActiveApi { it.pendingGroupMessages(groupId) }
        pending.messages.forEach { message ->
            val recipientCiphertext = runCatching {
                RecipientEnvelopeCodec.ciphertextForDevice(message.ciphertext, deviceId)
            }.getOrNull() ?: return@forEach
            val encodedPayload = cryptoEngine.decryptText(recipientCiphertext)
            MessagePayloadCodec.decode(encodedPayload)
            val localBody = localCipher.encryptToString(encodedPayload.toByteArray(Charsets.UTF_8))
            groupMessageDao.upsert(
                GroupMessageEntity(
                    id = message.id,
                    bubbleId = message.bubbleId,
                    groupId = message.groupId,
                    senderDeviceId = message.senderDeviceId,
                    messageType = message.messageType,
                    ciphertext = message.ciphertext,
                    encryptedLocalBody = localBody,
                    createdAt = message.createdAt,
                ),
            )
            apiProvider.withActiveApi {
                it.groupReceipt(
                    groupId = groupId,
                    messageId = message.id,
                    body = GroupReceiptRequestDto(deviceId = deviceId),
                )
            }
        }
    }.fold(
        onSuccess = { AppResult.Ok(Unit) },
        onFailure = { AppResult.Err(it.toUserVisibleError("Messages de groupe non synchronisés")) },
    )

    fun decryptLocalPayload(message: GroupMessageEntity): MessagePayload = runCatching {
        val decrypted = localCipher.decryptFromString(message.encryptedLocalBody)
        try {
            MessagePayloadCodec.decode(decrypted.toString(Charsets.UTF_8))
        } finally {
            decrypted.fill(0)
        }
    }.getOrDefault(MessagePayload(body = ""))

    fun decryptLocalBody(message: GroupMessageEntity): String = decryptLocalPayload(message).body

    private suspend fun upsertGroupDetail(detail: GroupDetailResponseDto) {
        groupDao.upsert(
            GroupEntity(
                id = detail.group.id,
                bubbleId = detail.group.bubbleId,
                title = detail.group.title,
                ownerUserId = detail.group.ownerUserId,
                createdAt = detail.group.createdAt,
            ),
        )
        groupDao.upsertMembers(detail.members.map { it.toEntity(detail.group.id) })
    }

    private fun GroupMemberDto.toEntity(groupId: String): GroupMemberEntity =
        GroupMemberEntity(
            groupId = groupId,
            userId = userId,
            publicId = publicId,
            role = role,
        )

    private fun MessagePayload.messageType(): String = when {
        attachments.isEmpty() -> "opaque"
        body.isBlank() && attachments.size == 1 -> "file"
        else -> "opaque"
    }
}
