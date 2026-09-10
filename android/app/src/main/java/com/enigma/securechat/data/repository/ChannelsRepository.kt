package com.enigma.securechat.data.repository

import com.enigma.securechat.crypto.CryptoEngine
import com.enigma.securechat.crypto.RecipientCiphertext
import com.enigma.securechat.crypto.RecipientEncryptedEnvelope
import com.enigma.securechat.crypto.RecipientEnvelopeCodec
import com.enigma.securechat.crypto.toRef
import com.enigma.securechat.data.db.ChannelDao
import com.enigma.securechat.data.db.ChannelEntity
import com.enigma.securechat.data.db.ChannelPostDao
import com.enigma.securechat.data.db.ChannelPostEntity
import com.enigma.securechat.data.mapper.toRemoteBundle
import com.enigma.securechat.domain.model.AppResult
import com.enigma.securechat.network.RelayScopedApiProvider
import com.enigma.securechat.network.toUserVisibleError
import com.enigma.securechat.network.dto.ChannelSubscriberDto
import com.enigma.securechat.network.dto.CreateChannelPostRequestDto
import com.enigma.securechat.network.dto.CreateChannelRequestDto
import com.enigma.securechat.storage.DeviceStore
import com.enigma.securechat.storage.LocalCipher
import com.enigma.securechat.storage.RelaySettingsStore
import java.util.UUID
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flatMapLatest
import kotlinx.coroutines.flow.flowOf

data class ChannelAudienceMember(
    val userId: String,
    val publicId: String,
    val role: String,
)

class ChannelsRepository(
    private val apiProvider: RelayScopedApiProvider,
    private val cryptoEngine: CryptoEngine,
    private val localCipher: LocalCipher,
    private val deviceStore: DeviceStore,
    private val channelDao: ChannelDao,
    private val channelPostDao: ChannelPostDao,
    private val activeBubbleId: Flow<String> = flowOf(RelaySettingsStore.DEFAULT_MAIN_BUBBLE_ID),
    private val activeBubbleIdProvider: suspend () -> String = {
        RelaySettingsStore.DEFAULT_MAIN_BUBBLE_ID
    },
) {
    @OptIn(ExperimentalCoroutinesApi::class)
    fun observeChannels(): Flow<List<ChannelEntity>> =
        activeBubbleId.flatMapLatest { bubbleId -> channelDao.observeChannels(bubbleId) }

    fun observePosts(channelId: String): Flow<List<ChannelPostEntity>> =
        channelPostDao.observePosts(channelId)

    suspend fun syncChannel(channelId: String): AppResult<ChannelEntity> = runCatching {
        val channel = apiProvider.withActiveApi { it.channel(channelId) }
        ChannelEntity(
            id = channel.id,
            bubbleId = channel.bubbleId,
            title = channel.title,
            description = channel.description,
            ownerUserId = channel.ownerUserId,
            createdAt = channel.createdAt,
        ).also { channelDao.upsert(it) }
    }.fold(
        onSuccess = { AppResult.Ok(it) },
        onFailure = { AppResult.Err(it.toUserVisibleError("Canal non synchronisé")) },
    )

    suspend fun subscribers(channelId: String): AppResult<List<ChannelAudienceMember>> = runCatching {
        apiProvider.withActiveApi { it.channelSubscribers(channelId) }
            .subscribers
            .map { it.toDomain() }
    }.fold(
        onSuccess = { AppResult.Ok(it) },
        onFailure = { AppResult.Err(it.toUserVisibleError("Audience du canal indisponible")) },
    )

    suspend fun syncChannels(): AppResult<Unit> = runCatching {
        val bubbleId = activeBubbleIdProvider()
        apiProvider.withActiveApi { it.channels(bubbleId) }.channels.forEach { channel ->
            channelDao.upsert(
                ChannelEntity(
                    id = channel.id,
                    bubbleId = channel.bubbleId,
                    title = channel.title,
                    description = channel.description,
                    ownerUserId = channel.ownerUserId,
                    createdAt = channel.createdAt,
                ),
            )
        }
    }.fold(
        onSuccess = { AppResult.Ok(Unit) },
        onFailure = { AppResult.Err(it.toUserVisibleError("Canaux non synchronisés")) },
    )

    suspend fun createChannel(title: String): AppResult<Unit> = runCatching {
        val bubbleId = activeBubbleIdProvider()
        val channel = apiProvider.withActiveApi {
            it.createChannel(CreateChannelRequestDto(bubbleId = bubbleId, title = title))
        }
        channelDao.upsert(
            ChannelEntity(
                id = channel.id,
                bubbleId = channel.bubbleId,
                title = channel.title,
                description = channel.description,
                ownerUserId = channel.ownerUserId,
                createdAt = channel.createdAt,
            ),
        )
    }.fold(
        onSuccess = { AppResult.Ok(Unit) },
        onFailure = { AppResult.Err(it.toUserVisibleError("Canal non créé")) },
    )

    suspend fun sendText(channelId: String, body: String): AppResult<Unit> =
        publishPayload(channelId, MessagePayload(body = body))

    suspend fun publishPayload(channelId: String, payload: MessagePayload): AppResult<Unit> = runCatching {
        require(payload.body.isNotBlank() || payload.attachments.isNotEmpty()) { "Empty channel payload" }
        val senderDeviceId = requireNotNull(deviceStore.deviceId()) { "Device is not registered" }
        val channel = when (val local = syncChannel(channelId)) {
            is AppResult.Ok -> local.value
            is AppResult.Err -> throw IllegalStateException(local.error.message)
        }
        payload.attachments.forEach { attachment ->
            require(attachment.descriptor.bubbleId == channel.bubbleId) {
                "Attachment bubble does not match channel bubble"
            }
        }
        val audience = apiProvider.withActiveApi { it.channelSubscribers(channelId) }.subscribers
        require(audience.isNotEmpty()) { "Channel has no subscribers" }

        val encodedPayload = MessagePayloadCodec.encode(payload.body, payload.attachments)
        val recipientCiphertexts = mutableListOf<RecipientCiphertext>()
        apiProvider.withActiveApi { api ->
            for (member in audience.distinctBy { it.userId }) {
                val devices = api.discoverKeys(member.userId).devices
                for (device in devices.distinctBy { it.deviceId }) {
                    val discovered = device.toRemoteBundle()
                    val remote = if (
                        discovered.protocolDeviceId != null &&
                        cryptoEngine.hasSession(discovered.toRef())
                    ) {
                        discovered
                    } else {
                        api.claimPreKey(member.userId, device.deviceId).device.toRemoteBundle()
                    }
                    recipientCiphertexts += RecipientCiphertext(
                        deviceId = device.deviceId,
                        ciphertext = cryptoEngine.encryptText(encodedPayload, remote),
                    )
                }
            }
        }
        require(recipientCiphertexts.isNotEmpty()) { "No subscriber devices available" }

        val transportEnvelope = RecipientEnvelopeCodec.encode(
            RecipientEncryptedEnvelope(recipients = recipientCiphertexts.distinctBy { it.deviceId }),
        )
        val localBody = localCipher.encryptToString(encodedPayload.toByteArray(Charsets.UTF_8))
        val sent = apiProvider.withActiveApi {
            it.createChannelPost(
                channelId = channelId,
                body = CreateChannelPostRequestDto(
                    bubbleId = channel.bubbleId,
                    senderDeviceId = senderDeviceId,
                    clientPostId = UUID.randomUUID().toString(),
                    postType = payload.postType(),
                    ciphertext = transportEnvelope,
                    attachmentBlobIds = payload.attachments.map { it.descriptor.blobId },
                ),
            )
        }
        channelPostDao.upsert(
            ChannelPostEntity(
                id = sent.id,
                bubbleId = sent.bubbleId,
                channelId = channelId,
                senderDeviceId = senderDeviceId,
                postType = payload.postType(),
                ciphertext = localBody,
                createdAt = sent.createdAt,
            ),
        )
    }.fold(
        onSuccess = { AppResult.Ok(Unit) },
        onFailure = { AppResult.Err(it.toUserVisibleError("Post non publié")) },
    )

    suspend fun syncPending(channelId: String): AppResult<Unit> = runCatching {
        val deviceId = requireNotNull(deviceStore.deviceId()) { "Device is not registered" }
        apiProvider.withActiveApi { it.pendingChannelPosts(channelId) }.posts.forEach { post ->
            val recipientCiphertext = runCatching {
                RecipientEnvelopeCodec.ciphertextForDevice(post.ciphertext, deviceId)
            }.getOrNull() ?: return@forEach
            val encodedPayload = cryptoEngine.decryptText(recipientCiphertext)
            MessagePayloadCodec.decode(encodedPayload)
            val localBody = localCipher.encryptToString(encodedPayload.toByteArray(Charsets.UTF_8))
            channelPostDao.upsert(
                ChannelPostEntity(
                    id = post.id,
                    bubbleId = post.bubbleId,
                    channelId = post.channelId,
                    senderDeviceId = post.senderDeviceId,
                    postType = post.postType,
                    ciphertext = localBody,
                    createdAt = post.createdAt,
                ),
            )
        }
    }.fold(
        onSuccess = { AppResult.Ok(Unit) },
        onFailure = { AppResult.Err(it.toUserVisibleError("Posts non synchronisés")) },
    )

    fun decryptLocalPayload(post: ChannelPostEntity): MessagePayload = runCatching {
        val decrypted = localCipher.decryptFromString(post.ciphertext)
        try {
            MessagePayloadCodec.decode(decrypted.toString(Charsets.UTF_8))
        } finally {
            decrypted.fill(0)
        }
    }.getOrDefault(MessagePayload(body = ""))

    fun decryptLocalBody(post: ChannelPostEntity): String = decryptLocalPayload(post).body

    private fun ChannelSubscriberDto.toDomain(): ChannelAudienceMember =
        ChannelAudienceMember(
            userId = userId,
            publicId = publicId,
            role = role,
        )

    private fun MessagePayload.postType(): String = when {
        attachments.isEmpty() -> "opaque"
        body.isBlank() && attachments.size == 1 -> "file"
        else -> "opaque"
    }
}
