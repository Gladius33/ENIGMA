package com.enigma.securechat.data.mapper

import com.enigma.securechat.crypto.OneTimePreKeyUpload
import com.enigma.securechat.crypto.PreKeyUploadBundle
import com.enigma.securechat.crypto.RemoteDeviceBundle
import com.enigma.securechat.crypto.RemoteKyberPreKey
import com.enigma.securechat.crypto.RemoteOneTimePreKey
import com.enigma.securechat.crypto.RemoteSignedPreKey
import com.enigma.securechat.crypto.KyberPreKeyUpload
import com.enigma.securechat.data.db.ContactEntity
import com.enigma.securechat.data.db.ConversationEntity
import com.enigma.securechat.data.db.MessageEntity
import com.enigma.securechat.domain.model.ChatMessage
import com.enigma.securechat.domain.model.Contact
import com.enigma.securechat.domain.model.Conversation
import com.enigma.securechat.domain.model.MessageDirection
import com.enigma.securechat.domain.model.MessagePeerIdentityState
import com.enigma.securechat.domain.model.MessageStatus
import com.enigma.securechat.domain.model.MessageTransport
import com.enigma.securechat.network.dto.DeviceKeyBundleDto
import com.enigma.securechat.network.dto.KyberPreKeyDto
import com.enigma.securechat.network.dto.OneTimePreKeyDto
import com.enigma.securechat.network.dto.SignedPreKeyDto
import com.enigma.securechat.network.dto.UploadKeysRequestDto
import java.time.Instant

fun ContactEntity.toDomain(): Contact = Contact(
    userId = userId,
    publicId = publicId,
    displayName = displayName,
)

fun Contact.toEntity(): ContactEntity = ContactEntity(
    userId = userId,
    publicId = publicId,
    displayName = displayName,
)

fun ConversationEntity.toDomain(): Conversation = Conversation(
    id = id,
    contactUserId = contactUserId,
    contactPublicId = contactPublicId,
    bubbleId = bubbleId,
    updatedAt = Instant.ofEpochMilli(updatedAt),
)

fun Conversation.toEntity(): ConversationEntity = ConversationEntity(
    id = id,
    contactUserId = contactUserId,
    contactPublicId = contactPublicId,
    bubbleId = bubbleId,
    updatedAt = updatedAt.toEpochMilli(),
)

fun MessageEntity.toDomain(): ChatMessage = ChatMessage(
    id = id,
    conversationId = conversationId,
    senderDeviceId = senderDeviceId,
    recipientDeviceId = recipientDeviceId,
    direction = MessageDirection.valueOf(direction),
    status = MessageStatus.valueOf(status),
    encryptedLocalBody = encryptedLocalBody,
    transportCiphertext = transportCiphertext,
    createdAt = Instant.ofEpochMilli(createdAt),
    clientMessageId = clientMessageId,
    transport = runCatching { MessageTransport.valueOf(transport) }.getOrDefault(MessageTransport.RELAY),
    peerIdentityState = runCatching { MessagePeerIdentityState.valueOf(peerIdentityState) }
        .getOrDefault(MessagePeerIdentityState.UNKNOWN),
)

fun ChatMessage.toEntity(remoteMessageId: String? = null): MessageEntity = MessageEntity(
    id = id,
    remoteMessageId = remoteMessageId,
    clientMessageId = clientMessageId,
    conversationId = conversationId,
    senderDeviceId = senderDeviceId,
    recipientDeviceId = recipientDeviceId,
    direction = direction.name,
    status = status.name,
    encryptedLocalBody = encryptedLocalBody,
    transportCiphertext = transportCiphertext,
    transport = transport.name,
    peerIdentityState = peerIdentityState.name,
    createdAt = createdAt.toEpochMilli(),
)

fun PreKeyUploadBundle.toDto(): UploadKeysRequestDto = UploadKeysRequestDto(
    deviceId = deviceId,
    identityKey = identityKey,
    registrationId = registrationId,
    protocolDeviceId = protocolDeviceId,
    signedPreKey = SignedPreKeyDto(
        keyId = signedPreKey.keyId,
        publicKey = signedPreKey.publicKey,
        signature = signedPreKey.signature,
    ),
    kyberPreKey = kyberPreKey?.toDto(),
    oneTimePreKeys = oneTimePreKeys.map(OneTimePreKeyUpload::toDto),
)

private fun OneTimePreKeyUpload.toDto(): OneTimePreKeyDto = OneTimePreKeyDto(
    keyId = keyId,
    publicKey = publicKey,
)

private fun KyberPreKeyUpload.toDto(): KyberPreKeyDto = KyberPreKeyDto(
    keyId = keyId,
    publicKey = publicKey,
    signature = signature,
)

fun DeviceKeyBundleDto.toRemoteBundle(): RemoteDeviceBundle = RemoteDeviceBundle(
    deviceId = deviceId,
    identityKey = identityKey,
    registrationId = registrationId,
    protocolDeviceId = protocolDeviceId,
    signedPreKey = RemoteSignedPreKey(
        keyId = signedPreKey.keyId,
        publicKey = signedPreKey.publicKey,
        signature = signedPreKey.signature,
    ),
    kyberPreKey = kyberPreKey?.let {
        RemoteKyberPreKey(
            keyId = it.keyId,
            publicKey = it.publicKey,
            signature = it.signature,
        )
    },
    oneTimePreKey = oneTimePreKey?.let {
        RemoteOneTimePreKey(keyId = it.keyId, publicKey = it.publicKey)
    },
)
