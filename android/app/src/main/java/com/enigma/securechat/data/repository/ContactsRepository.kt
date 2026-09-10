package com.enigma.securechat.data.repository

import com.enigma.securechat.data.db.ContactDao
import com.enigma.securechat.data.db.ContactDeviceDao
import com.enigma.securechat.data.db.ConversationDao
import com.enigma.securechat.data.mapper.toDomain
import com.enigma.securechat.data.mapper.toEntity
import com.enigma.securechat.domain.model.AppResult
import com.enigma.securechat.domain.model.Contact
import com.enigma.securechat.domain.model.Conversation
import com.enigma.securechat.network.RelayScopedApiProvider
import com.enigma.securechat.network.toUserVisibleError
import com.enigma.securechat.network.dto.AddContactRequestDto
import com.enigma.securechat.storage.RelaySettingsStore
import java.time.Instant
import java.util.UUID
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map

class ContactsRepository(
    private val apiProvider: RelayScopedApiProvider,
    private val contactDao: ContactDao,
    private val contactDeviceDao: ContactDeviceDao,
    private val conversationDao: ConversationDao,
    private val activeBubbleIdProvider: suspend () -> String = {
        RelaySettingsStore.DEFAULT_MAIN_BUBBLE_ID
    },
) {
    fun observeContacts(): Flow<List<Contact>> =
        contactDao.observeContacts().map { entities -> entities.map { it.toDomain() } }

    fun observeContactsForBubble(bubbleId: String): Flow<List<Contact>> =
        contactDao.observeContactsForBubble(bubbleId).map { entities -> entities.map { it.toDomain() } }

    suspend fun addByPublicId(publicId: String): AppResult<Contact> = runCatching {
        val resolved = apiProvider.withActiveApi { it.resolveUser(publicId) }
        val contact = Contact(
            userId = resolved.id,
            publicId = resolved.publicId,
            displayName = resolved.publicId,
        )
        apiProvider.withActiveApi { it.addContact(AddContactRequestDto(contactUserId = resolved.id)) }
        contactDao.upsert(contact.toEntity())

        val keys = apiProvider.withActiveApi { it.discoverKeys(resolved.id) }
        keys.devices.forEach { bundle ->
            contactDeviceDao.upsertRemoteIdentity(
                deviceId = bundle.deviceId,
                contactUserId = resolved.id,
                identityKey = bundle.identityKey,
                registrationId = bundle.registrationId,
                protocolDeviceId = bundle.protocolDeviceId,
            )
        }

        ensureConversation(contact)
        contact
    }.fold(
        onSuccess = { AppResult.Ok(it) },
        onFailure = { AppResult.Err(it.toUserVisibleError("Contact introuvable")) },
    )

    suspend fun ensureConversation(
        contact: Contact,
        bubbleId: String? = null,
    ): Conversation {
        val resolvedBubbleId = bubbleId ?: activeBubbleIdProvider()
        conversationDao.findByContact(contact.userId, resolvedBubbleId)?.let { return it.toDomain() }
        return Conversation(
            id = UUID.randomUUID().toString(),
            contactUserId = contact.userId,
            contactPublicId = contact.publicId,
            bubbleId = resolvedBubbleId,
            updatedAt = Instant.now(),
        ).also { conversationDao.upsert(it.toEntity()) }
    }

    suspend fun syncContacts(): AppResult<Unit> = runCatching {
        val response = apiProvider.withActiveApi { it.contacts() }
        for (remote in response.contacts) {
            contactDao.upsert(
                Contact(
                    userId = remote.userId,
                    publicId = remote.publicId,
                    displayName = remote.publicId,
                ).toEntity(),
            )
        }
    }.fold(
        onSuccess = { AppResult.Ok(Unit) },
        onFailure = { AppResult.Err(it.toUserVisibleError("Contacts non synchronisés")) },
    )
}
