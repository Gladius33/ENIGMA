package com.enigma.securechat.data.repository

import com.enigma.securechat.data.db.BubbleDao
import com.enigma.securechat.data.db.BubbleEntity
import com.enigma.securechat.data.db.BubbleIndexPolicy
import com.enigma.securechat.data.db.BubbleJoinPolicy
import com.enigma.securechat.data.db.BubbleMemberEntity
import com.enigma.securechat.data.db.BubbleMode
import com.enigma.securechat.data.db.BubbleRelayEntity
import com.enigma.securechat.data.db.BubbleServiceEntity
import com.enigma.securechat.data.db.BubbleVisibility
import com.enigma.securechat.data.db.RelayType
import com.enigma.securechat.domain.model.AppResult
import com.enigma.securechat.network.BubbleSyncRequiredException
import com.enigma.securechat.network.OfficialRelayResolver
import com.enigma.securechat.network.RelayScopedApiProvider
import com.enigma.securechat.network.dto.AddBubbleRelayRequestDto
import com.enigma.securechat.network.dto.BubbleDto
import com.enigma.securechat.network.dto.BubbleMemberDto
import com.enigma.securechat.network.dto.BubbleRelayDto
import com.enigma.securechat.network.dto.CreateBubbleRequestDto
import com.enigma.securechat.network.toUserVisibleError
import com.enigma.securechat.storage.RelaySettingsStore
import java.time.Instant
import java.util.UUID
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map

data class BubbleRelayPolicy(
    val bubbleId: String,
    val relayIds: List<String>,
    val fallbackOfficialAllowed: Boolean,
    val isolated: Boolean,
)

data class ActiveBubbleContext(
    val bubble: BubbleEntity,
    val relayPolicy: BubbleRelayPolicy,
    val primaryRelay: RelayProfile?,
    val fallbackRelay: RelayProfile?,
    val showGlobalContacts: Boolean,
)

class ActiveBubbleContextManager(
    private val relaySettingsStore: RelaySettingsStore,
) {
    val activeBubbleId: Flow<String> = relaySettingsStore.activeBubbleId

    suspend fun activateBubble(bubbleId: String) {
        relaySettingsStore.saveActiveBubble(bubbleId)
    }
}

class BubbleRepository(
    private val bubbleDao: BubbleDao,
    private val relayRepository: RelayRepository,
    private val activeBubbleContextManager: ActiveBubbleContextManager,
    private val apiProvider: RelayScopedApiProvider,
) {
    val bubbles: Flow<List<BubbleEntity>> = bubbleDao.observeBubbles().map { rows ->
        val hasOfficialServerMainBubble =
            apiProvider.activeEndpoint.value.primaryRelayId == OfficialRelayResolver.OFFICIAL_RELAY_ID &&
                rows.any { it.mode == BubbleMode.MAIN_GLOBAL.name && it.ownerIdentityId != null }
        if (hasOfficialServerMainBubble) {
            rows.filterNot { it.id == RelaySettingsStore.DEFAULT_MAIN_BUBBLE_ID }
        } else {
            rows
        }
    }
    val activeBubbleId: Flow<String> = activeBubbleContextManager.activeBubbleId
    private val selectedContext = MutableStateFlow<ActiveBubbleContext?>(null)
    val activeContext: Flow<ActiveBubbleContext?> =
        combine(selectedContext, activeBubbleId) { context, _ -> context }

    suspend fun ensureDefaults() {
        relayRepository.ensureDefaults()
        seedBubble(
            id = RelaySettingsStore.DEFAULT_MAIN_BUBBLE_ID,
            slug = "main",
            name = "Main Bubble",
            description = "Conversations Enigma globales via le relais officiel.",
            mode = BubbleMode.MAIN_GLOBAL,
            visibility = BubbleVisibility.PRIVATE,
            joinPolicy = BubbleJoinPolicy.CLOSED,
            indexPolicy = BubbleIndexPolicy.INDEX_FORBIDDEN,
            relayRole = "primary",
            fallbackAllowed = false,
        )
        seedBubble(
            id = "private-connected-bubble",
            slug = "private-connected",
            name = "Private Connected Bubble",
            description = "Bulle privée connectée aux identités Enigma globales.",
            mode = BubbleMode.PRIVATE_CONNECTED,
            visibility = BubbleVisibility.PRIVATE,
            joinPolicy = BubbleJoinPolicy.INVITE_ONLY,
            indexPolicy = BubbleIndexPolicy.PRIVATE_ONLY,
            relayRole = "primary",
            fallbackAllowed = true,
        )
        seedBubble(
            id = "private-isolated-bubble",
            slug = "private-isolated",
            name = "Private Isolated Bubble",
            description = "Bulle isolée avec invitations QR et contacts locaux filtrés.",
            mode = BubbleMode.PRIVATE_ISOLATED,
            visibility = BubbleVisibility.SECRET,
            joinPolicy = BubbleJoinPolicy.INVITE_ONLY,
            indexPolicy = BubbleIndexPolicy.INDEX_FORBIDDEN,
            relayRole = "primary",
            fallbackAllowed = false,
            seedOfficialRelay = false,
        )
        seedBubble(
            id = "community-bubble",
            slug = "community",
            name = "Community Bubble",
            description = "Espace communauté avec relais officiel et relais communautaire possible.",
            mode = BubbleMode.COMMUNITY,
            visibility = BubbleVisibility.UNLISTED,
            joinPolicy = BubbleJoinPolicy.REQUEST_APPROVAL,
            indexPolicy = BubbleIndexPolicy.INDEX_OPT_IN,
            relayRole = "fallback",
            fallbackAllowed = true,
        )
        seedBubble(
            id = "organization-bubble",
            slug = "organization",
            name = "Organization Bubble",
            description = "Espace organisationnel administré.",
            mode = BubbleMode.ORGANIZATION,
            visibility = BubbleVisibility.PRIVATE,
            joinPolicy = BubbleJoinPolicy.ADMIN_MANAGED,
            indexPolicy = BubbleIndexPolicy.PRIVATE_ONLY,
            relayRole = "fallback",
            fallbackAllowed = true,
        )
        runCatching { relayRepository.syncRelays() }
        runCatching { syncBubbles() }
        activateBubble(canonicalActiveBubbleId(activeBubbleId.first()))
    }

    suspend fun activateBubble(bubbleId: String): ActiveBubbleContext {
        val bubble = requireNotNull(bubbleDao.findBubble(bubbleId)) { "Unknown bubble" }
        activeBubbleContextManager.activateBubble(bubbleId)
        val context = buildContext(bubble)
        selectedContext.value = context
        apiProvider.updateActiveContext(context)
        return context
    }

    suspend fun currentBubbleId(): String = activeBubbleId.first()

    suspend fun currentNetworkBubbleId(): String {
        val activeId = activeBubbleId.first()
        if (activeId.isUuid()) return activeId

        if (activeId == RelaySettingsStore.DEFAULT_MAIN_BUBBLE_ID) {
            val serverMain = bubbleDao.findServerMainBubble(OfficialRelayResolver.OFFICIAL_RELAY_ID)
            if (serverMain != null) {
                activateBubble(serverMain.id)
                return serverMain.id
            }
        }

        throw BubbleSyncRequiredException()
    }

    suspend fun attachRelayToBubble(
        bubbleId: String,
        relayId: String,
        fallbackAllowed: Boolean,
    ) {
        val bubble = requireNotNull(bubbleDao.findBubble(bubbleId)) { "Unknown bubble" }
        val isolated = bubble.mode == BubbleMode.PRIVATE_ISOLATED.name
        require(!(isolated && relayId == OfficialRelayResolver.OFFICIAL_RELAY_ID)) {
            "Private Isolated requires a private relay"
        }
        val effectiveFallbackAllowed = fallbackAllowed && !isolated
        bubbleDao.clearPrimaryRelays(bubbleId)
        bubbleDao.upsertRelay(
            BubbleRelayEntity(
                bubbleId = bubbleId,
                relayId = relayId,
                role = "primary",
                priority = 0,
                required = isolated,
                fallbackAllowed = effectiveFallbackAllowed,
            ),
        )
        runCatching { addRelayToBubbleRemote(bubbleId, relayId, effectiveFallbackAllowed) }
        refreshSelectedContext(bubbleId)
    }

    suspend fun useOfficialRelayForBubble(bubbleId: String) {
        attachRelayToBubble(
            bubbleId = bubbleId,
            relayId = OfficialRelayResolver.OFFICIAL_RELAY_ID,
            fallbackAllowed = false,
        )
    }

    suspend fun syncBubbles(): AppResult<Unit> = runCatching {
        val response = apiProvider.withActiveApi { it.bubbles() }
        response.bubbles.forEach { bubble ->
            bubbleDao.upsertBubble(bubble.toEntity())
            syncBubbleRelays(bubble.id)
            syncBubbleMembers(bubble.id)
        }
        promoteMainBubbleAlias()
        val activeId = activeBubbleId.first()
        val canonicalId = canonicalActiveBubbleId(activeId)
        if (canonicalId != activeId) {
            activateBubble(canonicalId)
        } else {
            selectedContext.value?.bubble?.id?.let { refreshSelectedContext(it) }
        }
    }.fold(
        onSuccess = { AppResult.Ok(Unit) },
        onFailure = { AppResult.Err(it.toUserVisibleError("Bulles non synchronisées")) },
    )

    suspend fun syncBubbleRelays(bubbleId: String): AppResult<Unit> = runCatching {
        val response = apiProvider.withActiveApi { it.bubbleRelays(bubbleId) }
        response.relays.forEach { bubbleDao.upsertRelay(it.toEntity()) }
        refreshSelectedContext(bubbleId)
    }.fold(
        onSuccess = { AppResult.Ok(Unit) },
        onFailure = { AppResult.Err(it.toUserVisibleError("Relais de bulle non synchronisés")) },
    )

    suspend fun syncBubbleMembers(bubbleId: String): AppResult<Unit> = runCatching {
        val response = apiProvider.withActiveApi { it.bubbleMembers(bubbleId) }
        response.members.forEach { bubbleDao.upsertMember(it.toEntity(bubbleId)) }
    }.fold(
        onSuccess = { AppResult.Ok(Unit) },
        onFailure = { AppResult.Err(it.toUserVisibleError("Membres de bulle non synchronisés")) },
    )

    suspend fun createBubbleRemote(
        name: String,
        mode: BubbleMode,
        visibility: BubbleVisibility,
        joinPolicy: BubbleJoinPolicy,
        indexPolicy: BubbleIndexPolicy,
    ): AppResult<BubbleEntity> = runCatching {
        val remote = apiProvider.withActiveApi {
            it.createBubble(
                CreateBubbleRequestDto(
                    slug = null,
                    name = name,
                    description = null,
                    mode = mode.name,
                    visibility = visibility.name,
                    joinPolicy = joinPolicy.name,
                    indexPolicy = indexPolicy.name,
                ),
            )
        }
        val entity = remote.toEntity()
        bubbleDao.upsertBubble(entity)
        syncBubbleRelays(entity.id)
        syncBubbleMembers(entity.id)
        entity
    }.fold(
        onSuccess = { AppResult.Ok(it) },
        onFailure = { AppResult.Err(it.toUserVisibleError("Bulle non créée côté serveur")) },
    )

    suspend fun addRelayToBubbleRemote(
        bubbleId: String,
        relayId: String,
        fallbackAllowed: Boolean,
    ): AppResult<BubbleRelayEntity> = runCatching {
        val bubble = requireNotNull(bubbleDao.findBubble(bubbleId)) { "Unknown bubble" }
        val isolated = bubble.mode == BubbleMode.PRIVATE_ISOLATED.name
        require(!(isolated && relayId == OfficialRelayResolver.OFFICIAL_RELAY_ID)) {
            "Private Isolated requires a private relay"
        }
        val effectiveFallbackAllowed = fallbackAllowed && !isolated
        val remote = apiProvider.withActiveApi {
            it.addBubbleRelay(
                bubbleId = bubbleId,
                body = AddBubbleRelayRequestDto(
                    relayId = relayId,
                    role = "primary",
                    priority = 0,
                    required = isolated,
                    fallbackAllowed = effectiveFallbackAllowed,
                ),
            )
        }
        remote.toEntity().also { bubbleDao.upsertRelay(it) }
    }.fold(
        onSuccess = { AppResult.Ok(it) },
        onFailure = { AppResult.Err(it.toUserVisibleError("Relais non attaché côté serveur")) },
    )
    suspend fun seedBubbleFromInvite(
        bubbleId: String,
        name: String,
        mode: String,
        relayHint: String?,
    ) {
        val now = System.currentTimeMillis()
        val normalizedMode = runCatching { BubbleMode.valueOf(mode) }.getOrDefault(BubbleMode.PRIVATE_CONNECTED)
        bubbleDao.upsertBubble(
            BubbleEntity(
                id = bubbleId,
                slug = bubbleId.take(32),
                name = name.ifBlank { "Private Bubble" },
                description = "Bulle importée depuis QR.",
                mode = normalizedMode.name,
                visibility = BubbleVisibility.SECRET.name,
                joinPolicy = BubbleJoinPolicy.INVITE_ONLY.name,
                indexPolicy = BubbleIndexPolicy.PRIVATE_ONLY.name,
                ownerIdentityId = null,
                publicKey = null,
                createdAt = now,
                updatedAt = now,
                deletedAt = null,
            ),
        )
        relayHint?.takeIf { it.isNotBlank() }?.let {
            val relay = relayRepository.addCustomRelay("Relais QR", it, RelayType.PRIVATE)
            attachRelayToBubble(
                bubbleId = bubbleId,
                relayId = relay.id,
                fallbackAllowed = normalizedMode != BubbleMode.PRIVATE_ISOLATED,
            )
        }
        activateBubble(bubbleId)
    }

    fun observeMembers(bubbleId: String): Flow<List<BubbleMemberEntity>> = bubbleDao.observeMembers(bubbleId)
    fun observeRelays(bubbleId: String): Flow<List<BubbleRelayEntity>> = bubbleDao.observeBubbleRelays(bubbleId)
    fun observeServices(bubbleId: String): Flow<List<BubbleServiceEntity>> = bubbleDao.observeServices(bubbleId)

    private suspend fun buildContext(bubble: BubbleEntity): ActiveBubbleContext {
        val relays = bubbleDao.bubbleRelays(bubble.id)
        val isolated = bubble.mode == BubbleMode.PRIVATE_ISOLATED.name
        val eligibleRelays = if (isolated) {
            relays.filter { it.relayId != OfficialRelayResolver.OFFICIAL_RELAY_ID }
        } else {
            relays
        }
        val primaryRelayId = eligibleRelays.firstOrNull()?.relayId
        val primary = primaryRelayId?.let { relayRepository.relayById(it) }
            ?: relayRepository.relayById(OfficialRelayResolver.OFFICIAL_RELAY_ID).takeUnless { isolated }
        val fallbackAllowed = !isolated && relays.any { it.fallbackAllowed }
        val fallback = if (fallbackAllowed && primary?.isOfficial == false) {
            relayRepository.relayById(OfficialRelayResolver.OFFICIAL_RELAY_ID)
        } else {
            null
        }
        return ActiveBubbleContext(
            bubble = bubble,
            relayPolicy = BubbleRelayPolicy(
                bubbleId = bubble.id,
                relayIds = eligibleRelays.map { it.relayId },
                fallbackOfficialAllowed = fallbackAllowed,
                isolated = isolated,
            ),
            primaryRelay = primary,
            fallbackRelay = fallback,
            showGlobalContacts = bubble.mode != BubbleMode.PRIVATE_ISOLATED.name,
        )
    }

    private suspend fun seedBubble(
        id: String,
        slug: String,
        name: String,
        description: String,
        mode: BubbleMode,
        visibility: BubbleVisibility,
        joinPolicy: BubbleJoinPolicy,
        indexPolicy: BubbleIndexPolicy,
        relayRole: String,
        fallbackAllowed: Boolean,
        seedOfficialRelay: Boolean = true,
    ) {
        if (bubbleDao.findBySlug(slug) != null) return
        val now = System.currentTimeMillis()
        bubbleDao.upsertBubble(
            BubbleEntity(
                id = id,
                slug = slug,
                name = name,
                description = description,
                mode = mode.name,
                visibility = visibility.name,
                joinPolicy = joinPolicy.name,
                indexPolicy = indexPolicy.name,
                ownerIdentityId = null,
                publicKey = null,
                createdAt = now,
                updatedAt = now,
                deletedAt = null,
            ),
        )
        if (seedOfficialRelay) {
            bubbleDao.upsertRelay(
                BubbleRelayEntity(
                    bubbleId = id,
                    relayId = OfficialRelayResolver.OFFICIAL_RELAY_ID,
                    role = relayRole,
                    priority = 0,
                    required = mode == BubbleMode.MAIN_GLOBAL,
                    fallbackAllowed = fallbackAllowed,
                ),
            )
        }
        bubbleDao.upsertService(
            BubbleServiceEntity(
                id = UUID.randomUUID().toString(),
                bubbleId = id,
                serviceType = "messages",
                name = "Messages",
                slug = "messages",
                visibility = visibility.name,
                indexPolicy = indexPolicy.name,
                createdAt = now,
            ),
        )
    }

    private suspend fun refreshSelectedContext(bubbleId: String) {
        val activeId = activeBubbleId.first()
        if (activeId != bubbleId && selectedContext.value?.bubble?.id != bubbleId) return
        val context = bubbleDao.findBubble(bubbleId)?.let { buildContext(it) }
        selectedContext.value = context
        apiProvider.updateActiveContext(context)
    }

    private fun BubbleDto.toEntity(): BubbleEntity =
        BubbleEntity(
            id = id,
            slug = slug,
            name = name,
            description = description,
            mode = mode,
            visibility = visibility,
            joinPolicy = joinPolicy,
            indexPolicy = indexPolicy,
            ownerIdentityId = ownerIdentityId,
            publicKey = publicKey,
            createdAt = createdAt.toEpochMillis(),
            updatedAt = updatedAt.toEpochMillis(),
            deletedAt = null,
        )

    private fun BubbleRelayDto.toEntity(): BubbleRelayEntity =
        BubbleRelayEntity(
            bubbleId = bubbleId,
            relayId = relayId,
            role = role,
            priority = priority,
            required = required,
            fallbackAllowed = fallbackAllowed,
        )

    private fun BubbleMemberDto.toEntity(bubbleId: String): BubbleMemberEntity =
        BubbleMemberEntity(
            bubbleId = bubbleId,
            identityId = identityId,
            role = role,
            status = status,
            joinedAt = joinedAt.toEpochMillis(),
        )

    private suspend fun canonicalActiveBubbleId(activeId: String): String =
        if (activeId == RelaySettingsStore.DEFAULT_MAIN_BUBBLE_ID) {
            bubbleDao.findServerMainBubble(OfficialRelayResolver.OFFICIAL_RELAY_ID)?.id ?: activeId
        } else {
            activeId
        }

    private suspend fun promoteMainBubbleAlias() {
        if (apiProvider.activeEndpoint.value.primaryRelayId != OfficialRelayResolver.OFFICIAL_RELAY_ID) return
        val serverMain = bubbleDao.findServerMainBubble(OfficialRelayResolver.OFFICIAL_RELAY_ID) ?: return
        bubbleDao.promoteConversationBubbleAlias(
            localBubbleId = RelaySettingsStore.DEFAULT_MAIN_BUBBLE_ID,
            serverBubbleId = serverMain.id,
        )
    }

    private fun String.toEpochMillis(): Long =
        runCatching { Instant.parse(this).toEpochMilli() }.getOrDefault(System.currentTimeMillis())

    private fun String.isUuid(): Boolean =
        runCatching { UUID.fromString(this) }.isSuccess
}
