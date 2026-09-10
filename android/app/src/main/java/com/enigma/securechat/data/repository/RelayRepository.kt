package com.enigma.securechat.data.repository

import com.enigma.securechat.data.db.RelayDao
import com.enigma.securechat.data.db.RelayEntity
import com.enigma.securechat.data.db.RelayTrustState
import com.enigma.securechat.data.db.RelayType
import com.enigma.securechat.domain.model.AppResult
import com.enigma.securechat.network.OfficialRelayResolver
import com.enigma.securechat.network.RelayUrlPolicy
import com.enigma.securechat.network.RelayScopedApiProvider
import com.enigma.securechat.network.dto.CreateCustomRelayRequestDto
import com.enigma.securechat.network.dto.RelayDto
import com.enigma.securechat.network.toUserVisibleError
import com.enigma.securechat.storage.RelaySettingsStore
import java.util.UUID
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map

data class RelayProfile(
    val id: String,
    val name: String,
    val url: String,
    val publicKey: String?,
    val type: RelayType,
    val trustState: RelayTrustState,
    val isOfficial: Boolean,
    val regionLabel: String? = null,
    val connected: Boolean = false,
)

class RelayRepository(
    private val relayDao: RelayDao,
    private val relaySettingsStore: RelaySettingsStore,
    private val officialRelay: RelayProfile,
    private val cleartextAllowed: Boolean,
    private val apiProvider: RelayScopedApiProvider,
) {
    val relays: Flow<List<RelayProfile>> = relayDao.observeRelays().map { rows ->
        rows.map { it.toRelayProfile() }
    }
    val customRelays: Flow<List<RelayProfile>> = relayDao.observeCustomRelays().map { rows ->
        rows.map { it.toRelayProfile() }
    }
    val defaultRelayId: Flow<String> = relaySettingsStore.defaultRelayId

    suspend fun ensureDefaults() {
        relayDao.upsert(officialRelay.toEntity(createdAt = System.currentTimeMillis()))
        runCatching {
            relayDao.upsert(apiProvider.officialApi().officialRelayDescriptor().toRelayProfile().toEntity())
        }
    }

    suspend fun syncRelays(): AppResult<Unit> = runCatching {
        val response = apiProvider.withActiveApi { it.relays() }
        response.relays.forEach { relayDao.upsert(it.toRelayProfile().toEntity()) }
    }.fold(
        onSuccess = { AppResult.Ok(Unit) },
        onFailure = { AppResult.Err(it.toUserVisibleError("Relais non synchronisés")) },
    )

    suspend fun upsertRemoteRelay(relay: RelayDto): RelayProfile {
        val profile = relay.toRelayProfile()
        relayDao.upsert(profile.toEntity())
        return profile
    }

    suspend fun addCustomRelay(
        name: String,
        url: String,
        type: RelayType = RelayType.PRIVATE,
    ): RelayProfile {
        val normalized = RelayUrlPolicy.validate(url, cleartextAllowed).normalizedUrl
            ?: error("Invalid relay URL")
        val localRelay = RelayProfile(
            id = UUID.randomUUID().toString(),
            name = name.trim().ifBlank { "Relais privé" },
            url = normalized,
            publicKey = null,
            type = type,
            trustState = RelayTrustState.UNVERIFIED,
            isOfficial = false,
            regionLabel = null,
            connected = false,
        )
        val relay = runCatching {
            apiProvider.withActiveApi {
                it.createCustomRelay(
                    CreateCustomRelayRequestDto(
                        name = localRelay.name,
                        url = localRelay.url,
                        relayType = type.name,
                        publicKey = localRelay.publicKey,
                    ),
                )
            }.toRelayProfile()
        }.getOrElse { localRelay }
        relayDao.upsert(relay.toEntity(createdAt = System.currentTimeMillis()))
        return relay
    }

    suspend fun useOfficialRelay() {
        relaySettingsStore.useOfficialRelay()
    }

    suspend fun saveDefaultRelay(relayId: String) {
        if (relayId != OfficialRelayResolver.OFFICIAL_RELAY_ID) {
            requireNotNull(relayDao.findRelay(relayId)) { "Unknown relay" }
        }
        relaySettingsStore.saveDefaultRelay(relayId)
    }

    suspend fun relayById(relayId: String): RelayProfile? =
        relayDao.findRelay(relayId)?.toRelayProfile()

    private fun RelayEntity.toRelayProfile(): RelayProfile =
        RelayProfile(
            id = id,
            name = if (isOfficial) OfficialRelayResolver.OFFICIAL_RELAY_NAME else name,
            url = url,
            publicKey = publicKey,
            type = RelayType.valueOf(type),
            trustState = RelayTrustState.valueOf(trustState),
            isOfficial = isOfficial,
            regionLabel = if (isOfficial) OfficialRelayResolver.OFFICIAL_REGION_LABEL else null,
            connected = isOfficial,
        )

    private fun RelayDto.toRelayProfile(): RelayProfile =
        RelayProfile(
            id = id,
            name = if (isOfficial) OfficialRelayResolver.OFFICIAL_RELAY_NAME else name,
            url = url,
            publicKey = publicKey,
            type = RelayType.valueOf(type),
            trustState = RelayTrustState.valueOf(trustLevel),
            isOfficial = isOfficial,
            regionLabel = region,
            connected = isOfficial,
        )

    private fun RelayProfile.toEntity(): RelayEntity =
        toEntity(createdAt = System.currentTimeMillis())

    private fun RelayProfile.toEntity(createdAt: Long): RelayEntity =
        RelayEntity(
            id = id,
            name = name,
            url = url,
            publicKey = publicKey,
            type = type.name,
            trustState = trustState.name,
            isOfficial = isOfficial,
            createdAt = createdAt,
            lastSeenAt = if (connected) createdAt else null,
        )
}
