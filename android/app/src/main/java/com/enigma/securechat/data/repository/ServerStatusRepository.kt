package com.enigma.securechat.data.repository

import com.enigma.securechat.domain.model.AppResult
import com.enigma.securechat.network.RelayScopedApiProvider
import com.enigma.securechat.network.toUserVisibleError

data class ServerStatus(
    val status: String,
    val name: String,
    val version: String,
)

class ServerStatusRepository(
    private val apiProvider: RelayScopedApiProvider,
) {
    suspend fun check(): AppResult<ServerStatus> = runCatching {
        val health = apiProvider.withActiveApi { it.health() }
        val version = apiProvider.withActiveApi { it.version() }
        ServerStatus(
            status = health.status,
            name = version.name,
            version = version.version,
        )
    }.fold(
        onSuccess = { AppResult.Ok(it) },
        onFailure = { AppResult.Err(it.toUserVisibleError("Serveur indisponible")) },
    )
}
