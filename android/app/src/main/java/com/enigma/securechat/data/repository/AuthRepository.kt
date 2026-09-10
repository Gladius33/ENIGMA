package com.enigma.securechat.data.repository

import com.enigma.securechat.domain.model.AppResult
import com.enigma.securechat.domain.model.UserSession
import com.enigma.securechat.network.ChatApiService
import com.enigma.securechat.network.toUserVisibleError
import com.enigma.securechat.network.dto.AuthRequestDto
import com.enigma.securechat.storage.SessionPersistence

class AuthRepository(
    private val api: ChatApiService,
    private val sessionStore: SessionPersistence,
) {
    suspend fun register(publicId: String, password: String): AppResult<UserSession> =
        authenticate { api.register(AuthRequestDto(publicId, password)) }

    suspend fun login(publicId: String, password: String): AppResult<UserSession> =
        authenticate { api.login(AuthRequestDto(publicId, password)) }

    suspend fun logout() {
        sessionStore.clearSession()
    }

    private suspend fun authenticate(
        call: suspend () -> com.enigma.securechat.network.dto.AuthResponseDto,
    ): AppResult<UserSession> = runCatching {
        val response = call()
        UserSession(
            userId = response.user.id,
            publicId = response.user.publicId,
            accessToken = response.accessToken,
        ).also { sessionStore.saveSession(it) }
    }.fold(
        onSuccess = { AppResult.Ok(it) },
        onFailure = { AppResult.Err(it.toUserVisibleError("Authentification impossible")) },
    )
}
