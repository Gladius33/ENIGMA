package com.enigma.securechat.data.repository

import com.enigma.securechat.crypto.CryptoEngine
import com.enigma.securechat.data.mapper.toDto
import com.enigma.securechat.domain.model.AppResult
import com.enigma.securechat.domain.model.UserSession
import com.enigma.securechat.network.RelayScopedApiProvider
import com.enigma.securechat.network.dto.AuthRequestDto
import com.enigma.securechat.network.dto.DeviceRegisterRequestDto
import com.enigma.securechat.network.toUserVisibleError
import com.enigma.securechat.storage.DevicePersistence
import com.enigma.securechat.storage.RelaySessionPersistence

data class RelayPrivateSessionStatus(
    val baseUrl: String,
    val publicId: String,
    val deviceId: String,
)

class RelaySessionRepository(
    private val apiProvider: RelayScopedApiProvider,
    private val sessionStore: RelaySessionPersistence,
    private val deviceStore: DevicePersistence,
    private val cryptoEngine: CryptoEngine,
) {
    suspend fun signInActivePrivateRelay(
        publicId: String,
        password: String,
        deviceName: String,
    ): AppResult<RelayPrivateSessionStatus> = runCatching {
        val endpoint = apiProvider.activeEndpoint.value
        val baseUrl = requireNotNull(endpoint.primaryBaseUrl) { "Private relay unavailable" }
        require(endpoint.requiresDedicatedSession) { "Active relay does not require a private session" }
        val localDeviceId = requireNotNull(deviceStore.deviceId()) {
            "Register this device on the official relay first"
        }
        val api = apiProvider.sessionSetupApi(baseUrl)
        try {
            val login = api.login(AuthRequestDto(publicId.trim(), password))
            val bootstrapSession = UserSession(
                userId = login.user.id,
                publicId = login.user.publicId,
                accessToken = login.accessToken,
            )
            sessionStore.saveRelaySession(baseUrl, bootstrapSession)

            val device = api.registerDevice(
                DeviceRegisterRequestDto(
                    displayName = deviceName.trim().ifBlank { "Android" },
                    deviceId = localDeviceId,
                ),
            )
            val deviceSession = bootstrapSession.copy(accessToken = device.accessToken)
            sessionStore.saveRelaySession(baseUrl, deviceSession)
            api.uploadKeys(cryptoEngine.createPreKeyUpload(localDeviceId).toDto())

            RelayPrivateSessionStatus(
                baseUrl = baseUrl,
                publicId = deviceSession.publicId,
                deviceId = localDeviceId,
            )
        } catch (error: Throwable) {
            sessionStore.clearRelaySession(baseUrl)
            throw error
        }
    }.fold(
        onSuccess = { AppResult.Ok(it) },
        onFailure = { AppResult.Err(it.toUserVisibleError("Connexion relais privé impossible")) },
    )

    suspend fun signOutActivePrivateRelay(): AppResult<Unit> = runCatching {
        val baseUrl = requireNotNull(apiProvider.activeEndpoint.value.primaryBaseUrl) {
            "Private relay unavailable"
        }
        sessionStore.clearRelaySession(baseUrl)
    }.fold(
        onSuccess = { AppResult.Ok(Unit) },
        onFailure = { AppResult.Err(it.toUserVisibleError("Session relais privé non supprimée")) },
    )
}
