package com.enigma.securechat.data.repository

import com.enigma.securechat.crypto.CryptoEngine
import com.enigma.securechat.data.mapper.toDto
import com.enigma.securechat.domain.model.AppResult
import com.enigma.securechat.domain.model.DeviceRegistration
import com.enigma.securechat.domain.model.UserVisibleError
import com.enigma.securechat.network.ChatApiService
import com.enigma.securechat.network.dto.DeviceRegisterRequestDto
import com.enigma.securechat.network.dto.FcmTokenRequestDto
import com.enigma.securechat.storage.DeviceStore
import com.enigma.securechat.storage.SecureSessionStore
import kotlinx.coroutines.flow.firstOrNull

class DeviceRepository(
    private val api: ChatApiService,
    private val cryptoEngine: CryptoEngine,
    private val deviceStore: DeviceStore,
    private val sessionStore: SecureSessionStore,
) {
    suspend fun ensureRegistered(displayName: String): AppResult<DeviceRegistration> = runCatching {
        deviceStore.deviceId()?.let { existing ->
            replenishPreKeysIfNeeded(existing)
            return@runCatching DeviceRegistration(deviceId = existing, displayName = displayName)
        }

        cryptoEngine.ensureIdentity()
        val response = api.registerDevice(DeviceRegisterRequestDto(displayName = displayName))
        val deviceId = response.device.id
        deviceStore.saveDeviceId(deviceId)
        val currentSession = requireNotNull(sessionStore.session.firstOrNull()) {
            "Session is required before device registration"
        }
        sessionStore.saveSession(currentSession.copy(accessToken = response.accessToken))

        val preKeys = cryptoEngine.createPreKeyUpload(deviceId)
        api.uploadKeys(preKeys.toDto())
        replenishPreKeysIfNeeded(deviceId)

        DeviceRegistration(
            deviceId = deviceId,
            displayName = response.device.displayName,
            platform = response.device.platform,
        )
    }.fold(
        onSuccess = { AppResult.Ok(it) },
        onFailure = { AppResult.Err(UserVisibleError("Enregistrement appareil impossible")) },
    )

    suspend fun updateFcmToken(token: String): AppResult<Unit> = runCatching {
        api.updateFcmToken(FcmTokenRequestDto(fcmToken = token))
    }.fold(
        onSuccess = { AppResult.Ok(Unit) },
        onFailure = { AppResult.Err(UserVisibleError("Notifications non synchronisées")) },
    )

    suspend fun replenishPreKeys(): AppResult<Unit> = runCatching {
        val deviceId = requireNotNull(deviceStore.deviceId()) { "Device is not registered" }
        replenishPreKeysIfNeeded(deviceId)
    }.fold(
        onSuccess = { AppResult.Ok(Unit) },
        onFailure = { AppResult.Err(UserVisibleError("Pré-clés non synchronisées")) },
    )

    private suspend fun replenishPreKeysIfNeeded(deviceId: String) {
        val status = api.keyStatus()
        if (!status.prekeyLow) return
        val uploadCount = status.recommendedUploadCount
            .coerceAtLeast(1)
            .coerceAtMost(status.maxUploadCount.coerceAtLeast(1))
        val preKeys = cryptoEngine.createPreKeyUpload(deviceId, oneTimePreKeyCount = uploadCount)
        api.uploadKeys(preKeys.toDto())
    }
}
