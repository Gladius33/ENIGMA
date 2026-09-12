package com.enigma.securechat.data.repository

import com.enigma.securechat.crypto.CryptoEngine
import com.enigma.securechat.data.mapper.toDto
import com.enigma.securechat.domain.model.AppResult
import com.enigma.securechat.domain.model.DeviceRegistration
import com.enigma.securechat.domain.model.UserVisibleError
import com.enigma.securechat.multidevice.AuthorizedDesktopLink
import com.enigma.securechat.multidevice.DesktopLinkCandidate
import com.enigma.securechat.multidevice.DeviceLinkAuthorization
import com.enigma.securechat.network.ChatApiService
import com.enigma.securechat.network.dto.AuthorizeLinkedDesktopRequestDto
import com.enigma.securechat.network.dto.DeviceRegisterRequestDto
import com.enigma.securechat.network.dto.FcmTokenRequestDto
import com.enigma.securechat.storage.DeviceStore
import com.enigma.securechat.storage.SecureSessionStore
import java.util.Base64
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


    suspend fun authorizeLinkedDesktop(
        candidate: DesktopLinkCandidate,
        issuedAtUnixMs: Long = System.currentTimeMillis(),
    ): AppResult<AuthorizedDesktopLink> = runCatching {
        val session = requireNotNull(sessionStore.session.firstOrNull()) {
            "Session is required before linking a desktop"
        }
        val authorizingDeviceId = requireNotNull(deviceStore.deviceId()) {
            "Android device is not registered"
        }
        DeviceLinkAuthorization.validateCandidate(candidate, authorizingDeviceId)

        val authorizerIdentityKey = cryptoEngine.ensureIdentity().identityPublicKey
        val canonicalPayload = DeviceLinkAuthorization.canonicalPayload(
            accountId = session.userId,
            newDeviceId = candidate.deviceId,
            authorizingDeviceId = authorizingDeviceId,
            pairingSessionId = candidate.pairingSessionId,
            platform = candidate.platform,
            protocolVersion = candidate.protocolVersion,
            minSupportedVersion = candidate.minSupportedVersion,
            capabilities = candidate.capabilities,
            issuedAtUnixMs = issuedAtUnixMs,
            targetIdentityKey = candidate.targetIdentityKey,
            authorizerIdentityKey = authorizerIdentityKey,
        )
        val signatureBytes = cryptoEngine.signIdentityProof(
            canonicalPayload.toByteArray(Charsets.UTF_8),
        )
        val signature = try {
            Base64.getEncoder().withoutPadding().encodeToString(signatureBytes)
        } finally {
            signatureBytes.fill(0)
        }

        val response = api.authorizeLinkedDesktop(
            AuthorizeLinkedDesktopRequestDto(
                deviceId = candidate.deviceId,
                displayName = candidate.displayName,
                platform = candidate.platform,
                pairingSessionId = candidate.pairingSessionId,
                protocolVersion = candidate.protocolVersion,
                minSupportedVersion = candidate.minSupportedVersion,
                capabilities = candidate.capabilities,
                issuedAtUnixMs = issuedAtUnixMs,
                targetIdentityKey = candidate.targetIdentityKey,
                authorizerSignature = signature,
            ),
        )

        val proof = requireNotNull(response.device.authorization) {
            "Server omitted desktop authorization proof"
        }
        require(response.device.id == candidate.deviceId) {
            "Server returned a different desktop device id"
        }
        require(proof.authorizingDeviceId == authorizingDeviceId) {
            "Server returned a different authorizing device"
        }
        require(proof.canonicalPayload == canonicalPayload) {
            "Server altered the signed device authorization transcript"
        }
        require(proof.authorizerSignature == signature) {
            "Server altered the device authorization signature"
        }

        AuthorizedDesktopLink(
            deviceId = response.device.id,
            displayName = response.device.displayName,
            platform = response.device.platform,
            accessToken = response.accessToken,
            canonicalPayload = proof.canonicalPayload,
            authorizerSignature = proof.authorizerSignature,
        )
    }.fold(
        onSuccess = { AppResult.Ok(it) },
        onFailure = {
            AppResult.Err(
                UserVisibleError(
                    message = "Autorisation du poste impossible",
                    errorCode = "DESKTOP_LINK_AUTHORIZATION_FAILED",
                ),
            )
        },
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
