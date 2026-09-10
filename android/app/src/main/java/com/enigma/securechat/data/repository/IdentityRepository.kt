package com.enigma.securechat.data.repository

import com.enigma.securechat.crypto.CryptoEngine
import com.enigma.securechat.crypto.RecoverySecretVerifier
import com.enigma.securechat.crypto.KyberPreKeyUpload
import com.enigma.securechat.domain.model.AppResult
import com.enigma.securechat.domain.model.UserSession
import com.enigma.securechat.network.ChatApiService
import com.enigma.securechat.network.toUserVisibleError
import com.enigma.securechat.network.dto.CreateIdentityRequestDto
import com.enigma.securechat.data.mapper.toDto
import com.enigma.securechat.network.dto.KyberPreKeyDto
import com.enigma.securechat.network.dto.RecoverCompleteRequestDto
import com.enigma.securechat.network.dto.RecoverStartRequestDto
import com.enigma.securechat.storage.DevicePersistence
import com.enigma.securechat.storage.SessionPersistence
import java.util.UUID

data class CreatedIdentitySession(
    val session: UserSession,
    val recoverySecret: String,
)

class IdentityRepository(
    private val api: ChatApiService,
    private val cryptoEngine: CryptoEngine,
    private val deviceStore: DevicePersistence,
    private val sessionStore: SessionPersistence,
    private val accountDataPurger: AccountDataPurger = AccountDataPurger {
        sessionStore.clearSession()
        deviceStore.clearDeviceId()
    },
) {
    suspend fun checkHandle(handle: String): AppResult<Boolean> = runCatching {
        api.checkIdentity(handle).available
    }.fold(
        onSuccess = { AppResult.Ok(it) },
        onFailure = { AppResult.Err(it.toUserVisibleError("Vérification d'identité impossible")) },
    )

    suspend fun createIdentity(
        handle: String,
        password: String,
        deviceName: String,
    ): AppResult<CreatedIdentitySession> = runCatching {
        val localIdentity = cryptoEngine.ensureIdentity()
        val bootstrapPreKeys = cryptoEngine.createPreKeyUpload(UUID.randomUUID().toString(), oneTimePreKeyCount = 1)
        val recovery = RecoverySecretVerifier.generate()
        val response = api.createIdentity(
            CreateIdentityRequestDto(
                displayName = handle,
                password = password,
                identityPublicKey = localIdentity.identityPublicKey,
                registrationId = bootstrapPreKeys.registrationId,
                protocolDeviceId = bootstrapPreKeys.protocolDeviceId,
                signedPrekeyId = bootstrapPreKeys.signedPreKey.keyId,
                signedPrekey = bootstrapPreKeys.signedPreKey.publicKey,
                signedPrekeySignature = bootstrapPreKeys.signedPreKey.signature,
                kyberPrekey = bootstrapPreKeys.kyberPreKey?.toDto(),
                oneTimePrekeys = emptyList(),
                deviceName = deviceName,
                devicePublicKey = localIdentity.identityPublicKey,
                recoveryKeyVerifier = recovery.verifier,
            ),
        )
        deviceStore.saveDeviceId(response.deviceId)
        val session = UserSession(
            userId = response.identityId,
            publicId = response.canonicalHandle,
            accessToken = response.accessToken,
        )
        sessionStore.saveSession(session)
        api.uploadKeys(cryptoEngine.createPreKeyUpload(response.deviceId).toDto())
        CreatedIdentitySession(session, recovery.secret)
    }.fold(
        onSuccess = { AppResult.Ok(it) },
        onFailure = { AppResult.Err(it.toUserVisibleError("Création d'identité impossible")) },
    )

    suspend fun recoverIdentity(
        handle: String,
        recoverySecret: String,
        deviceName: String,
    ): AppResult<UserSession> = runCatching {
        val start = api.recoverStart(RecoverStartRequestDto(handle.trim()))
        check(start.recoveryConfigured) { "RECOVERY_NOT_CONFIGURED" }
        val localIdentity = cryptoEngine.ensureIdentity()
        val bootstrapPreKeys = cryptoEngine.createPreKeyUpload(UUID.randomUUID().toString(), oneTimePreKeyCount = 1)
        val response = api.recoverComplete(
            RecoverCompleteRequestDto(
                handle = handle.trim(),
                recoverySecret = recoverySecret.trim(),
                identityPublicKey = localIdentity.identityPublicKey,
                registrationId = bootstrapPreKeys.registrationId,
                protocolDeviceId = bootstrapPreKeys.protocolDeviceId,
                signedPrekeyId = bootstrapPreKeys.signedPreKey.keyId,
                signedPrekey = bootstrapPreKeys.signedPreKey.publicKey,
                signedPrekeySignature = bootstrapPreKeys.signedPreKey.signature,
                kyberPrekey = bootstrapPreKeys.kyberPreKey?.toDto(),
                oneTimePrekeys = emptyList(),
                deviceName = deviceName,
                devicePublicKey = localIdentity.identityPublicKey,
            ),
        )
        deviceStore.saveDeviceId(response.deviceId)
        UserSession(
            userId = response.identityId,
            publicId = response.canonicalHandle,
            accessToken = response.accessToken,
        ).also {
            sessionStore.saveSession(it)
            api.uploadKeys(cryptoEngine.createPreKeyUpload(response.deviceId).toDto())
        }
    }.fold(
        onSuccess = { AppResult.Ok(it) },
        onFailure = { AppResult.Err(it.toUserVisibleError("Récupération impossible ou secret invalide")) },
    )

    suspend fun deleteMe(): AppResult<Unit> = runCatching {
        api.deleteIdentity()
        accountDataPurger.purgeAccountData()
    }.fold(
        onSuccess = { AppResult.Ok(Unit) },
        onFailure = { AppResult.Err(it.toUserVisibleError("Suppression impossible")) },
    )

    private fun KyberPreKeyUpload.toDto(): KyberPreKeyDto = KyberPreKeyDto(
        keyId = keyId,
        publicKey = publicKey,
        signature = signature,
    )
}
