package com.enigma.securechat.storage

import android.content.Context
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import com.enigma.securechat.domain.model.UserSession
import com.squareup.moshi.Moshi
import com.squareup.moshi.kotlin.reflect.KotlinJsonAdapterFactory
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.firstOrNull
import kotlinx.coroutines.flow.map

private val Context.secureDataStore by preferencesDataStore(name = "secure_session_v1")

class SecureSessionStore(
    private val context: Context,
    private val localCipher: LocalCipher,
) : SessionPersistence, RelaySessionPersistence {
    private val moshi = Moshi.Builder().add(KotlinJsonAdapterFactory()).build()
    private val sessionAdapter = moshi.adapter(UserSession::class.java)
    private val relaySessionsAdapter = moshi.adapter(RelaySessionsEnvelope::class.java)
    private val random = SecureRandom()

    val session: Flow<UserSession?> = context.secureDataStore.data.map { preferences ->
        preferences[SESSION]?.let { encrypted ->
            runCatching {
                val json = localCipher.decryptFromString(encrypted).toString(Charsets.UTF_8)
                sessionAdapter.fromJson(json)
            }.getOrNull()
        }
    }

    override suspend fun saveSession(value: UserSession) {
        val json = sessionAdapter.toJson(value).toByteArray(Charsets.UTF_8)
        val encrypted = localCipher.encryptToString(json)
        json.fill(0)
        context.secureDataStore.edit { it[SESSION] = encrypted }
    }

    suspend fun accessToken(): String? = session.firstOrNull()?.accessToken

    override suspend fun saveRelaySession(baseUrl: String, value: UserSession) {
        require(baseUrl.isNotBlank())
        val next = relaySessions() + (baseUrl to value)
        saveRelaySessions(next)
    }

    override suspend fun relayAccessToken(baseUrl: String): String? =
        relaySessions()[baseUrl]?.accessToken

    override suspend fun clearRelaySession(baseUrl: String) {
        val next = relaySessions() - baseUrl
        saveRelaySessions(next)
    }

    override suspend fun clearSession() {
        context.secureDataStore.edit {
            it.remove(SESSION)
            it.remove(RELAY_SESSIONS)
        }
    }

    suspend fun clearAccountData() {
        context.secureDataStore.edit {
            it.remove(SESSION)
            it.remove(RELAY_SESSIONS)
            it.remove(PIN_HASH)
        }
    }

    suspend fun setLocalPin(pin: CharArray) {
        require(pin.size in 4..12)
        val salt = ByteArray(16).also(random::nextBytes)
        val hash = pbkdf2(pin, salt)
        val encoded = "v1:${encode(salt)}:${encode(hash)}"
        context.secureDataStore.edit { it[PIN_HASH] = localCipher.encryptToString(encoded.toByteArray()) }
        salt.fill(0)
        hash.fill(0)
        pin.fill('\u0000')
    }

    suspend fun hasLocalPin(): Boolean =
        context.secureDataStore.data.map { it[PIN_HASH] != null }.firstOrNull() == true

    suspend fun verifyLocalPin(pin: CharArray): Boolean {
        val encrypted = context.secureDataStore.data.map { it[PIN_HASH] }.firstOrNull() ?: return false
        val encoded = localCipher.decryptFromString(encrypted).toString(Charsets.UTF_8)
        val parts = encoded.split(":")
        if (parts.size != 3 || parts[0] != "v1") return false
        val salt = decode(parts[1])
        val expected = decode(parts[2])
        val actual = pbkdf2(pin, salt)
        val ok = expected.contentEquals(actual)
        salt.fill(0)
        expected.fill(0)
        actual.fill(0)
        pin.fill('\u0000')
        return ok
    }

    private fun pbkdf2(pin: CharArray, salt: ByteArray): ByteArray {
        val spec = PBEKeySpec(pin, salt, 120_000, 256)
        return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).encoded
    }

    private fun encode(bytes: ByteArray): String =
        Base64.getEncoder().withoutPadding().encodeToString(bytes)

    private fun decode(value: String): ByteArray =
        Base64.getDecoder().decode(value)

    private suspend fun relaySessions(): Map<String, UserSession> =
        context.secureDataStore.data.map { preferences ->
            preferences[RELAY_SESSIONS]?.let { encrypted ->
                runCatching {
                    val json = localCipher.decryptFromString(encrypted).toString(Charsets.UTF_8)
                    relaySessionsAdapter.fromJson(json)?.sessions.orEmpty()
                }.getOrNull()
            }.orEmpty()
        }.firstOrNull().orEmpty()

    private suspend fun saveRelaySessions(value: Map<String, UserSession>) {
        val json = relaySessionsAdapter.toJson(RelaySessionsEnvelope(value)).toByteArray(Charsets.UTF_8)
        val encrypted = localCipher.encryptToString(json)
        json.fill(0)
        context.secureDataStore.edit { preferences ->
            if (value.isEmpty()) {
                preferences.remove(RELAY_SESSIONS)
            } else {
                preferences[RELAY_SESSIONS] = encrypted
            }
        }
    }

    private data class RelaySessionsEnvelope(
        val sessions: Map<String, UserSession> = emptyMap(),
    )

    private companion object {
        val SESSION = stringPreferencesKey("session")
        val RELAY_SESSIONS = stringPreferencesKey("relay_sessions")
        val PIN_HASH = stringPreferencesKey("pin_hash")
    }
}

interface RelaySessionPersistence {
    suspend fun saveRelaySession(baseUrl: String, value: UserSession)
    suspend fun relayAccessToken(baseUrl: String): String?
    suspend fun clearRelaySession(baseUrl: String)
}
