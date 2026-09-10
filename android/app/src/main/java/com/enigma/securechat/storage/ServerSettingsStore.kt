package com.enigma.securechat.storage

import android.content.Context
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map

private val Context.serverSettingsDataStore by preferencesDataStore(name = "server_settings_v1")

class ServerSettingsStore(
    private val context: Context,
) {
    val language: Flow<String> = context.serverSettingsDataStore.data.map { it[LANGUAGE] ?: "fr" }
    val highSecurityMode: Flow<Boolean> = context.serverSettingsDataStore.data.map {
        it[HIGH_SECURITY_MODE] ?: false
    }

    suspend fun saveLanguage(value: String) {
        val normalized = if (value == "en") "en" else "fr"
        context.serverSettingsDataStore.edit { it[LANGUAGE] = normalized }
    }

    suspend fun saveHighSecurityMode(enabled: Boolean) {
        context.serverSettingsDataStore.edit { it[HIGH_SECURITY_MODE] = enabled }
    }

    private companion object {
        val LANGUAGE = stringPreferencesKey("language")
        val HIGH_SECURITY_MODE = booleanPreferencesKey("high_security_mode")
    }
}
