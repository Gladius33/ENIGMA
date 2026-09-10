package com.enigma.securechat.storage

import android.content.Context
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import com.enigma.securechat.network.OfficialRelayResolver
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map

private val Context.relaySettingsDataStore by preferencesDataStore(name = "relay_settings_v1")

class RelaySettingsStore(
    private val context: Context,
) {
    val defaultRelayId: Flow<String> = context.relaySettingsDataStore.data.map {
        it[DEFAULT_RELAY_ID] ?: OfficialRelayResolver.OFFICIAL_RELAY_ID
    }
    val activeBubbleId: Flow<String> = context.relaySettingsDataStore.data.map {
        it[ACTIVE_BUBBLE_ID] ?: DEFAULT_MAIN_BUBBLE_ID
    }

    suspend fun useOfficialRelay() {
        context.relaySettingsDataStore.edit { it[DEFAULT_RELAY_ID] = OfficialRelayResolver.OFFICIAL_RELAY_ID }
    }

    suspend fun saveDefaultRelay(relayId: String) {
        context.relaySettingsDataStore.edit { it[DEFAULT_RELAY_ID] = relayId }
    }

    suspend fun saveActiveBubble(bubbleId: String) {
        context.relaySettingsDataStore.edit { it[ACTIVE_BUBBLE_ID] = bubbleId }
    }

    companion object {
        const val DEFAULT_MAIN_BUBBLE_ID: String = "main-bubble"
        private val DEFAULT_RELAY_ID = stringPreferencesKey("default_relay_id")
        private val ACTIVE_BUBBLE_ID = stringPreferencesKey("active_bubble_id")
    }
}
