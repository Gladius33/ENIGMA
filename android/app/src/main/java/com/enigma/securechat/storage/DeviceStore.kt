package com.enigma.securechat.storage

import android.content.Context
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import kotlinx.coroutines.flow.firstOrNull
import kotlinx.coroutines.flow.map

private val Context.deviceDataStore by preferencesDataStore(name = "device_v1")

interface DevicePersistence {
    suspend fun saveDeviceId(deviceId: String)
    suspend fun deviceId(): String?
    suspend fun clearDeviceId()
}

class DeviceStore(
    private val context: Context,
    private val localCipher: LocalCipher,
) : DevicePersistence {
    override suspend fun saveDeviceId(deviceId: String) {
        context.deviceDataStore.edit {
            it[DEVICE_ID] = localCipher.encryptToString(deviceId.toByteArray(Charsets.UTF_8))
        }
    }

    override suspend fun deviceId(): String? {
        val encrypted = context.deviceDataStore.data.map { it[DEVICE_ID] }.firstOrNull() ?: return null
        return localCipher.decryptFromString(encrypted).toString(Charsets.UTF_8)
    }

    override suspend fun clearDeviceId() {
        context.deviceDataStore.edit { it.remove(DEVICE_ID) }
    }

    private companion object {
        val DEVICE_ID = stringPreferencesKey("device_id")
    }
}
