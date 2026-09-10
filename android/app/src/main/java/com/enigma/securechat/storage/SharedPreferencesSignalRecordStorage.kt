package com.enigma.securechat.storage

import android.content.Context
import com.enigma.securechat.crypto.SignalRecordStorage

class SharedPreferencesSignalRecordStorage(
    context: Context,
    private val localCipher: LocalCipher,
) : SignalRecordStorage {
    private val preferences = context.getSharedPreferences(STORE_NAME, Context.MODE_PRIVATE)

    override fun read(key: String): ByteArray? =
        preferences.getString(key, null)?.let(localCipher::decryptFromString)

    override fun write(key: String, value: ByteArray) {
        val encrypted = localCipher.encryptToString(value)
        preferences.edit().putString(key, encrypted).apply()
    }

    override fun remove(key: String) {
        preferences.edit().remove(key).apply()
    }

    override fun keys(prefix: String): List<String> =
        preferences.all.keys.filter { it.startsWith(prefix) }

    override fun clearAll() {
        preferences.edit().clear().commit()
    }

    private companion object {
        const val STORE_NAME = "signal_protocol_store_v1"
    }
}
