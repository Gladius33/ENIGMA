package com.enigma.securechat.data.repository

import com.enigma.securechat.crypto.SignalRecordStorage
import com.enigma.securechat.data.db.AppDatabase
import com.enigma.securechat.p2p.P2pAttachmentCommitOutboxStore
import com.enigma.securechat.p2p.P2pReceiptOutboxStore
import com.enigma.securechat.storage.DevicePersistence
import com.enigma.securechat.storage.SecureFileStore
import com.enigma.securechat.storage.SecureSessionStore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

fun interface AccountDataPurger {
    suspend fun purgeAccountData()
}

class LocalAccountDataPurger(
    private val database: AppDatabase,
    private val sessionStore: SecureSessionStore,
    private val deviceStore: DevicePersistence,
    private val signalRecordStorage: SignalRecordStorage,
    private val fileStore: SecureFileStore,
    private val p2pReceiptOutboxStore: P2pReceiptOutboxStore,
    private val p2pAttachmentCommitOutboxStore: P2pAttachmentCommitOutboxStore,
) : AccountDataPurger {
    override suspend fun purgeAccountData() {
        val errors = mutableListOf<Throwable>()
        withContext(Dispatchers.IO) {
            runCatching { database.clearAllTables() }.onFailure { errors.add(it) }
            runCatching { signalRecordStorage.clearAll() }.onFailure { errors.add(it) }
            runCatching { fileStore.clearEncryptedAttachments() }.onFailure { errors.add(it) }
            runCatching { p2pReceiptOutboxStore.clear() }.onFailure { errors.add(it) }
            runCatching { p2pAttachmentCommitOutboxStore.clear() }.onFailure { errors.add(it) }
        }
        runCatching { sessionStore.clearAccountData() }.onFailure { errors.add(it) }
        runCatching { deviceStore.clearDeviceId() }.onFailure { errors.add(it) }

        if (errors.isNotEmpty()) {
            throw IllegalStateException("LOCAL_ACCOUNT_PURGE_FAILED").also { failure ->
                errors.forEach(failure::addSuppressed)
            }
        }
    }
}
