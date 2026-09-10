package com.enigma.securechat.sync

interface SyncCoordinator {
    suspend fun syncDirect()
    suspend fun syncGroups()
    suspend fun syncChannels()
}
