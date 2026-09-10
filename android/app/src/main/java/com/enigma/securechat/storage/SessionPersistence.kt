package com.enigma.securechat.storage

import com.enigma.securechat.domain.model.UserSession

interface SessionPersistence {
    suspend fun saveSession(value: UserSession)
    suspend fun clearSession()
}

