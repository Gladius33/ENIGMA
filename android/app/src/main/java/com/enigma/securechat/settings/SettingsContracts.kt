package com.enigma.securechat.settings

data class SecuritySettings(
    val requireLocalUnlock: Boolean = true,
    val highSecurityMode: Boolean = false,
    val blockScreenshots: Boolean = false,
    val wipeAfterFailuresEnabled: Boolean = false,
    val wipeAfterFailuresCount: Int = 10,
)
