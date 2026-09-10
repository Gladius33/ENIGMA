package com.enigma.securechat.network

import com.enigma.securechat.data.db.RelayTrustState
import com.enigma.securechat.data.db.RelayType
import com.enigma.securechat.data.repository.RelayProfile

object OfficialRelayResolver {
    /**
     * Stable public identifier shared with the Rust server, QR payloads, local seed data and tests.
     */
    const val OFFICIAL_RELAY_ID: String = "00000000-0000-0000-0000-000000000001"
    const val OFFICIAL_RELAY_NAME: String = "Relais officiel Enigma"
    const val OFFICIAL_REGION_LABEL: String = "automatique"

    fun resolve(
        defaultBaseUrl: String,
        cleartextAllowed: Boolean,
    ): RelayProfile {
        val normalized = RelayUrlPolicy.validate(defaultBaseUrl, cleartextAllowed).normalizedUrl
            ?: error("Official relay URL is invalid for this build")
        return RelayProfile(
            id = OFFICIAL_RELAY_ID,
            name = OFFICIAL_RELAY_NAME,
            url = normalized,
            publicKey = null,
            type = RelayType.OFFICIAL,
            trustState = RelayTrustState.VERIFIED,
            isOfficial = true,
            regionLabel = OFFICIAL_REGION_LABEL,
            connected = true,
        )
    }
}
