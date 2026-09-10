package com.enigma.securechat.security

import com.enigma.securechat.BuildConfig
import com.enigma.securechat.crypto.CryptoEngine
import com.enigma.securechat.crypto.SignalCryptoEngine

object ReleaseCryptoGuard {
    fun requireSignalCrypto(engine: CryptoEngine) {
        check(BuildConfig.DEBUG || engine is SignalCryptoEngine) {
            "Release builds require SignalCryptoEngine/libsignal."
        }
    }
}
