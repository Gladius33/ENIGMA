package com.enigma.securechat.network

import android.util.Log

object SafeLog {
    fun info(tag: String, message: String) {
        runCatching { Log.i(tag, message) }
    }

    fun warn(tag: String, message: String, throwable: Throwable? = null) {
        runCatching { Log.w(tag, message, throwable) }
    }

    fun redactedId(value: String?): String =
        value?.take(6)?.plus("...") ?: "null"
}
