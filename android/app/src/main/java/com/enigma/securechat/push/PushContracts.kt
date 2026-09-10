package com.enigma.securechat.push

data class PushEvent(
    val type: String,
    val objectId: String?,
)
