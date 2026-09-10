package com.enigma.securechat.network.dto

data class HealthResponseDto(
    val status: String,
)

data class VersionResponseDto(
    val name: String,
    val version: String,
)
