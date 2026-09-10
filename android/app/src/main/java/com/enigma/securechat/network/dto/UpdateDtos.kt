package com.enigma.securechat.network.dto

import com.squareup.moshi.Json

data class AndroidReleaseResponseDto(
    val platform: String,
    val channel: String,
    @Json(name = "latest_version_name") val latestVersionName: String,
    @Json(name = "latest_version_code") val latestVersionCode: Long,
    @Json(name = "apk_url") val apkUrl: String,
    val sha256: String,
    val signature: String?,
    val mandatory: Boolean,
    @Json(name = "release_notes") val releaseNotes: ReleaseNotesDto,
)

data class ReleaseNotesDto(
    val fr: String,
    val en: String,
)
