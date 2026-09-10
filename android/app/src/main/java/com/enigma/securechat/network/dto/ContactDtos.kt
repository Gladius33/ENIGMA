package com.enigma.securechat.network.dto

import com.squareup.moshi.Json

data class AddContactRequestDto(
    @Json(name = "contact_user_id") val contactUserId: String,
)

data class ContactDto(
    @Json(name = "user_id") val userId: String,
    @Json(name = "public_id") val publicId: String,
    @Json(name = "created_at") val createdAt: String,
)

data class ContactsResponseDto(
    val contacts: List<ContactDto>,
)
