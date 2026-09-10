package com.enigma.securechat.domain.model

import java.time.Instant

data class UserSession(
    val userId: String,
    val publicId: String,
    val accessToken: String,
)

data class DeviceRegistration(
    val deviceId: String,
    val displayName: String,
    val platform: String = "android",
)

data class Contact(
    val userId: String,
    val publicId: String,
    val displayName: String = publicId,
)

data class Conversation(
    val id: String,
    val contactUserId: String,
    val contactPublicId: String,
    val bubbleId: String,
    val updatedAt: Instant,
)

data class ChatMessage(
    val id: String,
    val conversationId: String,
    val senderDeviceId: String?,
    val recipientDeviceId: String?,
    val direction: MessageDirection,
    val status: MessageStatus,
    val encryptedLocalBody: String,
    val transportCiphertext: String?,
    val createdAt: Instant,
    val clientMessageId: String = id,
    val transport: MessageTransport = MessageTransport.RELAY,
    val peerIdentityState: MessagePeerIdentityState = MessagePeerIdentityState.UNKNOWN,
)

data class AttachmentDescriptor(
    val blobId: String,
    val bubbleId: String,
    val contentType: String,
    val sizeBytes: Long,
    val sha256: String,
    val key: String,
    val nonce: String,
    val downloadSecret: String,
)

enum class MessageDirection {
    OUTBOUND,
    INBOUND,
}

enum class MessageStatus {
    QUEUED,
    SENDING,
    RECEIVING,
    SENT,
    DELIVERED,
    READ,
    FAILED,
}

enum class MessageTransport {
    P2P_DIRECT,
    P2P_TURN,
    RELAY,
}

enum class MessagePeerIdentityState {
    VERIFIED,
    UNVERIFIED,
    CHANGED,
    UNKNOWN,
}

sealed interface AppResult<out T> {
    data class Ok<T>(val value: T) : AppResult<T>
    data class Err(val error: UserVisibleError) : AppResult<Nothing>
}

data class UserVisibleError(
    val message: String,
    val recoverable: Boolean = true,
    val errorCode: String? = null,
    val requestId: String? = null,
)

fun UserVisibleError.displayMessage(fr: Boolean): String {
    val base = errorCode?.let { localizedErrorMessage(it, fr) } ?: message
    val reference = requestId?.takeIf { it.isNotBlank() }?.let {
        if (fr) "\nReference support: $it" else "\nSupport reference: $it"
    } ?: ""
    return base + reference
}

private fun localizedErrorMessage(code: String, fr: Boolean): String = when (code) {
    "VALIDATION_ERROR" -> if (fr) "Donnees invalides" else "Invalid data"
    "UNAUTHORIZED" -> if (fr) "Session expiree ou authentification requise" else "Session expired or authentication required"
    "FORBIDDEN" -> if (fr) "Action refusee" else "Action denied"
    "NOT_FOUND" -> if (fr) "Ressource introuvable" else "Resource not found"
    "CONFLICT" -> if (fr) "Conflit detecte" else "Conflict detected"
    "RATE_LIMITED" -> if (fr) "Trop de tentatives, reessaie plus tard" else "Too many attempts, try again later"
    "HANDLE_ALREADY_TAKEN" -> if (fr) "Ce handle est deja pris" else "This handle is already taken"
    "HANDLE_RESERVED" -> if (fr) "Ce handle est reserve" else "This handle is reserved"
    "INVALID_RECOVERY_SECRET" -> if (fr) "Secret de recuperation invalide" else "Invalid recovery secret"
    "RECOVERY_CONFIRMATION_MISMATCH" -> if (fr) {
        "Confirme exactement le secret de recuperation"
    } else {
        "Confirm the recovery secret exactly"
    }
    "RECOVERY_NOT_CONFIGURED" -> if (fr) {
        "Recuperation non configuree pour cette identite"
    } else {
        "Recovery is not configured for this identity"
    }
    "RELAY_URL_CLEARTEXT_NOT_ALLOWED" -> if (fr) {
        "HTTPS est requis en release"
    } else {
        "HTTPS is required in release"
    }
    "RELAY_URL_MISSING_SCHEME" -> if (fr) {
        "URL invalide: ajoute http:// en debug ou https:// en release"
    } else {
        "Invalid URL: add http:// in debug or https:// in release"
    }
    "RELAY_SESSION_REQUIRED" -> if (fr) {
        "Connexion au relais prive requise"
    } else {
        "Private relay sign-in required"
    }
    "DEVICE_ID_ALREADY_REGISTERED" -> if (fr) {
        "Cet appareil est deja associe a une autre identite"
    } else {
        "This device is already associated with another identity"
    }
    "BUBBLE_SYNC_REQUIRED" -> if (fr) {
        "Synchronise cette bulle avec le relais avant cette action"
    } else {
        "Sync this bubble with the relay before this action"
    }
    "DELETE_CONFIRMATION_MISMATCH" -> if (fr) {
        "Confirmation incorrecte"
    } else {
        "Incorrect confirmation"
    }
    "RELEASE_NOT_CONFIGURED" -> if (fr) {
        "Aucune mise a jour sideload configuree pour ce relais"
    } else {
        "No sideload update is configured for this relay"
    }
    "INTERNAL_ERROR" -> if (fr) "Erreur serveur temporaire" else "Temporary server error"
    else -> if (fr) "Erreur serveur: $code" else "Server error: $code"
}
