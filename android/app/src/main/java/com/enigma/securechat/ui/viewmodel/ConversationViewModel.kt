package com.enigma.securechat.ui.viewmodel

import android.content.ContentResolver
import android.net.Uri
import android.provider.OpenableColumns
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.enigma.securechat.data.db.ContactDeviceTrustState
import com.enigma.securechat.data.repository.MediaRepository
import com.enigma.securechat.data.repository.MessageAttachment
import com.enigma.securechat.data.repository.MessagePayload
import com.enigma.securechat.data.repository.MessagesRepository
import com.enigma.securechat.domain.model.AppResult
import com.enigma.securechat.domain.model.ChatMessage
import com.enigma.securechat.domain.model.Contact
import com.enigma.securechat.domain.model.UserVisibleError
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

data class ConversationUiState(
    val error: UserVisibleError? = null,
    val safetyNumber: String? = null,
    val safetyVerified: Boolean = false,
    val safetyTrustState: ContactDeviceTrustState = ContactDeviceTrustState.UNVERIFIED,
    val attachmentTransferInProgress: Boolean = false,
)

class ConversationViewModel(
    private val contact: Contact,
    private val conversationId: String,
    private val messagesRepository: MessagesRepository,
    private val mediaRepository: MediaRepository,
) : ViewModel() {
    val messages: StateFlow<List<ChatMessage>> = messagesRepository.observeMessages(conversationId)
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyList())

    private val _state = MutableStateFlow(ConversationUiState())
    val state = _state.asStateFlow()

    fun send(text: String) {
        if (text.isBlank()) return
        viewModelScope.launch {
            when (val result = messagesRepository.sendText(contact, text, conversationId)) {
                is AppResult.Ok -> _state.value = _state.value.copy(error = null)
                is AppResult.Err -> _state.value = _state.value.copy(error = result.error)
            }
        }
    }

    fun sendAttachment(
        contentResolver: ContentResolver,
        uri: Uri,
        caption: String,
    ) {
        if (_state.value.attachmentTransferInProgress) return
        viewModelScope.launch {
            _state.value = _state.value.copy(attachmentTransferInProgress = true, error = null)
            try {
                val contentType = contentResolver.getType(uri)?.takeIf { it.contains('/') }
                    ?: "application/octet-stream"
                val fileName = withContext(Dispatchers.IO) { displayName(contentResolver, uri) }
                val prepared = withContext(Dispatchers.IO) {
                    val source = contentResolver.openInputStream(uri)
                        ?: return@withContext AppResult.Err(
                            UserVisibleError("Impossible d’ouvrir la pièce jointe"),
                        )
                    source.use { mediaRepository.prepareDirectEncrypted(it, contentType) }
                }
                when (prepared) {
                    is AppResult.Err -> _state.value = _state.value.copy(error = prepared.error)
                    is AppResult.Ok -> {
                        val payload = MessagePayload(
                            body = caption,
                            attachments = listOf(
                                MessageAttachment(
                                    descriptor = prepared.value,
                                    fileName = fileName,
                                ),
                            ),
                        )
                        when (val sent = messagesRepository.sendPayload(contact, payload, conversationId)) {
                            is AppResult.Ok -> _state.value = _state.value.copy(error = null)
                            is AppResult.Err -> _state.value = _state.value.copy(error = sent.error)
                        }
                    }
                }
            } finally {
                _state.value = _state.value.copy(attachmentTransferInProgress = false)
            }
        }
    }

    fun downloadAttachment(
        contentResolver: ContentResolver,
        destination: Uri,
        attachment: MessageAttachment,
    ) {
        if (_state.value.attachmentTransferInProgress) return
        viewModelScope.launch {
            _state.value = _state.value.copy(attachmentTransferInProgress = true, error = null)
            try {
                val result = withContext(Dispatchers.IO) {
                    val output = contentResolver.openOutputStream(destination, "w")
                        ?: return@withContext AppResult.Err(
                            UserVisibleError("Impossible d’ouvrir la destination"),
                        )
                    output.use {
                        mediaRepository.downloadAndDecryptTo(attachment.descriptor, it)
                    }
                }
                if (result is AppResult.Err) {
                    _state.value = _state.value.copy(error = result.error)
                }
            } finally {
                _state.value = _state.value.copy(attachmentTransferInProgress = false)
            }
        }
    }

    fun syncPending() {
        viewModelScope.launch {
            messagesRepository.syncPending()
            messagesRepository.markConversationRead(conversationId)
        }
    }

    fun markRead() {
        viewModelScope.launch { messagesRepository.markConversationRead(conversationId) }
    }

    fun retryFailedMessages() {
        viewModelScope.launch {
            when (val result = messagesRepository.retryPendingOutbound()) {
                is AppResult.Ok -> _state.value = _state.value.copy(error = null)
                is AppResult.Err -> _state.value = _state.value.copy(error = result.error)
            }
        }
    }

    fun loadSafetyNumber() {
        viewModelScope.launch {
            when (val result = messagesRepository.safetyNumberState(contact)) {
                is AppResult.Ok -> _state.value = _state.value.copy(
                    safetyNumber = result.value.code,
                    safetyVerified = result.value.verified,
                    safetyTrustState = result.value.trustState,
                    error = null,
                )
                is AppResult.Err -> _state.value = _state.value.copy(error = result.error)
            }
        }
    }

    fun verifySafetyNumber() {
        viewModelScope.launch {
            when (val result = messagesRepository.markSafetyNumberVerified(contact)) {
                is AppResult.Ok -> _state.value = _state.value.copy(
                    safetyNumber = result.value.code,
                    safetyVerified = result.value.verified,
                    safetyTrustState = result.value.trustState,
                    error = null,
                )
                is AppResult.Err -> _state.value = _state.value.copy(error = result.error)
            }
        }
    }

    fun displayPayload(message: ChatMessage): MessagePayload =
        runCatching { messagesRepository.decryptLocalPayload(message) }
            .getOrDefault(MessagePayload(body = ""))

    fun displayText(message: ChatMessage): String = displayPayload(message).body

    private fun displayName(contentResolver: ContentResolver, uri: Uri): String? {
        return contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { cursor ->
            val index = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
            if (index >= 0 && cursor.moveToFirst()) cursor.getString(index) else null
        }
    }
}
