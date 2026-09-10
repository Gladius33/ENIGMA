package com.enigma.securechat.ui.viewmodel

import android.content.ContentResolver
import android.net.Uri
import android.provider.OpenableColumns
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.enigma.securechat.data.db.ChannelEntity
import com.enigma.securechat.data.db.ChannelPostEntity
import com.enigma.securechat.data.repository.ChannelAudienceMember
import com.enigma.securechat.data.repository.ChannelsRepository
import com.enigma.securechat.data.repository.MediaRepository
import com.enigma.securechat.data.repository.MessageAttachment
import com.enigma.securechat.data.repository.MessagePayload
import com.enigma.securechat.domain.model.AppResult
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class ChannelsViewModel(
    private val repository: ChannelsRepository,
    private val mediaRepository: MediaRepository,
) : ViewModel() {
    val channels: StateFlow<List<ChannelEntity>> = repository.observeChannels()
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyList())

    private val _state = MutableStateFlow(ProductSurfaceUiState())
    val state = _state.asStateFlow()
    private val _audience = MutableStateFlow<List<ChannelAudienceMember>>(emptyList())
    val audience = _audience.asStateFlow()

    fun refresh() {
        viewModelScope.launch {
            when (val result = repository.syncChannels()) {
                is AppResult.Ok -> _state.value = _state.value.copy(error = null)
                is AppResult.Err -> _state.value = _state.value.copy(error = result.error.message)
            }
        }
    }

    fun create(title: String) {
        if (title.isBlank()) return
        viewModelScope.launch {
            when (val result = repository.createChannel(title.trim())) {
                is AppResult.Ok -> {
                    _state.value = _state.value.copy(error = null)
                    repository.syncChannels()
                }
                is AppResult.Err -> _state.value = _state.value.copy(error = result.error.message)
            }
        }
    }

    fun posts(channelId: String): Flow<List<ChannelPostEntity>> = repository.observePosts(channelId)

    fun postPayload(post: ChannelPostEntity): MessagePayload = repository.decryptLocalPayload(post)

    fun postBody(post: ChannelPostEntity): String = postPayload(post).body

    fun syncPosts(channelId: String) {
        viewModelScope.launch {
            when (val audienceResult = repository.subscribers(channelId)) {
                is AppResult.Ok -> _audience.value = audienceResult.value
                is AppResult.Err -> _state.value = _state.value.copy(error = audienceResult.error.message)
            }
            when (val result = repository.syncPending(channelId)) {
                is AppResult.Ok -> _state.value = _state.value.copy(error = null)
                is AppResult.Err -> _state.value = _state.value.copy(error = result.error.message)
            }
        }
    }

    fun publish(channelId: String, body: String) {
        if (body.isBlank()) return
        viewModelScope.launch {
            when (val result = repository.sendText(channelId, body.trim())) {
                is AppResult.Ok -> {
                    _state.value = _state.value.copy(error = null)
                    repository.subscribers(channelId).let {
                        if (it is AppResult.Ok) _audience.value = it.value
                    }
                    repository.syncPending(channelId)
                }
                is AppResult.Err -> _state.value = _state.value.copy(error = result.error.message)
            }
        }
    }

    fun publishAttachment(contentResolver: ContentResolver, channelId: String, uri: Uri, caption: String) {
        if (_state.value.attachmentTransferInProgress) return
        viewModelScope.launch {
            _state.value = _state.value.copy(attachmentTransferInProgress = true, error = null)
            try {
                val contentType = contentResolver.getType(uri)?.takeIf { it.contains('/') }
                    ?: "application/octet-stream"
                val fileName = withContext(Dispatchers.IO) { displayName(contentResolver, uri) }
                val upload = withContext(Dispatchers.IO) {
                    val source = contentResolver.openInputStream(uri)
                        ?: return@withContext null
                    source.use { mediaRepository.uploadEncrypted(it, contentType) }
                }
                when (upload) {
                    null -> _state.value = _state.value.copy(error = "Impossible d’ouvrir la pièce jointe")
                    is AppResult.Err -> _state.value = _state.value.copy(error = upload.error.message)
                    is AppResult.Ok -> {
                        val payload = MessagePayload(
                            body = caption,
                            attachments = listOf(MessageAttachment(upload.value, fileName)),
                        )
                        when (val sent = repository.publishPayload(channelId, payload)) {
                            is AppResult.Ok -> _state.value = _state.value.copy(error = null)
                            is AppResult.Err -> _state.value = _state.value.copy(error = sent.error.message)
                        }
                    }
                }
            } finally {
                _state.value = _state.value.copy(attachmentTransferInProgress = false)
            }
        }
    }

    fun downloadAttachment(contentResolver: ContentResolver, destination: Uri, attachment: MessageAttachment) {
        if (_state.value.attachmentTransferInProgress) return
        viewModelScope.launch {
            _state.value = _state.value.copy(attachmentTransferInProgress = true, error = null)
            try {
                val result = withContext(Dispatchers.IO) {
                    val output = contentResolver.openOutputStream(destination, "w")
                        ?: return@withContext null
                    output.use { mediaRepository.downloadAndDecryptTo(attachment.descriptor, it) }
                }
                when (result) {
                    null -> _state.value = _state.value.copy(error = "Impossible d’ouvrir la destination")
                    is AppResult.Err -> _state.value = _state.value.copy(error = result.error.message)
                    is AppResult.Ok -> Unit
                }
            } finally {
                _state.value = _state.value.copy(attachmentTransferInProgress = false)
            }
        }
    }

    private fun displayName(contentResolver: ContentResolver, uri: Uri): String? =
        contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { cursor ->
            val index = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
            if (index >= 0 && cursor.moveToFirst()) cursor.getString(index) else null
        }
}
