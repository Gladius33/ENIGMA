package com.enigma.securechat.ui.viewmodel

import android.content.ContentResolver
import android.net.Uri
import android.provider.OpenableColumns
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.enigma.securechat.data.db.GroupEntity
import com.enigma.securechat.data.db.GroupMemberEntity
import com.enigma.securechat.data.db.GroupMessageEntity
import com.enigma.securechat.data.repository.GroupsRepository
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

data class ProductSurfaceUiState(
    val error: String? = null,
    val attachmentTransferInProgress: Boolean = false,
)

class GroupsViewModel(
    private val repository: GroupsRepository,
    private val mediaRepository: MediaRepository,
) : ViewModel() {
    val groups: StateFlow<List<GroupEntity>> = repository.observeGroups()
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyList())

    private val _state = MutableStateFlow(ProductSurfaceUiState())
    val state = _state.asStateFlow()

    fun refresh() {
        viewModelScope.launch {
            when (val result = repository.syncGroups()) {
                is AppResult.Ok -> _state.value = _state.value.copy(error = null)
                is AppResult.Err -> _state.value = _state.value.copy(error = result.error.message)
            }
        }
    }

    fun create(title: String) {
        if (title.isBlank()) return
        viewModelScope.launch {
            when (val result = repository.createGroup(title.trim())) {
                is AppResult.Ok -> {
                    _state.value = _state.value.copy(error = null)
                    repository.syncGroups()
                }
                is AppResult.Err -> _state.value = _state.value.copy(error = result.error.message)
            }
        }
    }

    fun messages(groupId: String): Flow<List<GroupMessageEntity>> = repository.observeMessages(groupId)

    fun members(groupId: String): Flow<List<GroupMemberEntity>> = repository.observeMembers(groupId)

    fun messagePayload(message: GroupMessageEntity): MessagePayload = repository.decryptLocalPayload(message)

    fun messageBody(message: GroupMessageEntity): String = messagePayload(message).body

    fun syncMessages(groupId: String) {
        viewModelScope.launch {
            when (val detail = repository.syncGroupDetail(groupId)) {
                is AppResult.Ok -> Unit
                is AppResult.Err -> _state.value = _state.value.copy(error = detail.error.message)
            }
            when (val result = repository.syncPending(groupId)) {
                is AppResult.Ok -> _state.value = _state.value.copy(error = null)
                is AppResult.Err -> _state.value = _state.value.copy(error = result.error.message)
            }
        }
    }

    fun addMember(groupId: String, userId: String) {
        if (userId.isBlank()) return
        viewModelScope.launch {
            when (val result = repository.addMember(groupId, userId.trim())) {
                is AppResult.Ok -> {
                    _state.value = _state.value.copy(error = null)
                    repository.syncGroupDetail(groupId)
                }
                is AppResult.Err -> _state.value = _state.value.copy(error = result.error.message)
            }
        }
    }

    fun sendMessage(groupId: String, body: String) {
        if (body.isBlank()) return
        viewModelScope.launch {
            when (val result = repository.sendText(groupId, body.trim())) {
                is AppResult.Ok -> {
                    _state.value = _state.value.copy(error = null)
                    repository.syncPending(groupId)
                }
                is AppResult.Err -> _state.value = _state.value.copy(error = result.error.message)
            }
        }
    }

    fun sendAttachment(contentResolver: ContentResolver, groupId: String, uri: Uri, caption: String) {
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
                        when (val sent = repository.sendPayload(groupId, payload)) {
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
