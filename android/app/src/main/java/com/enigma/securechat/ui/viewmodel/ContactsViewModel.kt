package com.enigma.securechat.ui.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.enigma.securechat.crypto.CryptoEngine
import com.enigma.securechat.data.repository.ActiveBubbleContext
import com.enigma.securechat.data.repository.BubbleRepository
import com.enigma.securechat.data.repository.ContactsRepository
import com.enigma.securechat.data.repository.DeviceRepository
import com.enigma.securechat.domain.model.AppResult
import com.enigma.securechat.domain.model.Contact
import com.enigma.securechat.domain.model.UserVisibleError
import com.enigma.securechat.qr.EnigmaQrCode
import com.enigma.securechat.qr.EnigmaQrPayloads
import com.enigma.securechat.qr.IdentityQrPayload
import com.enigma.securechat.qr.ParsedEnigmaQrPayload
import com.enigma.securechat.storage.SecureSessionStore
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.flatMapLatest
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch

data class ContactsUiState(
    val registeringDevice: Boolean = false,
    val error: UserVisibleError? = null,
)

class ContactsViewModel(
    private val contactsRepository: ContactsRepository,
    private val deviceRepository: DeviceRepository,
    private val bubbleRepository: BubbleRepository,
    private val sessionStore: SecureSessionStore,
    private val cryptoEngine: CryptoEngine,
) : ViewModel() {
    val activeBubbleContext: StateFlow<ActiveBubbleContext?> = bubbleRepository.activeContext
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), null)
    @OptIn(ExperimentalCoroutinesApi::class)
    val contacts: StateFlow<List<Contact>> = bubbleRepository.activeContext
        .flatMapLatest { context ->
            if (context?.showGlobalContacts == false) {
                contactsRepository.observeContactsForBubble(context.bubble.id)
            } else {
                contactsRepository.observeContacts()
            }
        }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyList())

    private val _state = MutableStateFlow(ContactsUiState())
    val state: StateFlow<ContactsUiState> = _state.asStateFlow()
    private val _identityQr = MutableStateFlow<EnigmaQrCode?>(null)
    val identityQr: StateFlow<EnigmaQrCode?> = _identityQr.asStateFlow()

    fun ensureDevice(displayName: String = android.os.Build.MODEL ?: "Android") {
        viewModelScope.launch {
            _state.value = ContactsUiState(registeringDevice = true)
            _state.value = when (val result = deviceRepository.ensureRegistered(displayName)) {
                is AppResult.Ok -> ContactsUiState()
                is AppResult.Err -> ContactsUiState(error = result.error)
            }
        }
    }

    fun syncContacts() {
        viewModelScope.launch {
            when (val result = contactsRepository.syncContacts()) {
                is AppResult.Ok -> _state.value = ContactsUiState()
                is AppResult.Err -> _state.value = ContactsUiState(error = result.error)
            }
        }
    }

    fun addContact(publicId: String) {
        viewModelScope.launch {
            when (val result = contactsRepository.addByPublicId(publicId.trim())) {
                is AppResult.Ok -> _state.value = ContactsUiState()
                is AppResult.Err -> _state.value = ContactsUiState(error = result.error)
            }
        }
    }

    fun showIdentityQr() {
        viewModelScope.launch {
            val session = sessionStore.session.first() ?: return@launch
            val identity = cryptoEngine.ensureIdentity()
            _identityQr.value = EnigmaQrPayloads.identity(
                IdentityQrPayload(
                    identity_id = session.userId,
                    public_handle = session.publicId,
                    display_name = session.publicId,
                    public_key = identity.identityPublicKey,
                    signature = null,
                ),
            )
        }
    }

    fun importContactQr(input: String) {
        val payload = EnigmaQrPayloads.parse(input) as? ParsedEnigmaQrPayload.Identity
        if (payload == null) {
            _state.value = ContactsUiState(error = UserVisibleError("QR contact invalide"))
            return
        }
        addContact(payload.payload.public_handle.removePrefix("@"))
    }
}
