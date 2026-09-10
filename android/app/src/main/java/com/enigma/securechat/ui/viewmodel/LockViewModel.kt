package com.enigma.securechat.ui.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.enigma.securechat.storage.SecureSessionStore
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

data class LockUiState(
    val unlocked: Boolean = false,
    val hasPin: Boolean = false,
    val error: String? = null,
)

class LockViewModel(
    private val sessionStore: SecureSessionStore,
) : ViewModel() {
    private val _state = MutableStateFlow(LockUiState())
    val state: StateFlow<LockUiState> = _state.asStateFlow()

    fun load() {
        viewModelScope.launch {
            val hasPin = sessionStore.hasLocalPin()
            _state.value = LockUiState(unlocked = !hasPin, hasPin = hasPin)
        }
    }

    fun setPin(pin: String) {
        viewModelScope.launch {
            if (pin.length !in 4..12) {
                _state.value = _state.value.copy(error = "invalid_code")
                return@launch
            }
            sessionStore.setLocalPin(pin.toCharArray())
            _state.value = LockUiState(unlocked = true, hasPin = true)
        }
    }

    fun unlock(pin: String) {
        viewModelScope.launch {
            val ok = sessionStore.verifyLocalPin(pin.toCharArray())
            _state.value = if (ok) {
                LockUiState(unlocked = true, hasPin = true)
            } else {
                _state.value.copy(error = "wrong_code")
            }
        }
    }
}
