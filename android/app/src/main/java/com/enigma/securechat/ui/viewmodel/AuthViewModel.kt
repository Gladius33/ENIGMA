package com.enigma.securechat.ui.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.enigma.securechat.data.repository.AuthRepository
import com.enigma.securechat.data.repository.IdentityRepository
import com.enigma.securechat.domain.model.AppResult
import com.enigma.securechat.domain.model.UserVisibleError
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

data class AuthUiState(
    val loading: Boolean = false,
    val error: UserVisibleError? = null,
    val authenticated: Boolean = false,
    val handleStatus: String? = null,
    val recoverySecretToConfirm: String? = null,
)

class AuthViewModel(
    private val repository: AuthRepository,
    private val identityRepository: IdentityRepository,
) : ViewModel() {
    private val _state = MutableStateFlow(AuthUiState())
    val state: StateFlow<AuthUiState> = _state.asStateFlow()

    fun register(publicId: String, password: String) = authenticate(publicId, password, register = true)
    fun login(publicId: String, password: String) = authenticate(publicId, password, register = false)
    fun recover(handle: String, recoverySecret: String) {
        viewModelScope.launch {
            _state.value = AuthUiState(loading = true)
            _state.value = when (
                val result = identityRepository.recoverIdentity(
                    handle = handle,
                    recoverySecret = recoverySecret,
                    deviceName = android.os.Build.MODEL ?: "Android",
                )
            ) {
                is AppResult.Ok -> AuthUiState(authenticated = true)
                is AppResult.Err -> AuthUiState(error = result.error)
            }
        }
    }

    fun checkHandle(handle: String) {
        viewModelScope.launch {
            val clean = handle.trim()
            if (clean.length < 3) {
                _state.value = _state.value.copy(handleStatus = "too_short")
                return@launch
            }
            _state.value = _state.value.copy(loading = true, handleStatus = null, error = null)
            _state.value = when (val result = identityRepository.checkHandle(clean)) {
                is AppResult.Ok -> _state.value.copy(
                    loading = false,
                    handleStatus = if (result.value) "available" else "unavailable",
                )
                is AppResult.Err -> _state.value.copy(loading = false, error = result.error)
            }
        }
    }

    fun confirmRecoverySecret(input: String) {
        val expected = _state.value.recoverySecretToConfirm
        _state.value = if (expected != null && input.trim() == expected) {
            AuthUiState(authenticated = true)
        } else {
            _state.value.copy(
                error = UserVisibleError(
                    message = "RECOVERY_CONFIRMATION_MISMATCH",
                    errorCode = "RECOVERY_CONFIRMATION_MISMATCH",
                ),
            )
        }
    }

    private fun authenticate(publicId: String, password: String, register: Boolean) {
        viewModelScope.launch {
            _state.value = AuthUiState(loading = true)
            if (register) {
                _state.value = when (
                    val result = identityRepository.createIdentity(
                        handle = publicId.trim(),
                        password = password,
                        deviceName = android.os.Build.MODEL ?: "Android",
                    )
                ) {
                    is AppResult.Ok -> AuthUiState(recoverySecretToConfirm = result.value.recoverySecret)
                    is AppResult.Err -> AuthUiState(error = result.error)
                }
            } else {
                _state.value = when (val result = repository.login(publicId.trim(), password)) {
                    is AppResult.Ok -> AuthUiState(authenticated = true)
                    is AppResult.Err -> AuthUiState(error = result.error)
                }
            }
        }
    }
}
