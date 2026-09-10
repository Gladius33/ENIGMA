package com.enigma.securechat.ui.screens

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import com.enigma.securechat.R
import com.enigma.securechat.domain.model.displayMessage
import com.enigma.securechat.ui.i18n.localizedString
import com.enigma.securechat.ui.viewmodel.AuthViewModel

enum class AuthMode {
    Register,
    Login,
    Recover,
}

@Composable
fun AuthScreen(
    mode: AuthMode,
    language: String,
    viewModel: AuthViewModel,
    onAuthenticated: () -> Unit,
    onBack: () -> Unit,
) {
    val state by viewModel.state.collectAsState()
    val fr = language != "en"
    var publicId by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    var recoverySecret by remember { mutableStateOf("") }
    var recoveryConfirmation by remember { mutableStateOf("") }

    LaunchedEffect(state.authenticated) {
        if (state.authenticated) onAuthenticated()
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(24.dp),
    ) {
        Text(localizedString(titleFor(mode), language), style = MaterialTheme.typography.headlineMedium)
        Spacer(Modifier.height(24.dp))
        OutlinedTextField(
            value = publicId,
            onValueChange = { publicId = it },
            modifier = Modifier.fillMaxWidth(),
            label = { Text(localizedString(R.string.handle_label, language)) },
            singleLine = true,
        )
        if (mode == AuthMode.Register) {
            Spacer(Modifier.height(8.dp))
            OutlinedButton(
                onClick = { viewModel.checkHandle(publicId) },
                enabled = !state.loading,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(localizedString(R.string.auth_check_availability, language))
            }
            state.handleStatus?.let {
                Spacer(Modifier.height(8.dp))
                Text(localizedString(handleStatusText(it), language))
            }
        }
        Spacer(Modifier.height(12.dp))
        if (mode == AuthMode.Recover) {
            OutlinedTextField(
                value = recoverySecret,
                onValueChange = { recoverySecret = it },
                modifier = Modifier.fillMaxWidth(),
                label = { Text(localizedString(R.string.auth_recovery_secret, language)) },
                visualTransformation = PasswordVisualTransformation(),
                singleLine = true,
            )
            Spacer(Modifier.height(8.dp))
            Text(localizedString(R.string.auth_recovery_warning, language))
        } else {
            OutlinedTextField(
                value = password,
                onValueChange = { password = it },
                modifier = Modifier.fillMaxWidth(),
                label = { Text(localizedString(R.string.auth_password, language)) },
                visualTransformation = PasswordVisualTransformation(),
                singleLine = true,
            )
        }
        Spacer(Modifier.height(16.dp))
        state.recoverySecretToConfirm?.let { generated ->
            Text(
                localizedString(R.string.auth_recovery_secret_title, language),
                style = MaterialTheme.typography.titleMedium,
            )
            Spacer(Modifier.height(8.dp))
            Text(generated, style = MaterialTheme.typography.bodyLarge)
            Spacer(Modifier.height(8.dp))
            OutlinedTextField(
                value = recoveryConfirmation,
                onValueChange = { recoveryConfirmation = it },
                modifier = Modifier.fillMaxWidth(),
                label = { Text(localizedString(R.string.auth_retype_secret, language)) },
                singleLine = true,
            )
            Spacer(Modifier.height(12.dp))
            Button(
                onClick = { viewModel.confirmRecoverySecret(recoveryConfirmation) },
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(localizedString(R.string.auth_saved_secret, language))
            }
            Spacer(Modifier.height(16.dp))
        }
        state.error?.let {
            Text(it.displayMessage(fr), color = MaterialTheme.colorScheme.error)
            Spacer(Modifier.height(12.dp))
        }
        Button(
            onClick = {
                when (mode) {
                    AuthMode.Register -> viewModel.register(publicId, password)
                    AuthMode.Login -> viewModel.login(publicId, password)
                    AuthMode.Recover -> viewModel.recover(publicId, recoverySecret)
                }
            },
            enabled = !state.loading && state.recoverySecretToConfirm == null,
            modifier = Modifier.fillMaxWidth(),
        ) {
            if (state.loading) CircularProgressIndicator() else Text(localizedString(R.string.continue_button, language))
        }
        Spacer(Modifier.height(12.dp))
        OutlinedButton(onClick = onBack, modifier = Modifier.fillMaxWidth()) {
            Text(localizedString(R.string.back_button, language))
        }
    }
}

private fun titleFor(mode: AuthMode): Int = when (mode) {
    AuthMode.Register -> R.string.auth_create_identity_title
        AuthMode.Login -> R.string.auth_sign_in_title
    AuthMode.Recover -> R.string.auth_recover_identity_title
}

private fun handleStatusText(status: String): Int = when (status) {
    "too_short" -> R.string.auth_handle_too_short
    "available" -> R.string.auth_handle_available
    "unavailable" -> R.string.auth_handle_unavailable
    else -> R.string.auth_handle_unavailable
}
