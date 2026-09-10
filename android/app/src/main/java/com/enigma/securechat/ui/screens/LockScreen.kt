package com.enigma.securechat.ui.screens

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import com.enigma.securechat.R
import com.enigma.securechat.ui.i18n.localizedString

@Composable
fun LockScreen(
    hasPin: Boolean,
    error: String?,
    language: String,
    onSetPin: (String) -> Unit,
    onUnlock: (String) -> Unit,
) {
    var pin by remember { mutableStateOf("") }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(24.dp),
    ) {
        Text(
            localizedString(
                if (hasPin) R.string.lock_unlock_title else R.string.lock_local_code_title,
                language,
            ),
            style = MaterialTheme.typography.headlineMedium,
        )
        Spacer(Modifier.height(24.dp))
        OutlinedTextField(
            value = pin,
            onValueChange = { pin = it.filter(Char::isDigit).take(12) },
            modifier = Modifier.fillMaxWidth(),
            label = { Text(localizedString(R.string.lock_code_label, language)) },
            visualTransformation = PasswordVisualTransformation(),
            singleLine = true,
        )
        error?.let {
            Spacer(Modifier.height(8.dp))
            Text(localizedString(lockErrorText(it), language), color = MaterialTheme.colorScheme.error)
        }
        Spacer(Modifier.height(16.dp))
        Button(
            onClick = {
                if (hasPin) onUnlock(pin) else onSetPin(pin)
                pin = ""
            },
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text(
                localizedString(
                    if (hasPin) R.string.lock_unlock_button else R.string.save_button,
                    language,
                ),
            )
        }
    }
}

private fun lockErrorText(error: String): Int = when (error) {
    "invalid_code" -> R.string.lock_invalid_code
    "wrong_code" -> R.string.lock_wrong_code
    else -> R.string.lock_invalid_code
}
