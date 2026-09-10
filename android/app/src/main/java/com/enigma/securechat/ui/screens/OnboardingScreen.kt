package com.enigma.securechat.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.enigma.securechat.R
import com.enigma.securechat.ui.components.EnigmaBrandLogo
import com.enigma.securechat.ui.i18n.localizedString

@Composable
fun OnboardingScreen(
    language: String,
    onLanguageSelected: (String) -> Unit,
    onRegister: () -> Unit,
    onLogin: () -> Unit,
    onRecover: () -> Unit,
    onSetLocalCode: () -> Unit,
    onSettings: () -> Unit,
) {
    val fr = language != "en"
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(24.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.Start,
    ) {
        EnigmaBrandLogo(size = 84.dp)
        Spacer(Modifier.height(18.dp))
        Text(
            localizedString(R.string.brand_welcome_title, language),
            style = MaterialTheme.typography.displaySmall,
            fontWeight = FontWeight.Bold,
        )
        Spacer(Modifier.height(8.dp))
        Text(localizedString(R.string.brand_welcome_body, language))
        Spacer(Modifier.height(6.dp))
        Text(localizedString(R.string.onboarding_tagline, language))
        Spacer(Modifier.height(16.dp))
        Text(localizedString(R.string.language_title, language), style = MaterialTheme.typography.labelLarge)
        Spacer(Modifier.height(8.dp))
        OutlinedButton(onClick = { onLanguageSelected("fr") }, modifier = Modifier.fillMaxWidth()) {
            Text(
                localizedString(
                    if (fr) R.string.language_french_selected else R.string.language_french,
                    language,
                ),
            )
        }
        Spacer(Modifier.height(8.dp))
        OutlinedButton(onClick = { onLanguageSelected("en") }, modifier = Modifier.fillMaxWidth()) {
            Text(
                localizedString(
                    if (fr) R.string.language_english else R.string.language_english_selected,
                    language,
                ),
            )
        }
        Spacer(Modifier.height(32.dp))
        Button(onClick = onRegister, modifier = Modifier.fillMaxWidth()) {
            Text(localizedString(R.string.onboarding_create_identity, language))
        }
        Spacer(Modifier.height(12.dp))
        OutlinedButton(onClick = onRecover, modifier = Modifier.fillMaxWidth()) {
            Text(localizedString(R.string.onboarding_recover_identity, language))
        }
        Spacer(Modifier.height(12.dp))
        OutlinedButton(onClick = onLogin, modifier = Modifier.fillMaxWidth()) {
            Text(localizedString(R.string.onboarding_sign_in, language))
        }
        Spacer(Modifier.height(12.dp))
        OutlinedButton(onClick = onSetLocalCode, modifier = Modifier.fillMaxWidth()) {
            Text(localizedString(R.string.onboarding_local_code, language))
        }
        Spacer(Modifier.height(12.dp))
        OutlinedButton(onClick = onSettings, modifier = Modifier.fillMaxWidth()) {
            Text(localizedString(R.string.server_title, language))
        }
    }
}
