package com.enigma.securechat.ui

import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import com.enigma.securechat.ui.screens.OnboardingScreen
import com.enigma.securechat.ui.theme.EnigmaTheme
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

class OnboardingScreenTest {
    @get:Rule
    val compose = createComposeRule()

    @Test
    fun onboardingShowsMainActionsInFrench() {
        var registerClicked = false

        compose.setContent {
            EnigmaTheme {
                OnboardingScreen(
                    language = "fr",
                    onLanguageSelected = {},
                    onRegister = { registerClicked = true },
                    onLogin = {},
                    onRecover = {},
                    onSetLocalCode = {},
                    onSettings = {},
                )
            }
        }

        compose.onNodeWithText("Créer une identité").performClick()
        assertTrue(registerClicked)
        compose.onNodeWithText("Récupérer une identité").assertExists()
        compose.onNodeWithText("Se connecter").assertExists()
        compose.onNodeWithText("Code local").assertExists()
        compose.onNodeWithText("Serveur").assertExists()
    }

    @Test
    fun onboardingShowsMainActionsInEnglish() {
        var registerClicked = false

        compose.setContent {
            EnigmaTheme {
                OnboardingScreen(
                    language = "en",
                    onLanguageSelected = {},
                    onRegister = { registerClicked = true },
                    onLogin = {},
                    onRecover = {},
                    onSetLocalCode = {},
                    onSettings = {},
                )
            }
        }

        compose.onNodeWithText("Create identity").performClick()
        assertTrue(registerClicked)
        compose.onNodeWithText("Recover identity").assertExists()
        compose.onNodeWithText("Sign in").assertExists()
        compose.onNodeWithText("Local code").assertExists()
        compose.onNodeWithText("Server").assertExists()
    }
}
