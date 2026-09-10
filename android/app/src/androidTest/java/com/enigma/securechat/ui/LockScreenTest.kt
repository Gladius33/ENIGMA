package com.enigma.securechat.ui

import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextInput
import com.enigma.securechat.ui.screens.LockScreen
import com.enigma.securechat.ui.theme.EnigmaTheme
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test

class LockScreenTest {
    @get:Rule
    val compose = createComposeRule()

    @Test
    fun lockScreenSubmitsLocalCodeInFrench() {
        var submitted = ""

        compose.setContent {
            EnigmaTheme {
                LockScreen(
                    hasPin = false,
                    error = null,
                    language = "fr",
                    onSetPin = { submitted = it },
                    onUnlock = {},
                )
            }
        }

        compose.onNodeWithText("Code").performTextInput("123456")
        compose.onNodeWithText("Enregistrer").performClick()

        assertEquals("123456", submitted)
    }

    @Test
    fun lockScreenSubmitsLocalCodeInEnglish() {
        var submitted = ""

        compose.setContent {
            EnigmaTheme {
                LockScreen(
                    hasPin = false,
                    error = null,
                    language = "en",
                    onSetPin = { submitted = it },
                    onUnlock = {},
                )
            }
        }

        compose.onNodeWithText("Code").performTextInput("123456")
        compose.onNodeWithText("Save").performClick()

        assertEquals("123456", submitted)
    }
}
