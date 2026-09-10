package com.enigma.securechat.ui.components

import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import com.enigma.securechat.R
import com.enigma.securechat.ui.i18n.localizedString

enum class EnigmaTab {
    Messages,
    Bubbles,
    Contacts,
    Profile,
}

@Composable
fun EnigmaBottomBar(
    selected: EnigmaTab,
    language: String,
    onSelected: (EnigmaTab) -> Unit,
) {
    NavigationBar {
        EnigmaTab.entries.forEach { tab ->
            NavigationBarItem(
                selected = selected == tab,
                onClick = { onSelected(tab) },
                icon = { Text(tab.icon) },
                label = { Text(localizedString(tab.labelRes, language)) },
            )
        }
    }
}

private val EnigmaTab.icon: String
    get() = when (this) {
        EnigmaTab.Messages -> "M"
        EnigmaTab.Bubbles -> "B"
        EnigmaTab.Contacts -> "C"
        EnigmaTab.Profile -> "P"
    }

private val EnigmaTab.labelRes: Int
    get() = when (this) {
        EnigmaTab.Messages -> R.string.tab_messages
        EnigmaTab.Bubbles -> R.string.tab_bubbles
        EnigmaTab.Contacts -> R.string.tab_contacts
        EnigmaTab.Profile -> R.string.tab_profile
    }
