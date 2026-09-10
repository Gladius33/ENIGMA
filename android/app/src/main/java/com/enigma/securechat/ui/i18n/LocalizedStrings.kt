package com.enigma.securechat.ui.i18n

import android.content.res.Configuration
import android.content.Context
import androidx.annotation.StringRes
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.platform.LocalContext
import java.util.Locale

@Composable
fun localizedString(@StringRes id: Int, language: String, vararg formatArgs: Any): String {
    val context = LocalContext.current
    val resources = remember(context, language) {
        localizedResources(context, language)
    }
    return if (formatArgs.isEmpty()) {
        resources.getString(id)
    } else {
        resources.getString(id, *formatArgs)
    }
}

fun localizedText(context: Context, @StringRes id: Int, language: String, vararg formatArgs: Any): String {
    val resources = localizedResources(context, language)
    return if (formatArgs.isEmpty()) {
        resources.getString(id)
    } else {
        resources.getString(id, *formatArgs)
    }
}

private fun localizedResources(context: Context, language: String) = run {
    val locale = if (language == "en") Locale.ENGLISH else Locale.FRENCH
    val config = Configuration(context.resources.configuration)
    config.setLocale(locale)
    context.createConfigurationContext(config).resources
}
