package com.enigma.securechat.ui

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.enigma.securechat.data.db.ChannelEntity
import com.enigma.securechat.data.db.GroupEntity
import com.enigma.securechat.data.repository.ActiveBubbleContext
import com.enigma.securechat.di.AppContainer
import com.enigma.securechat.di.EnigmaApplication
import com.enigma.securechat.domain.model.Contact
import com.enigma.securechat.domain.model.Conversation
import com.enigma.securechat.ui.components.EnigmaBottomBar
import com.enigma.securechat.ui.components.EnigmaTab
import com.enigma.securechat.ui.screens.AuthMode
import com.enigma.securechat.ui.screens.AuthScreen
import com.enigma.securechat.ui.screens.BubblesScreen
import com.enigma.securechat.ui.screens.CallsScreen
import com.enigma.securechat.ui.screens.ChannelPostsScreen
import com.enigma.securechat.ui.screens.ChannelsScreen
import com.enigma.securechat.ui.screens.ContactsScreen
import com.enigma.securechat.ui.screens.ConversationScreen
import com.enigma.securechat.ui.screens.GroupChatScreen
import com.enigma.securechat.ui.screens.GroupsScreen
import com.enigma.securechat.ui.screens.LockScreen
import com.enigma.securechat.ui.screens.MessagesScreen
import com.enigma.securechat.ui.screens.OnboardingScreen
import com.enigma.securechat.ui.screens.SettingsScreen
import com.enigma.securechat.ui.theme.EnigmaTheme
import com.enigma.securechat.ui.viewmodel.AuthViewModel
import com.enigma.securechat.ui.viewmodel.BubbleViewModel
import com.enigma.securechat.ui.viewmodel.CallsViewModel
import com.enigma.securechat.ui.viewmodel.ChannelsViewModel
import com.enigma.securechat.ui.viewmodel.ContactsViewModel
import com.enigma.securechat.ui.viewmodel.ConversationViewModel
import com.enigma.securechat.ui.viewmodel.GroupsViewModel
import com.enigma.securechat.ui.viewmodel.LockViewModel
import com.enigma.securechat.ui.viewmodel.SettingsViewModel
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.repeatOnLifecycle
import kotlinx.coroutines.launch

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val app = application as EnigmaApplication
        setContent {
            var container by remember { mutableStateOf(app.container) }
            EnigmaTheme {
                EnigmaApp(
                    container = container,
                    onReloadContainer = {
                        app.reloadContainer()
                        container = app.container
                    },
                )
            }
        }
    }
}

@Composable
fun EnigmaApp(container: AppContainer, onReloadContainer: () -> Unit) {
    val session by container.sessionStore.session.collectAsState(initial = null)
    val scope = rememberCoroutineScope()
    val authViewModel = remember(container) {
        AuthViewModel(container.authRepository, container.identityRepository)
    }
    val contactsViewModel = remember(container) {
        ContactsViewModel(
            container.contactsRepository,
            container.deviceRepository,
            container.bubbleRepository,
            container.sessionStore,
            container.cryptoEngine,
        )
    }
    val groupsViewModel = remember(container) {
        GroupsViewModel(container.groupsRepository, container.mediaRepository)
    }
    val bubbleViewModel = remember(container) {
        BubbleViewModel(
            container.bubbleRepository,
            container.relayRepository,
            container.relaySessionRepository,
            container.serverStatusRepository,
        )
    }
    val channelsViewModel = remember(container) {
        ChannelsViewModel(container.channelsRepository, container.mediaRepository)
    }
    val callsViewModel = remember(container) { CallsViewModel(container.callsRepository) }
    val settingsViewModel = remember(container) {
        SettingsViewModel(
            container.serverSettingsStore,
            container.serverStatusRepository,
            container.updateRepository,
            container.relayRepository,
            container.identityRepository,
            container.sessionStore,
            container.cryptoEngine,
            container.relayScopedApiProvider.activeEndpoint,
            container.api,
        )
    }
    val lockViewModel = remember(container) { LockViewModel(container.sessionStore) }
    val lockState by lockViewModel.state.collectAsState()
    val language by container.serverSettingsStore.language.collectAsState(initial = "fr")
    val activeBubbleContext by container.bubbleRepository.activeContext.collectAsState(initial = null)
    val lifecycleOwner = LocalLifecycleOwner.current

    var route by remember { mutableStateOf<Route>(Route.Onboarding) }
    var selected by remember { mutableStateOf<Pair<Contact, Conversation>?>(null) }
    var selectedGroup by remember { mutableStateOf<GroupEntity?>(null) }
    var selectedChannel by remember { mutableStateOf<ChannelEntity?>(null) }

    LaunchedEffect(lockViewModel) { lockViewModel.load() }
    LaunchedEffect(container, session?.userId) {
        if (session != null) {
            container.bubbleRepository.ensureDefaults()
            contactsViewModel.ensureDevice()
            contactsViewModel.syncContacts()
            route = Route.Messages
        }
    }
    LaunchedEffect(container, session?.accessToken) {
        val currentSession = session ?: return@LaunchedEffect
        lifecycleOwner.lifecycle.repeatOnLifecycle(Lifecycle.State.STARTED) {
            container.directSyncCoordinator.run(currentSession)
        }
    }

    if (session != null && !lockState.unlocked) {
        LockScreen(
            hasPin = lockState.hasPin,
            error = lockState.error,
            language = language,
            onSetPin = lockViewModel::setPin,
            onUnlock = lockViewModel::unlock,
        )
        return
    }

    when (val current = route) {
        Route.Onboarding -> OnboardingScreen(
            language = language,
            onLanguageSelected = { selectedLanguage ->
                scope.launch { container.serverSettingsStore.saveLanguage(selectedLanguage) }
            },
            onRegister = { route = Route.Auth(AuthMode.Register) },
            onLogin = { route = Route.Auth(AuthMode.Login) },
            onRecover = { route = Route.Auth(AuthMode.Recover) },
            onSetLocalCode = { route = Route.LockSetup },
            onSettings = { route = Route.Settings },
        )

        is Route.Auth -> AuthScreen(
            mode = current.mode,
            language = language,
            viewModel = authViewModel,
            onAuthenticated = { route = Route.Messages },
            onBack = { route = Route.Onboarding },
        )

        Route.LockSetup -> LockScreen(
            hasPin = false,
            error = lockState.error,
            language = language,
            onSetPin = {
                lockViewModel.setPin(it)
                route = if (session == null) Route.Onboarding else Route.Messages
            },
            onUnlock = {},
        )

        Route.Messages -> RootScaffold(
            selected = EnigmaTab.Messages,
            language = language,
            activeBubbleContext = activeBubbleContext,
            onTabSelected = { route = it.toRoute() },
        ) {
            MessagesScreen(
                viewModel = contactsViewModel,
                language = language,
                onOpen = { contact ->
                    scope.launch {
                        val conversation = container.contactsRepository.ensureConversation(contact)
                        selected = contact to conversation
                        route = Route.Conversation
                    }
                },
            )
        }

        Route.Bubbles -> RootScaffold(
            selected = EnigmaTab.Bubbles,
            language = language,
            activeBubbleContext = activeBubbleContext,
            onTabSelected = { route = it.toRoute() },
        ) {
            BubblesScreen(viewModel = bubbleViewModel, language = language)
        }

        Route.Contacts -> RootScaffold(
            selected = EnigmaTab.Contacts,
            language = language,
            activeBubbleContext = activeBubbleContext,
            onTabSelected = { tab -> route = tab.toRoute() },
        ) {
            ContactsScreen(
                viewModel = contactsViewModel,
                language = language,
                onOpen = { contact ->
                    scope.launch {
                        val conversation = container.contactsRepository.ensureConversation(contact)
                        selected = contact to conversation
                        route = Route.Conversation
                    }
                },
            )
        }

        Route.Conversation -> {
            val pair = selected ?: run {
                route = Route.Contacts
                return
            }
            val conversationViewModel = remember(pair.second.id) {
                ConversationViewModel(
                    contact = pair.first,
                    conversationId = pair.second.id,
                    messagesRepository = container.messagesRepository,
                    mediaRepository = container.mediaRepository,
                )
            }
            ConversationScreen(
                contact = pair.first,
                viewModel = conversationViewModel,
                language = language,
                onBack = { route = Route.Contacts },
            )
        }

        Route.Groups -> GroupsScreen(
            viewModel = groupsViewModel,
            onOpen = {
                selectedGroup = it
                route = Route.GroupChat
            },
            onBack = { route = Route.Messages },
        )

        Route.GroupChat -> {
            val group = selectedGroup ?: run {
                route = Route.Groups
                return
            }
            GroupChatScreen(group = group, viewModel = groupsViewModel, onBack = { route = Route.Groups })
        }

        Route.Channels -> ChannelsScreen(
            viewModel = channelsViewModel,
            onOpen = {
                selectedChannel = it
                route = Route.ChannelPosts
            },
            onBack = { route = Route.Contacts },
        )

        Route.ChannelPosts -> {
            val channel = selectedChannel ?: run {
                route = Route.Channels
                return
            }
            ChannelPostsScreen(channel = channel, viewModel = channelsViewModel, onBack = { route = Route.Channels })
        }

        Route.Calls -> CallsScreen(viewModel = callsViewModel, onBack = { route = Route.Contacts })

        Route.Settings -> RootScaffold(
            selected = EnigmaTab.Profile,
            language = language,
            activeBubbleContext = activeBubbleContext,
            onTabSelected = { route = it.toRoute() },
        ) {
            SettingsScreen(
                viewModel = settingsViewModel,
                onBack = { route = if (session == null) Route.Onboarding else Route.Messages },
                onDeleted = {
                    onReloadContainer()
                    route = Route.Onboarding
                },
            )
        }
    }
}

@Composable
private fun RootScaffold(
    selected: EnigmaTab,
    language: String,
    activeBubbleContext: ActiveBubbleContext?,
    onTabSelected: (EnigmaTab) -> Unit,
    content: @Composable () -> Unit,
) {
    Scaffold(
        bottomBar = {
            EnigmaBottomBar(
                selected = selected,
                language = language,
                onSelected = onTabSelected,
            )
        },
    ) { paddingValues ->
        Box(modifier = Modifier.padding(paddingValues)) {
            Column(modifier = Modifier.fillMaxSize()) {
                activeBubbleContext?.let {
                    ActiveBubbleContextBar(context = it, language = language)
                }
                Box(modifier = Modifier.weight(1f)) {
                    content()
                }
            }
        }
    }
}

@Composable
private fun ActiveBubbleContextBar(
    context: ActiveBubbleContext,
    language: String,
) {
    val fr = language != "en"
    val isolated = context.relayPolicy.isolated
    val relayLabel = context.primaryRelay?.name ?: if (fr) {
        "relais privé requis"
    } else {
        "private relay required"
    }
    val fallbackLabel = if (isolated) {
        if (fr) "fallback officiel interdit" else "official fallback disabled"
    } else if (context.relayPolicy.fallbackOfficialAllowed) {
        if (fr) "fallback officiel autorisé" else "official fallback allowed"
    } else {
        if (fr) "fallback officiel non" else "official fallback off"
    }
    Surface(
        modifier = Modifier.fillMaxWidth(),
        color = MaterialTheme.colorScheme.surfaceVariant,
        tonalElevation = 1.dp,
    ) {
        Column(modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp)) {
            Text(
                text = if (fr) {
                    "Bulle active : ${context.bubble.name} · ${context.bubble.mode.displayBubbleMode()}"
                } else {
                    "Active bubble: ${context.bubble.name} · ${context.bubble.mode.displayBubbleMode()}"
                },
                style = MaterialTheme.typography.labelLarge,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.height(2.dp))
            Text(
                text = if (fr) {
                    "Relais actif : $relayLabel · $fallbackLabel"
                } else {
                    "Active relay: $relayLabel · $fallbackLabel"
                },
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

private fun String.displayBubbleMode(): String =
    lowercase().split('_').joinToString(" ") { part ->
        part.replaceFirstChar { it.uppercase() }
    }

private fun EnigmaTab.toRoute(): Route = when (this) {
    EnigmaTab.Messages -> Route.Messages
    EnigmaTab.Bubbles -> Route.Bubbles
    EnigmaTab.Contacts -> Route.Contacts
    EnigmaTab.Profile -> Route.Settings
}

private sealed interface Route {
    data object Onboarding : Route
    data class Auth(val mode: AuthMode) : Route
    data object LockSetup : Route
    data object Messages : Route
    data object Bubbles : Route
    data object Contacts : Route
    data object Conversation : Route
    data object Groups : Route
    data object GroupChat : Route
    data object Channels : Route
    data object ChannelPosts : Route
    data object Calls : Route
    data object Settings : Route
}
