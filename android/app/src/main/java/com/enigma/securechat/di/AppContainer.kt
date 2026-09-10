package com.enigma.securechat.di

import android.content.Context
import android.os.Build
import androidx.room.Room
import com.enigma.securechat.BuildConfig
import com.enigma.securechat.calls.WebRtcCallEngine
import com.enigma.securechat.crypto.CryptoEngine
import com.enigma.securechat.crypto.PersistentSignalProtocolStore
import com.enigma.securechat.crypto.SignalCryptoEngine
import com.enigma.securechat.data.db.AppDatabase
import com.enigma.securechat.data.repository.ActiveBubbleContextManager
import com.enigma.securechat.data.repository.AttachmentRepository
import com.enigma.securechat.data.repository.AuthRepository
import com.enigma.securechat.data.repository.BubbleRepository
import com.enigma.securechat.data.repository.CallsRepository
import com.enigma.securechat.data.repository.ChannelsRepository
import com.enigma.securechat.data.repository.ContactsRepository
import com.enigma.securechat.data.repository.DeviceRepository
import com.enigma.securechat.data.repository.GroupsRepository
import com.enigma.securechat.data.repository.IdentityRepository
import com.enigma.securechat.data.repository.InstallSource
import com.enigma.securechat.data.repository.JcaEd25519ApkSignatureVerifier
import com.enigma.securechat.data.repository.LocalAccountDataPurger
import com.enigma.securechat.data.repository.MediaRepository
import com.enigma.securechat.data.repository.MessagesRepository
import com.enigma.securechat.data.repository.OkHttpApkDownloader
import com.enigma.securechat.data.repository.RelayRepository
import com.enigma.securechat.data.repository.RelaySessionRepository
import com.enigma.securechat.data.repository.ServerStatusRepository
import com.enigma.securechat.data.repository.UpdateRepository
import com.enigma.securechat.network.AttachmentHttpClient
import com.enigma.securechat.network.NetworkConfig
import com.enigma.securechat.network.NetworkModule
import com.enigma.securechat.network.OfficialRelayResolver
import com.enigma.securechat.network.RelayEndpoint
import com.enigma.securechat.network.RelayScopedApiProvider
import com.enigma.securechat.network.SecureOkHttpFactory
import com.enigma.securechat.p2p.P2pAttachmentCommitOutboxStore
import com.enigma.securechat.p2p.P2pAttachmentTransferManager
import com.enigma.securechat.p2p.P2pMessagingCoordinator
import com.enigma.securechat.p2p.P2pReceiptOutboxStore
import com.enigma.securechat.p2p.WebRtcP2pEngine
import com.enigma.securechat.security.ReleaseCryptoGuard
import com.enigma.securechat.storage.AndroidKeystoreLocalCipher
import com.enigma.securechat.storage.DeviceStore
import com.enigma.securechat.storage.LocalCipher
import com.enigma.securechat.storage.RelaySettingsStore
import com.enigma.securechat.storage.SecureFileStore
import com.enigma.securechat.storage.SecureSessionStore
import com.enigma.securechat.storage.ServerSettingsStore
import com.enigma.securechat.storage.SharedPreferencesSignalRecordStorage
import com.enigma.securechat.sync.DirectSyncCoordinator
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.flow.firstOrNull
import okhttp3.OkHttpClient

class AppContainer(context: Context) {
    private val appContext = context.applicationContext

    val localCipher: LocalCipher = AndroidKeystoreLocalCipher()
    val sessionStore = SecureSessionStore(appContext, localCipher)
    val serverSettingsStore = ServerSettingsStore(appContext)
    val relaySettingsStore = RelaySettingsStore(appContext)
    val deviceStore = DeviceStore(appContext, localCipher)
    val fileStore = SecureFileStore(appContext)
    val p2pReceiptOutboxStore = P2pReceiptOutboxStore(appContext, localCipher)
    val p2pAttachmentCommitOutboxStore = P2pAttachmentCommitOutboxStore(appContext, localCipher)
    private val signalRecordStorage = SharedPreferencesSignalRecordStorage(appContext, localCipher)
    private val signalStore = PersistentSignalProtocolStore.open(signalRecordStorage)
    val cryptoEngine: CryptoEngine = SignalCryptoEngine(signalStore).also(ReleaseCryptoGuard::requireSignalCrypto)

    val database: AppDatabase = Room.databaseBuilder(
        appContext,
        AppDatabase::class.java,
        "enigma_local.db",
    )
        .addMigrations(AppDatabase.MIGRATION_1_2)
        .addMigrations(AppDatabase.MIGRATION_2_3)
        .addMigrations(AppDatabase.MIGRATION_3_4)
        .addMigrations(AppDatabase.MIGRATION_4_5)
        .addMigrations(AppDatabase.MIGRATION_5_6)
        .addMigrations(AppDatabase.MIGRATION_6_7)
        .addMigrations(AppDatabase.MIGRATION_7_8)
        .addMigrations(AppDatabase.MIGRATION_8_9)
        .addMigrations(AppDatabase.MIGRATION_9_10)
        .addMigrations(AppDatabase.MIGRATION_10_11)
        .addMigrations(AppDatabase.MIGRATION_11_12)
        .build()

    private val officialRelay = OfficialRelayResolver.resolve(
        defaultBaseUrl = BuildConfig.DEFAULT_BASE_URL,
        cleartextAllowed = BuildConfig.CLEARTEXT_ALLOWED,
    )
    val networkConfig = NetworkConfig(
        baseUrl = officialRelay.url,
        cleartextAllowed = BuildConfig.CLEARTEXT_ALLOWED,
        pinningEnabled = BuildConfig.PINNING_ENABLED_BY_DEFAULT,
        pinnedHost = BuildConfig.PINNED_HOST,
        pinnedSha256 = BuildConfig.PINNED_SHA256,
    )
    private val moshi = NetworkModule.moshi()
    private val okHttpFactory = SecureOkHttpFactory { sessionStore.accessToken() }
    private val okHttp = okHttpFactory.create(networkConfig)
    private val attachmentOkHttp = OkHttpClient.Builder()
        .connectTimeout(15, TimeUnit.SECONDS)
        .readTimeout(30, TimeUnit.SECONDS)
        .writeTimeout(30, TimeUnit.SECONDS)
        .retryOnConnectionFailure(true)
        .build()
    val relayScopedApiProvider = RelayScopedApiProvider(
        officialRelay = officialRelay,
        okHttpClientForBaseUrl = ::okHttpClientForBaseUrl,
        moshi = moshi,
        relaySessionTokenProvider = { baseUrl -> sessionStore.relayAccessToken(baseUrl) },
    )
    val api = relayScopedApiProvider.officialApi()
    val webSocketClient = relayScopedApiProvider.realtimeClient()

    val authRepository = AuthRepository(api, sessionStore)
    val serverStatusRepository = ServerStatusRepository(relayScopedApiProvider)
    val relayRepository = RelayRepository(
        relayDao = database.relayDao(),
        relaySettingsStore = relaySettingsStore,
        officialRelay = officialRelay,
        cleartextAllowed = BuildConfig.CLEARTEXT_ALLOWED,
        apiProvider = relayScopedApiProvider,
    )
    val relaySessionRepository = RelaySessionRepository(
        apiProvider = relayScopedApiProvider,
        sessionStore = sessionStore,
        deviceStore = deviceStore,
        cryptoEngine = cryptoEngine,
    )
    val activeBubbleContextManager = ActiveBubbleContextManager(relaySettingsStore)
    val bubbleRepository = BubbleRepository(
        bubbleDao = database.bubbleDao(),
        relayRepository = relayRepository,
        activeBubbleContextManager = activeBubbleContextManager,
        apiProvider = relayScopedApiProvider,
    )
    private val accountDataPurger = LocalAccountDataPurger(
        database = database,
        sessionStore = sessionStore,
        deviceStore = deviceStore,
        signalRecordStorage = signalRecordStorage,
        fileStore = fileStore,
        p2pReceiptOutboxStore = p2pReceiptOutboxStore,
        p2pAttachmentCommitOutboxStore = p2pAttachmentCommitOutboxStore,
    )
    val identityRepository = IdentityRepository(
        api = api,
        cryptoEngine = cryptoEngine,
        deviceStore = deviceStore,
        sessionStore = sessionStore,
        accountDataPurger = accountDataPurger,
    )
    val deviceRepository = DeviceRepository(api, cryptoEngine, deviceStore, sessionStore)
    val contactsRepository = ContactsRepository(
        apiProvider = relayScopedApiProvider,
        contactDao = database.contactDao(),
        contactDeviceDao = database.contactDeviceDao(),
        conversationDao = database.conversationDao(),
        activeBubbleIdProvider = { bubbleRepository.currentNetworkBubbleId() },
    )

    val attachmentRepository = AttachmentRepository(
        apiProvider = relayScopedApiProvider,
        httpClient = AttachmentHttpClient(attachmentOkHttp),
        tempDirectory = java.io.File(appContext.cacheDir, "attachment-transfer"),
        fileStore = fileStore,
        activeBubbleIdProvider = { bubbleRepository.currentNetworkBubbleId() },
    )
    val mediaRepository = MediaRepository(
        attachmentRepository = attachmentRepository,
        attachmentDao = database.attachmentDao(),
    )

    private val p2pEngine = WebRtcP2pEngine(appContext)
    private val p2pAttachmentTransferManager = P2pAttachmentTransferManager(
        engine = p2pEngine,
        fileStore = fileStore,
    )
    val p2pMessagingCoordinator = P2pMessagingCoordinator(
        apiProvider = relayScopedApiProvider,
        realtimeClient = webSocketClient,
        engine = p2pEngine,
        cryptoEngine = cryptoEngine,
        deviceStore = deviceStore,
        contactDeviceDao = database.contactDeviceDao(),
        attachmentTransferManager = p2pAttachmentTransferManager,
        moshi = moshi,
    )

    val messagesRepository = MessagesRepository(
        apiProvider = relayScopedApiProvider,
        cryptoEngine = cryptoEngine,
        localCipher = localCipher,
        deviceStore = deviceStore,
        contactDao = database.contactDao(),
        contactDeviceDao = database.contactDeviceDao(),
        conversationDao = database.conversationDao(),
        messageDao = database.messageDao(),
        p2pCoordinator = p2pMessagingCoordinator,
        p2pReceiptOutboxStore = p2pReceiptOutboxStore,
        attachmentRepository = attachmentRepository,
        p2pAttachmentCommitOutboxStore = p2pAttachmentCommitOutboxStore,
        highSecurityModeProvider = { serverSettingsStore.highSecurityMode.firstOrNull() ?: false },
        activeBubbleIdProvider = { bubbleRepository.currentNetworkBubbleId() },
    ).also { repository ->
        p2pMessagingCoordinator.setIncomingMessageHandler(repository::handleP2pIncoming)
        p2pMessagingCoordinator.setIncomingAttachmentCompleteHandler(repository::completeP2pIncomingAttachments)
        p2pMessagingCoordinator.setIncomingReceiptHandler(repository::handleP2pReceipt)
    }

    val groupsRepository = GroupsRepository(
        apiProvider = relayScopedApiProvider,
        cryptoEngine = cryptoEngine,
        localCipher = localCipher,
        deviceStore = deviceStore,
        groupDao = database.groupDao(),
        groupMessageDao = database.groupMessageDao(),
        activeBubbleId = bubbleRepository.activeBubbleId,
        activeBubbleIdProvider = { bubbleRepository.currentNetworkBubbleId() },
    )
    val channelsRepository = ChannelsRepository(
        apiProvider = relayScopedApiProvider,
        cryptoEngine = cryptoEngine,
        localCipher = localCipher,
        deviceStore = deviceStore,
        channelDao = database.channelDao(),
        channelPostDao = database.channelPostDao(),
        activeBubbleId = bubbleRepository.activeBubbleId,
        activeBubbleIdProvider = { bubbleRepository.currentNetworkBubbleId() },
    )
    private val callEngine = WebRtcCallEngine(appContext)
    val callsRepository = CallsRepository(
        apiProvider = relayScopedApiProvider,
        callEventDao = database.callEventDao(),
        callEngine = callEngine,
        activeBubbleId = bubbleRepository.activeBubbleId,
        activeBubbleIdProvider = { bubbleRepository.currentNetworkBubbleId() },
    )
    val updateRepository = UpdateRepository(
        api = api,
        installSourceProvider = { detectInstallSource(appContext) },
        apkDownloader = OkHttpApkDownloader(okHttp),
        apkSignatureVerifier = JcaEd25519ApkSignatureVerifier.fromBase64OrNoop(
            BuildConfig.UPDATE_ED25519_PUBLIC_KEY,
        ),
        currentVersionCode = BuildConfig.VERSION_CODE.toLong(),
        apkDestinationProvider = { release ->
            java.io.File(appContext.cacheDir, "updates/enigma-${release.latestVersionCode}.apk")
        },
    )
    val directSyncCoordinator = DirectSyncCoordinator(
        realtimeClient = webSocketClient,
        deviceIdProvider = { deviceStore.deviceId() },
        syncPending = { messagesRepository.syncPending() },
        retryOutbound = { messagesRepository.retryPendingOutbound() },
        syncReceipts = { messagesRepository.syncReceipts() },
        syncContacts = { contactsRepository.syncContacts() },
        handleRealtimeEvent = { event ->
            p2pMessagingCoordinator.handleRealtimeEvent(event)
            messagesRepository.handleRealtimeEvent(event)
            callsRepository.handleRealtimeEvent(event)
        },
        transportRunner = { p2pMessagingCoordinator.run() },
    )

    fun dispose() {
        webSocketClient.disconnect()
        p2pEngine.dispose()
        callEngine.dispose()
    }

    private fun detectInstallSource(context: Context): InstallSource {
        val installer = runCatching {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                context.packageManager
                    .getInstallSourceInfo(context.packageName)
                    .installingPackageName
            } else {
                @Suppress("DEPRECATION")
                context.packageManager.getInstallerPackageName(context.packageName)
            }
        }.getOrNull()
        return when (installer) {
            "com.android.vending" -> InstallSource.PLAY_STORE
            "org.fdroid.fdroid", "org.fdroid.basic" -> InstallSource.FDROID
            null -> InstallSource.SIDELOAD
            "com.github.android" -> InstallSource.GITHUB_BUILD
            else -> InstallSource.UNKNOWN
        }
    }

    private fun networkConfigForBaseUrl(baseUrl: String): NetworkConfig =
        NetworkConfig(
            baseUrl = RelayEndpoint.apiBaseUrl(baseUrl),
            cleartextAllowed = BuildConfig.CLEARTEXT_ALLOWED,
            pinningEnabled = BuildConfig.PINNING_ENABLED_BY_DEFAULT &&
                RelayEndpoint.apiBaseUrl(baseUrl) == RelayEndpoint.apiBaseUrl(officialRelay.url),
            pinnedHost = BuildConfig.PINNED_HOST,
            pinnedSha256 = BuildConfig.PINNED_SHA256,
        )

    private fun okHttpClientForBaseUrl(baseUrl: String): OkHttpClient {
        val normalizedBaseUrl = RelayEndpoint.apiBaseUrl(baseUrl)
        return if (normalizedBaseUrl == RelayEndpoint.apiBaseUrl(officialRelay.url)) {
            okHttp
        } else {
            okHttpFactory.create(networkConfigForBaseUrl(baseUrl)) {
                sessionStore.relayAccessToken(normalizedBaseUrl)
            }
        }
    }
}
