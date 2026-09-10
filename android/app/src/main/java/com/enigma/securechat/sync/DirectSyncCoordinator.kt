package com.enigma.securechat.sync

import com.enigma.securechat.domain.model.UserSession
import com.enigma.securechat.network.RealtimeClient
import com.enigma.securechat.network.SafeLog
import com.enigma.securechat.network.dto.WsEventDto
import kotlin.coroutines.cancellation.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withTimeoutOrNull

class DirectSyncCoordinator(
    private val realtimeClient: RealtimeClient,
    private val deviceIdProvider: suspend () -> String?,
    private val syncPending: suspend () -> Unit,
    private val retryOutbound: suspend () -> Unit,
    private val syncReceipts: suspend () -> Unit,
    private val syncContacts: suspend () -> Unit,
    private val handleRealtimeEvent: suspend (WsEventDto) -> Unit = {},
    private val transportRunner: (suspend () -> Unit)? = null,
    private val pollIntervalMillis: Long = 60_000,
    private val deviceWaitIntervalMillis: Long = 1_000,
    private val initialReconnectDelayMillis: Long = 1_000,
    private val maxReconnectDelayMillis: Long = 30_000,
) {
    init {
        require(pollIntervalMillis > 0)
        require(deviceWaitIntervalMillis > 0)
        require(initialReconnectDelayMillis > 0)
        require(maxReconnectDelayMillis >= initialReconnectDelayMillis)
    }

    suspend fun run(session: UserSession): Unit = coroutineScope {
        val syncMutex = Mutex()
        val realtimeEvents = Channel<WsEventDto>(Channel.UNLIMITED)
        var reconnectDelay = initialReconnectDelayMillis

        suspend fun syncOnce() {
            syncMutex.withLock {
                syncPending()
                retryOutbound()
                syncReceipts()
                syncContacts()
            }
        }

        val transportJob = transportRunner?.let { runner ->
            launch { runner() }
        }
        val eventProcessor = launch {
            for (event in realtimeEvents) {
                handleRealtimeEvent(event)
                if (event.requiresDirectSync()) {
                    launch { syncOnce() }
                }
            }
        }

        try {
            while (currentCoroutineContext().isActive) {
                val deviceId = waitForDeviceId()
                syncOnce()

                val disconnected = CompletableDeferred<Unit>()
                realtimeClient.connect(
                    token = session.accessToken,
                    deviceId = deviceId,
                    onEvent = { event ->
                        realtimeEvents.trySend(event)
                    },
                    onDisconnected = {
                        if (!disconnected.isCompleted) {
                            disconnected.complete(Unit)
                        }
                    },
                )

                var connected = true
                while (currentCoroutineContext().isActive && connected) {
                    val disconnectedBeforePoll = withTimeoutOrNull(pollIntervalMillis) {
                        disconnected.await()
                        true
                    } == true
                    if (disconnectedBeforePoll) {
                        connected = false
                    } else {
                        syncOnce()
                        reconnectDelay = initialReconnectDelayMillis
                    }
                }

                realtimeClient.disconnect()
                syncOnce()
                if (currentCoroutineContext().isActive) {
                    SafeLog.info("Sync", "WebSocket reconnect scheduled in ${reconnectDelay}ms")
                    delay(reconnectDelay)
                    reconnectDelay = (reconnectDelay * 2).coerceAtMost(maxReconnectDelayMillis)
                }
            }
        } finally {
            realtimeClient.disconnect()
            realtimeEvents.close()
            eventProcessor.cancel()
            transportJob?.cancel()
        }
    }

    private suspend fun waitForDeviceId(): String {
        while (currentCoroutineContext().isActive) {
            val deviceId = deviceIdProvider()
            if (!deviceId.isNullOrBlank()) return deviceId
            delay(deviceWaitIntervalMillis)
        }
        throw CancellationException("Sync cancelled before device id was available")
    }

    private fun WsEventDto.requiresDirectSync(): Boolean = when (type) {
        "new_message",
        "receipt_updated",
        "incoming_call",
        "call_signaling",
        "sync_required",
        "device_revoked",
        -> true
        else -> conversationKind == "direct"
    }
}
