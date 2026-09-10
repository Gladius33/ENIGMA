package com.enigma.securechat.sync

import com.enigma.securechat.domain.model.UserSession
import com.enigma.securechat.network.RealtimeClient
import com.enigma.securechat.network.dto.WsEventDto
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Test

class DirectSyncCoordinatorTest {
    @OptIn(ExperimentalCoroutinesApi::class)
    @Test
    fun syncsOnStartupEventsPollingAndReconnects() = runTest {
        val realtime = FakeRealtimeClient()
        var deviceId: String? = null
        var syncPendingCalls = 0
        var retryCalls = 0
        var receiptSyncCalls = 0
        var realtimeEventCalls = 0
        var contactSyncCalls = 0
        val coordinator = DirectSyncCoordinator(
            realtimeClient = realtime,
            deviceIdProvider = { deviceId },
            syncPending = { syncPendingCalls++ },
            retryOutbound = { retryCalls++ },
            syncReceipts = { receiptSyncCalls++ },
            syncContacts = { contactSyncCalls++ },
            handleRealtimeEvent = { realtimeEventCalls++ },
            pollIntervalMillis = 1_000,
            deviceWaitIntervalMillis = 100,
            initialReconnectDelayMillis = 200,
            maxReconnectDelayMillis = 400,
        )

        val job = launch {
            coordinator.run(UserSession("user", "alice", "token"))
        }

        runCurrent()
        assertEquals(0, realtime.connectCalls)

        deviceId = "device-1"
        advanceTimeBy(100)
        runCurrent()

        assertEquals(1, realtime.connectCalls)
        assertEquals(1, syncPendingCalls)
        assertEquals(1, retryCalls)
        assertEquals(1, receiptSyncCalls)
        assertEquals(1, contactSyncCalls)

        realtime.emit(type = "receipt_updated", conversationKind = "direct")
        runCurrent()

        assertEquals(2, syncPendingCalls)
        assertEquals(2, retryCalls)
        assertEquals(2, receiptSyncCalls)
        assertEquals(2, contactSyncCalls)
        assertEquals(1, realtimeEventCalls)

        advanceTimeBy(1_000)
        runCurrent()

        assertEquals(3, syncPendingCalls)
        assertEquals(3, retryCalls)
        assertEquals(3, receiptSyncCalls)
        assertEquals(3, contactSyncCalls)

        realtime.serverDisconnect()
        runCurrent()

        assertEquals(1, realtime.disconnectCalls)
        assertEquals(4, syncPendingCalls)

        advanceTimeBy(200)
        runCurrent()

        assertEquals(2, realtime.connectCalls)

        job.cancelAndJoin()
    }

    @OptIn(ExperimentalCoroutinesApi::class)
    @Test
    fun p2pSignalIsHandledWithoutTriggeringStoreAndForwardSync() = runTest {
        val realtime = FakeRealtimeClient()
        var syncPendingCalls = 0
        var realtimeEventCalls = 0
        var transportRunnerStarts = 0
        val coordinator = DirectSyncCoordinator(
            realtimeClient = realtime,
            deviceIdProvider = { "device-1" },
            syncPending = { syncPendingCalls++ },
            retryOutbound = {},
            syncReceipts = {},
            syncContacts = {},
            handleRealtimeEvent = { realtimeEventCalls++ },
            transportRunner = {
                transportRunnerStarts++
                awaitCancellation()
            },
            pollIntervalMillis = 60_000,
        )

        val job = launch { coordinator.run(UserSession("user", "alice", "token")) }
        runCurrent()
        assertEquals(1, transportRunnerStarts)
        assertEquals(1, syncPendingCalls)

        realtime.emit(type = "p2p_signal", conversationKind = null)
        runCurrent()

        assertEquals(1, realtimeEventCalls)
        assertEquals(1, syncPendingCalls)

        job.cancelAndJoin()
    }

    private class FakeRealtimeClient : RealtimeClient {
        var connectCalls = 0
        var disconnectCalls = 0
        private var onEvent: ((WsEventDto) -> Unit)? = null
        private var onDisconnected: (() -> Unit)? = null

        override fun connect(
            token: String,
            deviceId: String,
            onEvent: (WsEventDto) -> Unit,
            onDisconnected: () -> Unit,
        ) {
            connectCalls++
            this.onEvent = onEvent
            this.onDisconnected = onDisconnected
        }

        override fun disconnect() {
            disconnectCalls++
        }

        fun emit(type: String, conversationKind: String?) {
            onEvent?.invoke(
                WsEventDto(
                    type = type,
                    conversationKind = conversationKind,
                    bubbleId = "bubble-1",
                    messageId = "message-1",
                    clientMessageId = "client-message-1",
                    status = "delivered",
                ),
            )
        }

        fun serverDisconnect() {
            onDisconnected?.invoke()
        }
    }
}
