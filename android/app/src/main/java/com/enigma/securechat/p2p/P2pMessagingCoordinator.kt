package com.enigma.securechat.p2p

import com.enigma.securechat.calls.CallIceServer
import com.enigma.securechat.crypto.CryptoEngine
import com.enigma.securechat.data.db.ContactDeviceDao
import com.enigma.securechat.data.db.ContactDeviceEntity
import com.enigma.securechat.data.db.ContactDeviceTrustState
import com.enigma.securechat.network.RealtimeClient
import com.enigma.securechat.network.RelayScopedApiProvider
import com.enigma.securechat.network.dto.P2pSignalCommandDto
import com.enigma.securechat.network.dto.WsEventDto
import com.enigma.securechat.storage.DeviceStore
import com.squareup.moshi.Moshi
import com.squareup.moshi.kotlin.reflect.KotlinJsonAdapterFactory
import java.security.SecureRandom
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.withTimeoutOrNull

class P2pMessagingCoordinator(
    private val apiProvider: RelayScopedApiProvider,
    private val realtimeClient: RealtimeClient,
    private val engine: P2pEngine,
    private val cryptoEngine: CryptoEngine,
    private val deviceStore: DeviceStore,
    private val contactDeviceDao: ContactDeviceDao,
    private val attachmentTransferManager: P2pAttachmentTransferManager? = null,
    private val frameCodec: P2pFrameCodec = P2pFrameCodec(),
    moshi: Moshi = Moshi.Builder().add(KotlinJsonAdapterFactory()).build(),
    private val connectTimeoutMillis: Long = 5_000,
    private val ackTimeoutMillis: Long = 2_500,
    private val maxSessionIdleMillis: Long = 5 * 60_000,
    private val receiptFailureBackoffMillis: Long = 15_000,
) {
    private val random = SecureRandom()
    private val iceCandidateAdapter = moshi.adapter(P2pIceCandidate::class.java)
    private val sessions = ConcurrentHashMap<String, SessionState>()
    private val activeByPeer = ConcurrentHashMap<String, String>()
    private val receiptBackoffUntil = ConcurrentHashMap<String, Long>()

    @Volatile
    private var incomingMessageHandler: (suspend (P2pIncomingMessage) -> P2pIncomingMessageResult)? = null

    @Volatile
    private var incomingAttachmentCompleteHandler: (suspend (P2pIncomingMessage) -> Boolean)? = null

    @Volatile
    private var incomingReceiptHandler: (suspend (P2pIncomingReceipt) -> Boolean)? = null

    init {
        require(connectTimeoutMillis in 1_000..30_000)
        require(ackTimeoutMillis in 500..15_000)
        require(maxSessionIdleMillis in 30_000..60 * 60_000)
        require(receiptFailureBackoffMillis in 1_000..60_000)
    }

    fun setIncomingMessageHandler(
        handler: suspend (P2pIncomingMessage) -> P2pIncomingMessageResult,
    ) {
        incomingMessageHandler = handler
    }

    fun setIncomingAttachmentCompleteHandler(handler: suspend (P2pIncomingMessage) -> Boolean) {
        incomingAttachmentCompleteHandler = handler
    }

    fun setIncomingReceiptHandler(handler: suspend (P2pIncomingReceipt) -> Boolean) {
        incomingReceiptHandler = handler
    }

    suspend fun run() {
        engine.events.collect { event ->
            try {
                when (event) {
                    is P2pEngineEvent.LocalIceCandidate -> handleLocalIceCandidate(event)
                    is P2pEngineEvent.ChannelOpen -> sendLocalAuth(event.sessionId)
                    is P2pEngineEvent.Payload -> handleDataChannelPayload(event.sessionId, event.payload)
                    is P2pEngineEvent.BinaryPayload -> handleDataChannelBinary(event.sessionId, event.payload)
                    is P2pEngineEvent.StateChanged -> handleEngineState(event.sessionId, event.state)
                }
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (_: Throwable) {
                invalidate(event.sessionId())
            }
        }
    }

    suspend fun trySend(
        bubbleId: String,
        recipientDeviceId: String,
        clientMessageId: String,
        messageType: String,
        ciphertext: String,
        attachments: List<P2pAttachmentSpec> = emptyList(),
    ): P2pDelivery? {
        if (!validMessageShape(messageType, attachments)) return null
        val localDeviceId = deviceStore.deviceId() ?: return null
        if (localDeviceId == recipientDeviceId) return null
        val remoteDevice = contactDeviceDao.findByDevice(recipientDeviceId) ?: return null
        val remoteIdentityKey = remoteDevice.identityKey ?: return null
        val identityState = remoteDevice.toP2pIdentityState() ?: return null
        if (attachments.isNotEmpty() && attachmentTransferManager == null) return null

        repeat(2) {
            val state = activeSession(
                bubbleId = bubbleId,
                remoteDeviceId = recipientDeviceId,
                remoteIdentityKey = remoteIdentityKey,
                identityState = identityState,
            ) ?: createOutgoingSession(
                bubbleId = bubbleId,
                localDeviceId = localDeviceId,
                remoteDevice = remoteDevice,
                remoteIdentityKey = remoteIdentityKey,
                identityState = identityState,
            ) ?: return@repeat

            val selectedRoute = withTimeoutOrNull(connectTimeoutMillis) { state.authenticated.await() }
            if (selectedRoute == null) {
                invalidate(state.sessionId)
                return@repeat
            }

            val delivered = CompletableDeferred<Unit>()
            state.deliveryWaiters[clientMessageId] = delivered
            val messageSent = sendMessageFrame(
                state = state,
                bubbleId = bubbleId,
                localDeviceId = localDeviceId,
                recipientDeviceId = recipientDeviceId,
                clientMessageId = clientMessageId,
                messageType = messageType,
                ciphertext = ciphertext,
            )
            if (!messageSent) {
                state.deliveryWaiters.remove(clientMessageId)
                invalidate(state.sessionId)
                return@repeat
            }

            if (attachments.isNotEmpty()) {
                val transferred = try {
                    attachmentTransferManager?.sendAttachments(
                        sessionId = state.sessionId,
                        clientMessageId = clientMessageId,
                        attachments = attachments,
                    ) == true
                } catch (cancelled: CancellationException) {
                    throw cancelled
                } catch (_: Throwable) {
                    false
                }
                if (!transferred) {
                    state.deliveryWaiters.remove(clientMessageId)
                    invalidate(state.sessionId)
                    return@repeat
                }
            }

            val acknowledged = withTimeoutOrNull(ackTimeoutMillis) {
                delivered.await()
                true
            } == true
            state.deliveryWaiters.remove(clientMessageId)
            if (!acknowledged) {
                invalidate(state.sessionId)
                return@repeat
            }
            if (!verifyCurrentPeerIdentity(state)) return null
            state.lastUsedAt = System.currentTimeMillis()
            return state.delivery(selectedRoute)
        }
        return null
    }

    suspend fun trySendReceipt(
        receiptId: String,
        bubbleId: String,
        recipientDeviceId: String,
        clientMessageId: String,
        status: P2pReceiptStatus,
    ): P2pDelivery? {
        val key = peerKey(bubbleId, recipientDeviceId)
        val now = System.currentTimeMillis()
        val blockedUntil = receiptBackoffUntil[key]
        if (blockedUntil != null) {
            if (blockedUntil > now) return null
            receiptBackoffUntil.remove(key, blockedUntil)
        }

        val delivery = trySendReceiptAttempt(
            receiptId = receiptId,
            bubbleId = bubbleId,
            recipientDeviceId = recipientDeviceId,
            clientMessageId = clientMessageId,
            status = status,
        )
        if (delivery == null) {
            receiptBackoffUntil[key] = System.currentTimeMillis() + receiptFailureBackoffMillis
        } else {
            receiptBackoffUntil.remove(key)
        }
        return delivery
    }

    private suspend fun trySendReceiptAttempt(
        receiptId: String,
        bubbleId: String,
        recipientDeviceId: String,
        clientMessageId: String,
        status: P2pReceiptStatus,
    ): P2pDelivery? {
        val localDeviceId = deviceStore.deviceId() ?: return null
        if (localDeviceId == recipientDeviceId) return null
        val remoteDevice = contactDeviceDao.findByDevice(recipientDeviceId) ?: return null
        val remoteIdentityKey = remoteDevice.identityKey ?: return null
        val identityState = remoteDevice.toP2pIdentityState() ?: return null

        repeat(2) {
            val state = activeSession(
                bubbleId = bubbleId,
                remoteDeviceId = recipientDeviceId,
                remoteIdentityKey = remoteIdentityKey,
                identityState = identityState,
            ) ?: createOutgoingSession(
                bubbleId = bubbleId,
                localDeviceId = localDeviceId,
                remoteDevice = remoteDevice,
                remoteIdentityKey = remoteIdentityKey,
                identityState = identityState,
            ) ?: return@repeat

            val selectedRoute = withTimeoutOrNull(connectTimeoutMillis) { state.authenticated.await() }
            if (selectedRoute == null) {
                invalidate(state.sessionId)
                return@repeat
            }
            val receiptAck = CompletableDeferred<Unit>()
            state.receiptAckWaiters[receiptId] = receiptAck
            if (!sendReceiptFrame(state, receiptId, clientMessageId, status)) {
                state.receiptAckWaiters.remove(receiptId)
                invalidate(state.sessionId)
                return@repeat
            }
            val acknowledged = withTimeoutOrNull(ackTimeoutMillis) {
                receiptAck.await()
                true
            } == true
            state.receiptAckWaiters.remove(receiptId)
            if (!acknowledged) {
                invalidate(state.sessionId)
                return@repeat
            }
            if (!verifyCurrentPeerIdentity(state)) return null
            state.lastUsedAt = System.currentTimeMillis()
            return state.delivery(selectedRoute)
        }
        return null
    }

    suspend fun handleRealtimeEvent(event: WsEventDto) {
        when (event.type) {
            "p2p_signal_unavailable" -> {
                val sessionId = event.sessionId ?: return
                sessions[sessionId]?.authenticated?.completeExceptionally(
                    IllegalStateException("P2P peer unavailable"),
                )
                invalidate(sessionId)
            }
            "p2p_signal" -> handleP2pSignal(event)
        }
    }

    private suspend fun handleP2pSignal(event: WsEventDto) {
        val sessionId = event.sessionId ?: return
        val bubbleId = event.bubbleId ?: return
        val senderDeviceId = event.senderDeviceId ?: return
        val signalKind = event.signalKind ?: return
        val payload = event.payload ?: return
        when (signalKind) {
            "offer" -> handleOffer(sessionId, bubbleId, senderDeviceId, payload)
            "answer" -> {
                val state = sessions[sessionId] ?: return
                if (state.remoteDeviceId != senderDeviceId || state.bubbleId != bubbleId) return
                engine.setRemoteAnswer(sessionId, payload)
                state.remoteDescriptionReady = true
                flushRemoteIce(state)
            }
            "ice" -> {
                val state = sessions[sessionId] ?: return
                if (state.remoteDeviceId != senderDeviceId || state.bubbleId != bubbleId) return
                val candidate = runCatching { iceCandidateAdapter.fromJson(payload) }.getOrNull() ?: return
                if (state.remoteDescriptionReady) {
                    engine.addRemoteIceCandidate(sessionId, candidate)
                } else {
                    synchronized(state.pendingRemoteIce) { state.pendingRemoteIce += candidate }
                }
            }
            "ice_complete" -> Unit
            "cancel" -> invalidate(sessionId)
        }
    }

    private suspend fun handleOffer(
        sessionId: String,
        bubbleId: String,
        senderDeviceId: String,
        offerSdp: String,
    ) {
        if (sessions.containsKey(sessionId)) return
        val localDeviceId = deviceStore.deviceId() ?: return
        if (localDeviceId == senderDeviceId) return
        val remoteDevice = contactDeviceDao.findByDevice(senderDeviceId) ?: return
        val remoteIdentityKey = remoteDevice.identityKey ?: return
        val identityState = remoteDevice.toP2pIdentityState() ?: return
        val state = SessionState(
            sessionId = sessionId,
            bubbleId = bubbleId,
            localDeviceId = localDeviceId,
            remoteDeviceId = senderDeviceId,
            initiatorDeviceId = senderDeviceId,
            responderDeviceId = localDeviceId,
            remoteIdentityKey = remoteIdentityKey,
            peerIdentityState = identityState,
        )
        sessions[sessionId] = state

        val answer = runCatching {
            engine.acceptIncoming(
                P2pSessionConfig(
                    sessionId = sessionId,
                    bubbleId = bubbleId,
                    localDeviceId = localDeviceId,
                    remoteDeviceId = senderDeviceId,
                    iceServers = fetchIceServers(),
                ),
                offerSdp,
            )
        }.getOrElse {
            invalidate(sessionId)
            return
        }
        state.remoteDescriptionReady = true
        flushRemoteIce(state)
        if (!sendSignal(state, "answer", answer)) {
            invalidate(sessionId)
            return
        }
        state.localSdpSignaled = true
        flushLocalIce(state)
    }

    private suspend fun createOutgoingSession(
        bubbleId: String,
        localDeviceId: String,
        remoteDevice: ContactDeviceEntity,
        remoteIdentityKey: String,
        identityState: P2pPeerIdentityState,
    ): SessionState? {
        val sessionId = UUID.randomUUID().toString()
        val state = SessionState(
            sessionId = sessionId,
            bubbleId = bubbleId,
            localDeviceId = localDeviceId,
            remoteDeviceId = remoteDevice.deviceId,
            initiatorDeviceId = localDeviceId,
            responderDeviceId = remoteDevice.deviceId,
            remoteIdentityKey = remoteIdentityKey,
            peerIdentityState = identityState,
        )
        sessions[sessionId] = state
        val offer = runCatching {
            engine.startOutgoing(
                P2pSessionConfig(
                    sessionId = sessionId,
                    bubbleId = bubbleId,
                    localDeviceId = localDeviceId,
                    remoteDeviceId = remoteDevice.deviceId,
                    iceServers = fetchIceServers(),
                ),
            )
        }.getOrElse {
            invalidate(sessionId)
            return null
        }
        if (!sendSignal(state, "offer", offer)) {
            invalidate(sessionId)
            return null
        }
        state.localSdpSignaled = true
        flushLocalIce(state)
        return state
    }

    private suspend fun fetchIceServers(): List<CallIceServer> {
        val turn = runCatching { apiProvider.withActiveApi { it.turnCredentials() } }.getOrNull()
            ?: return emptyList()
        return listOf(
            CallIceServer(
                urls = turn.uris,
                username = turn.username,
                credential = turn.credential,
            ),
        )
    }

    private fun handleLocalIceCandidate(event: P2pEngineEvent.LocalIceCandidate) {
        val state = sessions[event.sessionId] ?: return
        if (state.localSdpSignaled) {
            if (!sendIce(state, event.candidate)) invalidate(state.sessionId)
        } else {
            synchronized(state.pendingLocalIce) { state.pendingLocalIce += event.candidate }
        }
    }

    private fun flushLocalIce(state: SessionState) {
        val pending = synchronized(state.pendingLocalIce) {
            state.pendingLocalIce.toList().also { state.pendingLocalIce.clear() }
        }
        for (candidate in pending) {
            if (!sendIce(state, candidate)) {
                invalidate(state.sessionId)
                return
            }
        }
    }

    private suspend fun flushRemoteIce(state: SessionState) {
        val pending = synchronized(state.pendingRemoteIce) {
            state.pendingRemoteIce.toList().also { state.pendingRemoteIce.clear() }
        }
        for (candidate in pending) engine.addRemoteIceCandidate(state.sessionId, candidate)
    }

    private fun sendIce(state: SessionState, candidate: P2pIceCandidate): Boolean {
        val payload = runCatching { iceCandidateAdapter.toJson(candidate) }.getOrNull() ?: return false
        return sendSignal(state, "ice", payload)
    }

    private fun sendSignal(state: SessionState, kind: String, payload: String): Boolean =
        realtimeClient.sendP2pSignal(
            P2pSignalCommandDto(
                bubbleId = state.bubbleId,
                recipientDeviceId = state.remoteDeviceId,
                sessionId = state.sessionId,
                signalKind = kind,
                payload = payload,
            ),
        )

    private suspend fun sendLocalAuth(sessionId: String) {
        val state = sessions[sessionId] ?: return
        if (state.authSent) return
        val fingerprints = expectedFingerprints(state) ?: return
        val nonceBytes = ByteArray(32).also(random::nextBytes)
        val nonce = frameCodec.encodeBytes(nonceBytes)
        nonceBytes.fill(0)
        val transcript = frameCodec.transcript(
            sessionId = state.sessionId,
            bubbleId = state.bubbleId,
            initiatorDeviceId = state.initiatorDeviceId,
            responderDeviceId = state.responderDeviceId,
            offerFingerprint = fingerprints.first,
            answerFingerprint = fingerprints.second,
            proofDeviceId = state.localDeviceId,
            nonce = nonce,
        )
        val signature = cryptoEngine.signIdentityProof(transcript)
        transcript.fill(0)
        val proof = P2pAuthProof(
            sessionId = state.sessionId,
            bubbleId = state.bubbleId,
            initiatorDeviceId = state.initiatorDeviceId,
            responderDeviceId = state.responderDeviceId,
            offerFingerprint = fingerprints.first,
            answerFingerprint = fingerprints.second,
            proofDeviceId = state.localDeviceId,
            nonce = nonce,
            signature = frameCodec.encodeBytes(signature),
        )
        signature.fill(0)
        state.authSent = engine.send(sessionId, frameCodec.encodeAuth(proof))
        if (!state.authSent) invalidate(sessionId)
    }

    private suspend fun handleDataChannelPayload(sessionId: String, payload: String) {
        val state = sessions[sessionId] ?: return
        val transferManager = attachmentTransferManager
        if (transferManager != null && transferManager.isControl(payload)) {
            if (validateAuthenticatedSession(state) == null) return
            val handled = runCatching {
                transferManager.handleControl(
                    sessionId = sessionId,
                    payload = payload,
                    validateOffer = { clientMessageId, attachments ->
                        val pending = state.pendingAttachmentMessages[clientMessageId]
                        pending != null &&
                            pending.attachments == attachments &&
                            verifyCurrentPeerIdentity(state)
                    },
                    completeIncoming = { clientMessageId ->
                        completeIncomingAttachments(state, clientMessageId)
                    },
                )
            }.getOrDefault(false)
            if (!handled) invalidate(sessionId)
            return
        }

        when (val frame = runCatching { frameCodec.decode(payload) }.getOrNull() ?: return) {
            is P2pFrameCodec.DecodedP2pFrame.Auth -> handleRemoteAuth(state, frame.proof)
            is P2pFrameCodec.DecodedP2pFrame.Route -> handleRemoteRoute(state, frame.observation)
            is P2pFrameCodec.DecodedP2pFrame.Message -> handleIncomingMessage(state, frame.message)
            is P2pFrameCodec.DecodedP2pFrame.Receipt -> handleIncomingReceipt(state, frame.receipt)
            is P2pFrameCodec.DecodedP2pFrame.ReceiptAck -> {
                if (state.selectedRoute != null && state.remoteAuthVerified) {
                    state.receiptAckWaiters[frame.ack.receiptId]?.complete(Unit)
                }
            }
        }
    }

    private suspend fun handleDataChannelBinary(sessionId: String, payload: ByteArray) {
        val state = sessions[sessionId]
        val transferManager = attachmentTransferManager
        if (state == null || transferManager == null || validateAuthenticatedSession(state) == null) {
            payload.fill(0)
            if (state != null) invalidate(sessionId)
            return
        }
        val accepted = runCatching { transferManager.handleBinary(sessionId, payload) }.getOrDefault(false)
        if (!accepted) invalidate(sessionId)
    }

    private suspend fun handleRemoteAuth(state: SessionState, proof: P2pAuthProof) {
        if (state.remoteAuthVerified) return
        val fingerprints = expectedFingerprints(state) ?: run {
            invalidate(state.sessionId)
            return
        }
        if (
            proof.sessionId != state.sessionId ||
            proof.bubbleId != state.bubbleId ||
            proof.initiatorDeviceId != state.initiatorDeviceId ||
            proof.responderDeviceId != state.responderDeviceId ||
            proof.offerFingerprint != fingerprints.first ||
            proof.answerFingerprint != fingerprints.second ||
            proof.proofDeviceId != state.remoteDeviceId
        ) {
            invalidate(state.sessionId)
            return
        }
        val nonce = runCatching { frameCodec.decodeBytes(proof.nonce) }.getOrNull() ?: run {
            invalidate(state.sessionId)
            return
        }
        if (nonce.size != 32) {
            nonce.fill(0)
            invalidate(state.sessionId)
            return
        }
        nonce.fill(0)
        val signature = runCatching { frameCodec.decodeBytes(proof.signature) }.getOrNull() ?: run {
            invalidate(state.sessionId)
            return
        }
        val transcript = frameCodec.transcript(
            sessionId = proof.sessionId,
            bubbleId = proof.bubbleId,
            initiatorDeviceId = proof.initiatorDeviceId,
            responderDeviceId = proof.responderDeviceId,
            offerFingerprint = proof.offerFingerprint,
            answerFingerprint = proof.answerFingerprint,
            proofDeviceId = proof.proofDeviceId,
            nonce = proof.nonce,
        )
        val valid = cryptoEngine.verifyIdentityProof(
            identityPublicKey = state.remoteIdentityKey,
            transcript = transcript,
            signature = signature,
        )
        transcript.fill(0)
        signature.fill(0)
        if (!valid) {
            invalidate(state.sessionId)
            return
        }

        state.remoteAuthVerified = true
        if (!state.authSent) sendLocalAuth(state.sessionId)
        val localRoute = resolveSelectedRoute(state.sessionId) ?: run {
            invalidate(state.sessionId)
            return
        }
        state.localRoute = localRoute
        if (
            !engine.send(
                state.sessionId,
                frameCodec.encodeRoute(
                    P2pRouteObservation(
                        sessionId = state.sessionId,
                        bubbleId = state.bubbleId,
                        senderDeviceId = state.localDeviceId,
                        route = localRoute.route,
                        localCandidateType = localRoute.localCandidateType,
                        remoteCandidateType = localRoute.remoteCandidateType,
                    ),
                ),
            )
        ) {
            invalidate(state.sessionId)
            return
        }
        completeAuthenticationIfReady(state)
    }

    private fun handleRemoteRoute(state: SessionState, observation: P2pRouteObservation) {
        if (!state.remoteAuthVerified) return
        if (
            observation.sessionId != state.sessionId ||
            observation.bubbleId != state.bubbleId ||
            observation.senderDeviceId != state.remoteDeviceId
        ) {
            invalidate(state.sessionId)
            return
        }
        state.remoteRoute = P2pSelectedRoute(
            route = observation.route,
            localCandidateType = observation.localCandidateType,
            remoteCandidateType = observation.remoteCandidateType,
        )
        completeAuthenticationIfReady(state)
    }

    private fun completeAuthenticationIfReady(state: SessionState) {
        if (!state.remoteAuthVerified || state.authenticated.isCompleted) return
        val local = state.localRoute ?: return
        val remote = state.remoteRoute ?: return
        val effective = consensusRoute(local, remote)
        state.selectedRoute = effective
        state.lastUsedAt = System.currentTimeMillis()
        activeByPeer[peerKey(state.bubbleId, state.remoteDeviceId)] = state.sessionId
        state.authenticated.complete(effective)
    }

    private suspend fun resolveSelectedRoute(sessionId: String): P2pSelectedRoute? {
        repeat(20) {
            engine.selectedRoute(sessionId)?.let { return it }
            delay(100)
        }
        return null
    }

    private suspend fun handleIncomingMessage(state: SessionState, envelope: P2pMessageEnvelope) {
        val selectedRoute = validateAuthenticatedSession(state) ?: return
        if (
            envelope.bubbleId != state.bubbleId ||
            envelope.senderDeviceId != state.remoteDeviceId ||
            envelope.recipientDeviceId != state.localDeviceId ||
            envelope.messageType !in SUPPORTED_MESSAGE_TYPES
        ) return
        val handler = incomingMessageHandler ?: return
        val message = P2pIncomingMessage(
            sessionId = state.sessionId,
            bubbleId = envelope.bubbleId,
            senderDeviceId = envelope.senderDeviceId,
            recipientDeviceId = envelope.recipientDeviceId,
            clientMessageId = envelope.clientMessageId,
            messageType = envelope.messageType,
            ciphertext = envelope.ciphertext,
            route = selectedRoute.route,
            peerIdentityState = state.peerIdentityState,
        )
        when (val result = runCatching { handler(message) }.getOrDefault(P2pIncomingMessageResult.Rejected)) {
            P2pIncomingMessageResult.Rejected -> Unit
            P2pIncomingMessageResult.Delivered -> {
                sendDeliveredReceipt(state, envelope.clientMessageId)
                state.lastUsedAt = System.currentTimeMillis()
            }
            is P2pIncomingMessageResult.AwaitingAttachments -> {
                if (result.attachments.isEmpty() || result.attachments.size > 16) return
                state.pendingAttachmentMessages[envelope.clientMessageId] = PendingAttachmentMessage(
                    message = message,
                    attachments = result.attachments,
                )
                state.lastUsedAt = System.currentTimeMillis()
            }
        }
    }

    private suspend fun completeIncomingAttachments(state: SessionState, clientMessageId: String): Boolean {
        val selectedRoute = validateAuthenticatedSession(state) ?: return false
        val pending = state.pendingAttachmentMessages[clientMessageId] ?: return false
        if (pending.message.route != selectedRoute.route) return false
        val handler = incomingAttachmentCompleteHandler ?: return false
        val committed = runCatching { handler(pending.message) }.getOrDefault(false)
        if (!committed) return false
        state.pendingAttachmentMessages.remove(clientMessageId, pending)
        sendDeliveredReceipt(state, clientMessageId)
        state.lastUsedAt = System.currentTimeMillis()
        return true
    }

    private suspend fun handleIncomingReceipt(state: SessionState, receipt: P2pReceiptEnvelope) {
        val selectedRoute = validateAuthenticatedSession(state) ?: return
        if (
            receipt.bubbleId != state.bubbleId ||
            receipt.senderDeviceId != state.remoteDeviceId ||
            receipt.recipientDeviceId != state.localDeviceId
        ) return
        val handler = incomingReceiptHandler ?: return
        val applied = runCatching {
            handler(
                P2pIncomingReceipt(
                    sessionId = state.sessionId,
                    receiptId = receipt.receiptId,
                    bubbleId = receipt.bubbleId,
                    senderDeviceId = receipt.senderDeviceId,
                    recipientDeviceId = receipt.recipientDeviceId,
                    clientMessageId = receipt.clientMessageId,
                    status = receipt.status,
                    route = selectedRoute.route,
                    peerIdentityState = state.peerIdentityState,
                ),
            )
        }.getOrDefault(false)
        if (!applied) return

        if (receipt.status == P2pReceiptStatus.DELIVERED) {
            state.deliveryWaiters[receipt.clientMessageId]?.complete(Unit)
        }
        engine.send(
            state.sessionId,
            frameCodec.encodeReceiptAck(P2pReceiptAck(receipt.receiptId)),
        )
        state.lastUsedAt = System.currentTimeMillis()
    }

    private fun sendMessageFrame(
        state: SessionState,
        bubbleId: String,
        localDeviceId: String,
        recipientDeviceId: String,
        clientMessageId: String,
        messageType: String,
        ciphertext: String,
    ): Boolean = engine.send(
        state.sessionId,
        frameCodec.encodeMessage(
            P2pMessageEnvelope(
                bubbleId = bubbleId,
                senderDeviceId = localDeviceId,
                recipientDeviceId = recipientDeviceId,
                clientMessageId = clientMessageId,
                messageType = messageType,
                ciphertext = ciphertext,
            ),
        ),
    )

    private fun sendDeliveredReceipt(state: SessionState, clientMessageId: String): Boolean =
        sendReceiptFrame(
            state = state,
            receiptId = UUID.randomUUID().toString(),
            clientMessageId = clientMessageId,
            status = P2pReceiptStatus.DELIVERED,
        )

    private fun sendReceiptFrame(
        state: SessionState,
        receiptId: String,
        clientMessageId: String,
        status: P2pReceiptStatus,
    ): Boolean = engine.send(
        state.sessionId,
        frameCodec.encodeReceipt(
            P2pReceiptEnvelope(
                receiptId = receiptId,
                bubbleId = state.bubbleId,
                senderDeviceId = state.localDeviceId,
                recipientDeviceId = state.remoteDeviceId,
                clientMessageId = clientMessageId,
                status = status,
            ),
        ),
    )

    private suspend fun validateAuthenticatedSession(state: SessionState): P2pSelectedRoute? {
        val selectedRoute = state.selectedRoute ?: return null
        if (state.isIdleExpired()) {
            invalidate(state.sessionId)
            return null
        }
        if (!verifyCurrentPeerIdentity(state)) return null
        return selectedRoute
    }

    private suspend fun verifyCurrentPeerIdentity(state: SessionState): Boolean {
        val currentDevice = contactDeviceDao.findByDevice(state.remoteDeviceId) ?: run {
            invalidate(state.sessionId)
            return false
        }
        if (!state.matchesCurrentIdentity(currentDevice)) {
            invalidate(state.sessionId)
            return false
        }
        return true
    }

    private fun SessionState.delivery(route: P2pSelectedRoute): P2pDelivery = P2pDelivery(
        sessionId = sessionId,
        route = route.route,
        peerIdentityState = peerIdentityState,
        localCandidateType = route.localCandidateType,
        remoteCandidateType = route.remoteCandidateType,
    )

    private fun expectedFingerprints(state: SessionState): Pair<String, String>? {
        val local = engine.localDtlsFingerprint(state.sessionId) ?: return null
        val remote = engine.remoteDtlsFingerprint(state.sessionId) ?: return null
        return if (state.localDeviceId == state.initiatorDeviceId) local to remote else remote to local
    }

    private fun handleEngineState(sessionId: String, state: String) {
        if (state == "failed" || state == "closed" || state == "ended") invalidate(sessionId)
    }

    private fun activeSession(
        bubbleId: String,
        remoteDeviceId: String,
        remoteIdentityKey: String,
        identityState: P2pPeerIdentityState,
    ): SessionState? {
        val key = peerKey(bubbleId, remoteDeviceId)
        val sessionId = activeByPeer[key] ?: return null
        val state = sessions[sessionId]
        if (
            state == null ||
            state.selectedRoute == null ||
            state.remoteIdentityKey != remoteIdentityKey ||
            state.peerIdentityState != identityState ||
            state.isIdleExpired()
        ) {
            activeByPeer.remove(key, sessionId)
            if (state != null) invalidate(sessionId)
            return null
        }
        return state
    }

    private fun invalidate(sessionId: String) {
        val state = sessions.remove(sessionId) ?: return
        activeByPeer.remove(peerKey(state.bubbleId, state.remoteDeviceId), sessionId)
        attachmentTransferManager?.releaseSession(sessionId)
        val closed = IllegalStateException("P2P session closed")
        state.authenticated.completeExceptionally(closed)
        state.deliveryWaiters.values.forEach { it.completeExceptionally(closed) }
        state.deliveryWaiters.clear()
        state.receiptAckWaiters.values.forEach { it.completeExceptionally(closed) }
        state.receiptAckWaiters.clear()
        state.pendingAttachmentMessages.clear()
        synchronized(state.pendingLocalIce) { state.pendingLocalIce.clear() }
        synchronized(state.pendingRemoteIce) { state.pendingRemoteIce.clear() }
        engine.release(sessionId)
    }

    private fun validMessageShape(messageType: String, attachments: List<P2pAttachmentSpec>): Boolean =
        when {
            attachments.isEmpty() -> messageType == "text"
            attachments.size > 16 -> false
            else -> messageType == "file" || messageType == "opaque"
        }

    private fun peerKey(bubbleId: String, remoteDeviceId: String): String = "$bubbleId:$remoteDeviceId"

    private fun ContactDeviceEntity.toP2pIdentityState(): P2pPeerIdentityState? =
        when (runCatching { ContactDeviceTrustState.valueOf(trustState) }.getOrNull()) {
            ContactDeviceTrustState.VERIFIED -> P2pPeerIdentityState.VERIFIED
            ContactDeviceTrustState.CHANGED -> P2pPeerIdentityState.CHANGED
            ContactDeviceTrustState.UNVERIFIED, null -> P2pPeerIdentityState.UNVERIFIED
            ContactDeviceTrustState.BLOCKED -> null
        }

    private fun P2pEngineEvent.sessionId(): String = when (this) {
        is P2pEngineEvent.LocalIceCandidate -> sessionId
        is P2pEngineEvent.ChannelOpen -> sessionId
        is P2pEngineEvent.Payload -> sessionId
        is P2pEngineEvent.BinaryPayload -> sessionId
        is P2pEngineEvent.StateChanged -> sessionId
    }

    private data class PendingAttachmentMessage(
        val message: P2pIncomingMessage,
        val attachments: List<P2pAttachmentSpec>,
    )

    private inner class SessionState(
        val sessionId: String,
        val bubbleId: String,
        val localDeviceId: String,
        val remoteDeviceId: String,
        val initiatorDeviceId: String,
        val responderDeviceId: String,
        val remoteIdentityKey: String,
        val peerIdentityState: P2pPeerIdentityState,
        val authenticated: CompletableDeferred<P2pSelectedRoute> = CompletableDeferred(),
        val deliveryWaiters: ConcurrentHashMap<String, CompletableDeferred<Unit>> = ConcurrentHashMap(),
        val receiptAckWaiters: ConcurrentHashMap<String, CompletableDeferred<Unit>> = ConcurrentHashMap(),
        val pendingAttachmentMessages: ConcurrentHashMap<String, PendingAttachmentMessage> = ConcurrentHashMap(),
        val pendingLocalIce: MutableList<P2pIceCandidate> = mutableListOf(),
        val pendingRemoteIce: MutableList<P2pIceCandidate> = mutableListOf(),
        @Volatile var authSent: Boolean = false,
        @Volatile var remoteAuthVerified: Boolean = false,
        @Volatile var localSdpSignaled: Boolean = false,
        @Volatile var remoteDescriptionReady: Boolean = false,
        @Volatile var localRoute: P2pSelectedRoute? = null,
        @Volatile var remoteRoute: P2pSelectedRoute? = null,
        @Volatile var selectedRoute: P2pSelectedRoute? = null,
        @Volatile var lastUsedAt: Long = System.currentTimeMillis(),
    ) {
        fun isIdleExpired(nowMillis: Long = System.currentTimeMillis()): Boolean =
            nowMillis - lastUsedAt > maxSessionIdleMillis

        fun matchesCurrentIdentity(device: ContactDeviceEntity): Boolean =
            device.identityKey == remoteIdentityKey && device.toP2pIdentityState() == peerIdentityState
    }

    private companion object {
        val SUPPORTED_MESSAGE_TYPES = setOf("text", "file", "opaque")
    }
}
