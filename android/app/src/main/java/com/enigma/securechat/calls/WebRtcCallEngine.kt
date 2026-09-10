package com.enigma.securechat.calls

import android.content.Context
import android.media.AudioManager
import java.util.concurrent.ConcurrentHashMap
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.suspendCancellableCoroutine
import org.webrtc.AudioSource
import org.webrtc.AudioTrack
import org.webrtc.Camera2Enumerator
import org.webrtc.DataChannel
import org.webrtc.DefaultVideoDecoderFactory
import org.webrtc.DefaultVideoEncoderFactory
import org.webrtc.EglBase
import org.webrtc.IceCandidate
import org.webrtc.MediaConstraints
import org.webrtc.MediaStream
import org.webrtc.PeerConnection
import org.webrtc.PeerConnectionFactory
import org.webrtc.RtpReceiver
import org.webrtc.SessionDescription
import org.webrtc.SdpObserver
import org.webrtc.SurfaceTextureHelper
import org.webrtc.VideoCapturer
import org.webrtc.VideoSource
import org.webrtc.VideoTrack
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

class WebRtcCallEngine(context: Context) : CallEngine {
    private val appContext = context.applicationContext
    private val audioManager = appContext.getSystemService(Context.AUDIO_SERVICE) as AudioManager
    private val eglBase = EglBase.create()
    private val factory: PeerConnectionFactory
    private val sessions = ConcurrentHashMap<String, MediaSession>()
    private val _events = MutableSharedFlow<CallEngineEvent>(
        replay = 0,
        extraBufferCapacity = 64,
        onBufferOverflow = BufferOverflow.DROP_OLDEST,
    )

    override val events: Flow<CallEngineEvent> = _events

    init {
        initialize(appContext)
        factory = PeerConnectionFactory.builder()
            .setVideoEncoderFactory(
                DefaultVideoEncoderFactory(
                    eglBase.eglBaseContext,
                    true,
                    true,
                ),
            )
            .setVideoDecoderFactory(DefaultVideoDecoderFactory(eglBase.eglBaseContext))
            .createPeerConnectionFactory()
    }

    override suspend fun startOutgoing(config: CallMediaConfig): String {
        val session = createSession(config)
        val offer = session.peerConnection.createOfferAwait(mediaConstraints(config.video))
        session.peerConnection.setLocalDescriptionAwait(offer)
        emit(CallEngineEvent.StateChanged(config.callId, "connecting"))
        return offer.description
    }

    override suspend fun acceptIncoming(config: CallMediaConfig, remoteOfferSdp: String): String {
        val session = createSession(config)
        session.peerConnection.setRemoteDescriptionAwait(
            SessionDescription(SessionDescription.Type.OFFER, remoteOfferSdp),
        )
        val answer = session.peerConnection.createAnswerAwait(mediaConstraints(config.video))
        session.peerConnection.setLocalDescriptionAwait(answer)
        emit(CallEngineEvent.StateChanged(config.callId, "connecting"))
        return answer.description
    }

    override suspend fun setRemoteAnswer(callId: String, remoteAnswerSdp: String) {
        val session = sessions[callId] ?: return
        session.peerConnection.setRemoteDescriptionAwait(
            SessionDescription(SessionDescription.Type.ANSWER, remoteAnswerSdp),
        )
        emit(CallEngineEvent.StateChanged(callId, "connected"))
    }

    override suspend fun addRemoteIceCandidate(callId: String, candidate: CallIceCandidate) {
        val session = sessions[callId] ?: return
        session.peerConnection.addIceCandidate(
            IceCandidate(
                candidate.sdpMid ?: "0",
                candidate.sdpMLineIndex,
                candidate.candidate,
            ),
        )
    }

    override fun setMicrophoneEnabled(callId: String, enabled: Boolean) {
        sessions[callId]?.audioTrack?.setEnabled(enabled)
    }

    override fun setCameraEnabled(callId: String, enabled: Boolean) {
        sessions[callId]?.videoTrack?.setEnabled(enabled)
    }

    override fun setSpeakerEnabled(enabled: Boolean) {
        @Suppress("DEPRECATION")
        audioManager.isSpeakerphoneOn = enabled
    }

    override fun release(callId: String) {
        sessions.remove(callId)?.dispose()
        emit(CallEngineEvent.StateChanged(callId, "ended"))
    }

    override fun dispose() {
        sessions.keys.toList().forEach(::release)
        factory.dispose()
        eglBase.release()
    }

    private fun createSession(config: CallMediaConfig): MediaSession {
        release(config.callId)
        val peerConnection = factory.createPeerConnection(
            PeerConnection.RTCConfiguration(config.iceServers.toRtcIceServers()).apply {
                sdpSemantics = PeerConnection.SdpSemantics.UNIFIED_PLAN
                continualGatheringPolicy = PeerConnection.ContinualGatheringPolicy.GATHER_CONTINUALLY
            },
            PeerObserver(config.callId),
        ) ?: error("PeerConnection indisponible")

        val streamId = "enigma-${config.callId}"
        val audioSource = factory.createAudioSource(MediaConstraints())
        val audioTrack = factory.createAudioTrack("audio-${config.callId}", audioSource)
        peerConnection.addTrack(audioTrack, listOf(streamId))

        val videoBundle = if (config.video) {
            createVideoBundle(config.callId).also {
                peerConnection.addTrack(it.track, listOf(streamId))
                emit(CallEngineEvent.LocalVideoTrackReady(config.callId, it.track))
            }
        } else {
            null
        }

        return MediaSession(
            peerConnection = peerConnection,
            audioSource = audioSource,
            audioTrack = audioTrack,
            videoBundle = videoBundle,
        ).also {
            sessions[config.callId] = it
        }
    }

    private fun createVideoBundle(callId: String): VideoBundle {
        val capturer = createCameraCapturer()
            ?: error("Caméra indisponible")
        val surfaceTextureHelper = SurfaceTextureHelper.create(
            "enigma-camera-$callId",
            eglBase.eglBaseContext,
        )
        val videoSource = factory.createVideoSource(false)
        capturer.initialize(surfaceTextureHelper, appContext, videoSource.capturerObserver)
        capturer.startCapture(DEFAULT_VIDEO_WIDTH, DEFAULT_VIDEO_HEIGHT, DEFAULT_VIDEO_FPS)
        val videoTrack = factory.createVideoTrack("video-$callId", videoSource)
        return VideoBundle(
            capturer = capturer,
            source = videoSource,
            track = videoTrack,
            textureHelper = surfaceTextureHelper,
        )
    }

    private fun createCameraCapturer(): VideoCapturer? {
        val enumerator = Camera2Enumerator(appContext)
        val frontCamera = enumerator.deviceNames.firstOrNull { enumerator.isFrontFacing(it) }
        val backCamera = enumerator.deviceNames.firstOrNull { enumerator.isBackFacing(it) }
        return listOfNotNull(frontCamera, backCamera)
            .firstNotNullOfOrNull { enumerator.createCapturer(it, null) }
    }

    private fun List<CallIceServer>.toRtcIceServers(): List<PeerConnection.IceServer> =
        map { server ->
            val builder = if (server.urls.size == 1) {
                PeerConnection.IceServer.builder(server.urls.first())
            } else {
                PeerConnection.IceServer.builder(server.urls)
            }
            builder
                .setUsername(server.username.orEmpty())
                .setPassword(server.credential.orEmpty())
                .createIceServer()
        }

    private fun mediaConstraints(video: Boolean): MediaConstraints =
        MediaConstraints().apply {
            mandatory.add(MediaConstraints.KeyValuePair("OfferToReceiveAudio", "true"))
            mandatory.add(MediaConstraints.KeyValuePair("OfferToReceiveVideo", video.toString()))
        }

    private fun emit(event: CallEngineEvent) {
        _events.tryEmit(event)
    }

    private inner class PeerObserver(
        private val callId: String,
    ) : PeerConnection.Observer {
        override fun onSignalingChange(newState: PeerConnection.SignalingState?) = Unit

        override fun onIceConnectionChange(newState: PeerConnection.IceConnectionState?) {
            val state = when (newState) {
                PeerConnection.IceConnectionState.CONNECTED,
                PeerConnection.IceConnectionState.COMPLETED,
                -> "connected"
                PeerConnection.IceConnectionState.FAILED -> "failed"
                PeerConnection.IceConnectionState.DISCONNECTED -> "disconnected"
                PeerConnection.IceConnectionState.CLOSED -> "ended"
                else -> "connecting"
            }
            emit(CallEngineEvent.StateChanged(callId, state))
        }

        override fun onIceConnectionReceivingChange(receiving: Boolean) = Unit

        override fun onIceGatheringChange(newState: PeerConnection.IceGatheringState?) = Unit

        override fun onIceCandidate(candidate: IceCandidate?) {
            if (candidate == null) return
            emit(
                CallEngineEvent.LocalIceCandidate(
                    callId = callId,
                    candidate = CallIceCandidate(
                        sdpMid = candidate.sdpMid,
                        sdpMLineIndex = candidate.sdpMLineIndex,
                        candidate = candidate.sdp,
                    ),
                ),
            )
        }

        override fun onIceCandidatesRemoved(candidates: Array<out IceCandidate>?) = Unit

        override fun onAddStream(stream: MediaStream?) = Unit

        override fun onRemoveStream(stream: MediaStream?) = Unit

        override fun onDataChannel(dataChannel: DataChannel?) = Unit

        override fun onRenegotiationNeeded() = Unit

        override fun onAddTrack(receiver: RtpReceiver?, mediaStreams: Array<out MediaStream>?) {
            val track = receiver?.track() as? VideoTrack ?: return
            emit(CallEngineEvent.RemoteVideoTrackReady(callId, track))
        }
    }

    private data class MediaSession(
        val peerConnection: PeerConnection,
        val audioSource: AudioSource,
        val audioTrack: AudioTrack,
        val videoBundle: VideoBundle?,
    ) {
        val videoTrack: VideoTrack?
            get() = videoBundle?.track

        fun dispose() {
            videoBundle?.dispose()
            audioTrack.dispose()
            audioSource.dispose()
            peerConnection.dispose()
        }
    }

    private data class VideoBundle(
        val capturer: VideoCapturer,
        val source: VideoSource,
        val track: VideoTrack,
        val textureHelper: SurfaceTextureHelper,
    ) {
        fun dispose() {
            runCatching { capturer.stopCapture() }
            capturer.dispose()
            track.dispose()
            source.dispose()
            textureHelper.dispose()
        }
    }

    private companion object {
        private const val DEFAULT_VIDEO_WIDTH = 1280
        private const val DEFAULT_VIDEO_HEIGHT = 720
        private const val DEFAULT_VIDEO_FPS = 30
        private var initialized = false

        @Synchronized
        fun initialize(context: Context) {
            if (initialized) return
            PeerConnectionFactory.initialize(
                PeerConnectionFactory.InitializationOptions.builder(context)
                    .createInitializationOptions(),
            )
            initialized = true
        }
    }
}

private suspend fun PeerConnection.createOfferAwait(
    constraints: MediaConstraints,
): SessionDescription = suspendCancellableCoroutine { continuation ->
    createOffer(object : SdpObserver {
        override fun onCreateSuccess(description: SessionDescription?) {
            if (description == null) {
                continuation.resumeWithException(IllegalStateException("Offer SDP vide"))
            } else {
                continuation.resume(description)
            }
        }

        override fun onSetSuccess() = Unit

        override fun onCreateFailure(error: String?) {
            continuation.resumeWithException(IllegalStateException(error ?: "Offer SDP non créée"))
        }

        override fun onSetFailure(error: String?) = Unit
    }, constraints)
}

private suspend fun PeerConnection.createAnswerAwait(
    constraints: MediaConstraints,
): SessionDescription = suspendCancellableCoroutine { continuation ->
    createAnswer(object : SdpObserver {
        override fun onCreateSuccess(description: SessionDescription?) {
            if (description == null) {
                continuation.resumeWithException(IllegalStateException("Answer SDP vide"))
            } else {
                continuation.resume(description)
            }
        }

        override fun onSetSuccess() = Unit

        override fun onCreateFailure(error: String?) {
            continuation.resumeWithException(IllegalStateException(error ?: "Answer SDP non créée"))
        }

        override fun onSetFailure(error: String?) = Unit
    }, constraints)
}

private suspend fun PeerConnection.setLocalDescriptionAwait(
    description: SessionDescription,
): Unit = suspendCancellableCoroutine { continuation ->
    setLocalDescription(object : SdpObserver {
        override fun onCreateSuccess(description: SessionDescription?) = Unit

        override fun onSetSuccess() {
            continuation.resume(Unit)
        }

        override fun onCreateFailure(error: String?) = Unit

        override fun onSetFailure(error: String?) {
            continuation.resumeWithException(IllegalStateException(error ?: "Local SDP refusée"))
        }
    }, description)
}

private suspend fun PeerConnection.setRemoteDescriptionAwait(
    description: SessionDescription,
): Unit = suspendCancellableCoroutine { continuation ->
    setRemoteDescription(object : SdpObserver {
        override fun onCreateSuccess(description: SessionDescription?) = Unit

        override fun onSetSuccess() {
            continuation.resume(Unit)
        }

        override fun onCreateFailure(error: String?) = Unit

        override fun onSetFailure(error: String?) {
            continuation.resumeWithException(IllegalStateException(error ?: "Remote SDP refusée"))
        }
    }, description)
}
