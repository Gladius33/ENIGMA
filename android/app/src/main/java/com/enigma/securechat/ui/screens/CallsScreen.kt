package com.enigma.securechat.ui.screens

import android.Manifest
import android.content.pm.PackageManager
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.viewinterop.AndroidView
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import com.enigma.securechat.ui.viewmodel.CallsViewModel
import org.webrtc.EglBase
import org.webrtc.RendererCommon
import org.webrtc.SurfaceViewRenderer
import org.webrtc.VideoTrack

@Composable
fun CallsScreen(viewModel: CallsViewModel, onBack: () -> Unit) {
    val events by viewModel.events.collectAsState()
    val state by viewModel.state.collectAsState()
    val context = LocalContext.current
    var calleeUserId by remember { mutableStateOf("") }
    var pendingVideo by remember { mutableStateOf(false) }
    val selectedCallId = state.selectedCallId.orEmpty()
    val permissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions(),
    ) { grants ->
        val audioGranted = grants[Manifest.permission.RECORD_AUDIO]
            ?: context.hasPermission(Manifest.permission.RECORD_AUDIO)
        val cameraGranted = grants[Manifest.permission.CAMERA]
            ?: context.hasPermission(Manifest.permission.CAMERA)
        if (audioGranted && (!pendingVideo || cameraGranted)) {
            viewModel.start(calleeUserId, video = pendingVideo)
        } else {
            viewModel.permissionDenied(video = pendingVideo)
        }
    }

    fun startWithPermissions(video: Boolean) {
        pendingVideo = video
        val required = buildList {
            add(Manifest.permission.RECORD_AUDIO)
            if (video) add(Manifest.permission.CAMERA)
        }
        val missing = required.filterNot(context::hasPermission)
        if (missing.isEmpty()) {
            viewModel.start(calleeUserId, video = video)
        } else {
            permissionLauncher.launch(missing.toTypedArray())
        }
    }

    Column(Modifier.fillMaxSize().padding(16.dp)) {
        Row(Modifier.fillMaxWidth()) {
            Text("Appels", style = MaterialTheme.typography.headlineSmall, modifier = Modifier.weight(1f))
            OutlinedButton(onClick = onBack) { Text("Retour") }
        }
        Spacer(Modifier.height(8.dp))
        OutlinedTextField(
            value = calleeUserId,
            onValueChange = { calleeUserId = it },
            modifier = Modifier.fillMaxWidth(),
            label = { Text("User ID du contact") },
            singleLine = true,
        )
        Spacer(Modifier.height(8.dp))
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(onClick = { startWithPermissions(video = false) }, modifier = Modifier.weight(1f)) {
                Text("Audio")
            }
            Button(onClick = { startWithPermissions(video = true) }, modifier = Modifier.weight(1f)) {
                Text("Vidéo")
            }
        }
        Spacer(Modifier.height(10.dp))
        Text("État média : ${state.mediaState}", style = MaterialTheme.typography.bodyMedium)
        Text(
            text = "Appel actif : ${selectedCallId.ifBlank { "aucun" }}",
            style = MaterialTheme.typography.bodySmall,
        )
        Spacer(Modifier.height(8.dp))
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            Button(
                onClick = { viewModel.accept(selectedCallId) },
                enabled = selectedCallId.isNotBlank(),
                modifier = Modifier.weight(1f),
            ) { Text("Accepter") }
            OutlinedButton(
                onClick = { viewModel.reject(selectedCallId) },
                enabled = selectedCallId.isNotBlank(),
                modifier = Modifier.weight(1f),
            ) { Text("Refuser") }
            OutlinedButton(
                onClick = { viewModel.hangup(selectedCallId) },
                enabled = selectedCallId.isNotBlank(),
                modifier = Modifier.weight(1f),
            ) { Text("Raccrocher") }
        }
        Spacer(Modifier.height(8.dp))
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            OutlinedButton(
                onClick = viewModel::toggleMicrophone,
                enabled = selectedCallId.isNotBlank(),
                modifier = Modifier.weight(1f),
            ) { Text(if (state.microphoneEnabled) "Mute" else "Unmute") }
            OutlinedButton(
                onClick = viewModel::toggleCamera,
                enabled = selectedCallId.isNotBlank(),
                modifier = Modifier.weight(1f),
            ) { Text(if (state.cameraEnabled) "Caméra off" else "Caméra on") }
            OutlinedButton(
                onClick = viewModel::toggleSpeaker,
                modifier = Modifier.weight(1f),
            ) { Text(if (state.speakerEnabled) "HP off" else "HP on") }
        }
        Spacer(Modifier.height(8.dp))
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            OutlinedButton(
                onClick = { viewModel.syncSignaling(selectedCallId) },
                enabled = selectedCallId.isNotBlank(),
                modifier = Modifier.weight(1f),
            ) { Text("Synchroniser") }
            OutlinedButton(onClick = viewModel::loadTurn, modifier = Modifier.weight(1f)) {
                Text("Tester TURN")
            }
        }
        state.turnSummary?.let {
            Spacer(Modifier.height(4.dp))
            Text(it, style = MaterialTheme.typography.bodySmall)
        }
        state.error?.let {
            Spacer(Modifier.height(4.dp))
            Text(it, color = MaterialTheme.colorScheme.error)
        }
        if (state.localVideoTrack != null || state.remoteVideoTrack != null) {
            Spacer(Modifier.height(10.dp))
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                WebRtcVideoTile(
                    track = state.remoteVideoTrack,
                    label = "Distant",
                    mirror = false,
                    modifier = Modifier.weight(1f),
                )
                WebRtcVideoTile(
                    track = state.localVideoTrack,
                    label = "Local",
                    mirror = true,
                    modifier = Modifier.weight(1f),
                )
            }
        }
        Spacer(Modifier.height(10.dp))
        LazyColumn {
            items(events, key = { it.id }) { event ->
                Column(Modifier.fillMaxWidth().padding(vertical = 10.dp)) {
                    Row(Modifier.fillMaxWidth()) {
                        Column(Modifier.weight(1f)) {
                            Text("${event.eventKind} · ${event.state}")
                            Text(event.callId, style = MaterialTheme.typography.bodySmall)
                        }
                        Spacer(Modifier.width(8.dp))
                        OutlinedButton(onClick = { viewModel.select(event.callId) }) {
                            Text("Sélectionner")
                        }
                    }
                }
                HorizontalDivider()
            }
        }
    }
}

private fun android.content.Context.hasPermission(permission: String): Boolean =
    ContextCompat.checkSelfPermission(this, permission) == PackageManager.PERMISSION_GRANTED

@Composable
private fun WebRtcVideoTile(
    track: VideoTrack?,
    label: String,
    mirror: Boolean,
    modifier: Modifier = Modifier,
) {
    Surface(
        modifier = modifier.aspectRatio(3f / 4f),
        color = MaterialTheme.colorScheme.surfaceVariant,
    ) {
        Box {
            if (track == null) {
                Text(
                    label,
                    modifier = Modifier.padding(12.dp),
                    style = MaterialTheme.typography.bodySmall,
                )
            } else {
                val eglBase = remember { EglBase.create() }
                var renderer by remember { mutableStateOf<SurfaceViewRenderer?>(null) }
                AndroidView(
                    modifier = Modifier.fillMaxSize(),
                    factory = { context ->
                        SurfaceViewRenderer(context).apply {
                            init(eglBase.eglBaseContext, null)
                            setScalingType(RendererCommon.ScalingType.SCALE_ASPECT_FILL)
                            setMirror(mirror)
                            renderer = this
                        }
                    },
                    update = { renderer ->
                        renderer.setMirror(mirror)
                    },
                )
                DisposableEffect(track, renderer) {
                    val activeRenderer = renderer
                    if (activeRenderer != null) {
                        track.addSink(activeRenderer)
                    }
                    onDispose {
                        if (activeRenderer != null) {
                            track.removeSink(activeRenderer)
                        }
                    }
                }
                DisposableEffect(Unit) {
                    onDispose {
                        renderer?.release()
                        eglBase.release()
                    }
                }
            }
        }
    }
}
