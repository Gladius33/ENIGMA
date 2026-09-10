package com.enigma.securechat.network.fcm

import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import androidx.core.app.NotificationManagerCompat
import androidx.core.app.NotificationCompat
import com.enigma.securechat.R
import com.enigma.securechat.di.EnigmaApplication
import com.enigma.securechat.network.SafeLog
import com.google.firebase.messaging.FirebaseMessagingService
import com.google.firebase.messaging.RemoteMessage
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch

class EnigmaFirebaseMessagingService : FirebaseMessagingService() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    override fun onNewToken(token: String) {
        SafeLog.info("FCM", "FCM token refreshed: ${SafeLog.redactedId(token)}")
        scope.launch {
            val container = (application as EnigmaApplication).container
            container.deviceRepository.updateFcmToken(token)
        }
    }

    override fun onMessageReceived(message: RemoteMessage) {
        val type = message.data["type"]
        if (type == "sync_hint" || type == "wake") {
            scope.launch {
                val container = (application as EnigmaApplication).container
                container.messagesRepository.syncPending()
                container.messagesRepository.syncReceipts()
                container.messagesRepository.retryPendingOutbound()
                container.contactsRepository.syncContacts()
            }
            showNotification()
        }
    }

    private fun showNotification() {
        val channelId = "messages"
        val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        manager.createNotificationChannel(
            NotificationChannel(
                channelId,
                getString(R.string.notification_channel_messages),
                NotificationManager.IMPORTANCE_DEFAULT,
            ),
        )
        if (!NotificationManagerCompat.from(this).areNotificationsEnabled()) {
            return
        }
        val notification = NotificationCompat.Builder(this, channelId)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle(getString(R.string.app_name))
            .setContentText(getString(R.string.notification_sync_hint))
            .setAutoCancel(true)
            .build()
        runCatching { manager.notify(1001, notification) }
    }
}
