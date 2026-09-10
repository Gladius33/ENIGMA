package com.enigma.securechat.data

import androidx.sqlite.db.SupportSQLiteDatabase
import androidx.sqlite.db.SupportSQLiteOpenHelper
import androidx.sqlite.db.framework.FrameworkSQLiteOpenHelperFactory
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.enigma.securechat.data.db.AppDatabase
import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class AppDatabaseMigration11To12Test {
    @get:Rule
    val tempFolder = TemporaryFolder()

    @Test
    fun migration11To12AddsClientIdentityAndTransportMetadata() {
        val dbPath = File(tempFolder.root, "messages-11-12.db").absolutePath
        openDatabase(
            dbPath = dbPath,
            callback = object : SupportSQLiteOpenHelper.Callback(11) {
                override fun onCreate(db: SupportSQLiteDatabase) {
                    db.execSQL(
                        "CREATE TABLE messages (" +
                            "id TEXT NOT NULL PRIMARY KEY, " +
                            "remote_message_id TEXT, " +
                            "conversation_id TEXT NOT NULL, " +
                            "sender_device_id TEXT, " +
                            "recipient_device_id TEXT, " +
                            "direction TEXT NOT NULL, " +
                            "status TEXT NOT NULL, " +
                            "encrypted_local_body TEXT NOT NULL, " +
                            "transport_ciphertext TEXT, " +
                            "created_at INTEGER NOT NULL" +
                            ")",
                    )
                    db.execSQL(
                        "INSERT INTO messages " +
                            "(id, remote_message_id, conversation_id, sender_device_id, recipient_device_id, " +
                            "direction, status, encrypted_local_body, transport_ciphertext, created_at) " +
                            "VALUES ('message-1', NULL, 'conversation-1', 'device-a', 'device-b', " +
                            "'INBOUND', 'DELIVERED', 'local', 'transport', 123)",
                    )
                }

                override fun onUpgrade(db: SupportSQLiteDatabase, oldVersion: Int, newVersion: Int) = Unit
            },
        ).apply {
            writableDatabase
            close()
        }

        val migrated = openDatabase(
            dbPath = dbPath,
            callback = object : SupportSQLiteOpenHelper.Callback(12) {
                override fun onCreate(db: SupportSQLiteDatabase) = Unit

                override fun onUpgrade(db: SupportSQLiteDatabase, oldVersion: Int, newVersion: Int) {
                    assertEquals(11, oldVersion)
                    assertEquals(12, newVersion)
                    AppDatabase.MIGRATION_11_12.migrate(db)
                }
            },
        )

        migrated.writableDatabase.query(
            "SELECT client_message_id, transport, peer_identity_state " +
                "FROM messages WHERE id = 'message-1'",
        ).use { cursor ->
            assertTrue(cursor.moveToFirst())
            assertEquals("message-1", cursor.getString(0))
            assertEquals("RELAY", cursor.getString(1))
            assertEquals("UNKNOWN", cursor.getString(2))
        }
        migrated.writableDatabase.query(
            "SELECT name FROM sqlite_master " +
                "WHERE type = 'index' AND name = 'index_messages_sender_device_id_client_message_id'",
        ).use { cursor ->
            assertTrue(cursor.moveToFirst())
        }
        migrated.close()
    }

    private fun openDatabase(
        dbPath: String,
        callback: SupportSQLiteOpenHelper.Callback,
    ): SupportSQLiteOpenHelper {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        return FrameworkSQLiteOpenHelperFactory()
            .create(
                SupportSQLiteOpenHelper.Configuration.builder(context)
                    .name(dbPath)
                    .callback(callback)
                    .build(),
            )
    }
}
