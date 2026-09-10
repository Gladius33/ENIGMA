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
class AppDatabaseMigrationTest {
    @get:Rule
    val tempFolder = TemporaryFolder()

    @Test
    fun migration3To4AddsLocalSafetyVerificationColumns() {
        val dbPath = File(tempFolder.root, DB_NAME).absolutePath
        openDatabase(
            dbPath = dbPath,
            callback = object : SupportSQLiteOpenHelper.Callback(3) {
                override fun onCreate(db: SupportSQLiteDatabase) {
                    createVersion3ContactDevices(db)
                    db.execSQL(
                        "INSERT INTO contact_devices (device_id, contact_user_id, identity_key) " +
                            "VALUES ('device-1', 'contact-1', 'identity-1')",
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
            callback = object : SupportSQLiteOpenHelper.Callback(4) {
                override fun onCreate(db: SupportSQLiteDatabase) = Unit

                override fun onUpgrade(db: SupportSQLiteDatabase, oldVersion: Int, newVersion: Int) {
                    assertEquals(3, oldVersion)
                    assertEquals(4, newVersion)
                    AppDatabase.MIGRATION_3_4.migrate(db)
                }
            },
        )

        migrated.writableDatabase.query(
            "SELECT identity_key, verified_safety_number, verified_at " +
                "FROM contact_devices WHERE device_id = 'device-1'",
        ).use { cursor ->
            assertTrue(cursor.moveToFirst())
            assertEquals("identity-1", cursor.getString(0))
            assertTrue(cursor.isNull(1))
            assertTrue(cursor.isNull(2))
        }
        migrated.close()
    }

    @Test
    fun migration1To7PreservesLegacyContactDeviceAndAddsNewColumns() {
        val dbPath = File(tempFolder.root, "legacy-$DB_NAME").absolutePath
        openDatabase(
            dbPath = dbPath,
            callback = object : SupportSQLiteOpenHelper.Callback(1) {
                override fun onCreate(db: SupportSQLiteDatabase) {
                    createVersion1ContactDevices(db)
                    createVersion6Conversations(db)
                    db.execSQL(
                        "INSERT INTO contact_devices (device_id, contact_user_id) " +
                            "VALUES ('device-1', 'contact-1')",
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
            callback = object : SupportSQLiteOpenHelper.Callback(7) {
                override fun onCreate(db: SupportSQLiteDatabase) = Unit

                override fun onUpgrade(db: SupportSQLiteDatabase, oldVersion: Int, newVersion: Int) {
                    assertEquals(1, oldVersion)
                    assertEquals(7, newVersion)
                    AppDatabase.MIGRATION_1_2.migrate(db)
                    AppDatabase.MIGRATION_2_3.migrate(db)
                    AppDatabase.MIGRATION_3_4.migrate(db)
                    AppDatabase.MIGRATION_4_5.migrate(db)
                    AppDatabase.MIGRATION_5_6.migrate(db)
                    AppDatabase.MIGRATION_6_7.migrate(db)
                }
            },
        )

        migrated.writableDatabase.query(
            "SELECT contact_user_id, identity_key, verified_safety_number, verified_at, trust_state " +
                "FROM contact_devices WHERE device_id = 'device-1'",
        ).use { cursor ->
            assertTrue(cursor.moveToFirst())
            assertEquals("contact-1", cursor.getString(0))
            assertTrue(cursor.isNull(1))
            assertTrue(cursor.isNull(2))
            assertTrue(cursor.isNull(3))
            assertEquals("UNVERIFIED", cursor.getString(4))
        }
        migrated.writableDatabase.query(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'bubbles'",
        ).use { cursor ->
            assertTrue(cursor.moveToFirst())
        }
        migrated.close()
    }

    @Test
    fun migration6To7AddsBubbleIdToConversations() {
        val dbPath = File(tempFolder.root, "bubble-id-$DB_NAME").absolutePath
        openDatabase(
            dbPath = dbPath,
            callback = object : SupportSQLiteOpenHelper.Callback(6) {
                override fun onCreate(db: SupportSQLiteDatabase) {
                    createVersion6Conversations(db)
                    db.execSQL(
                        "INSERT INTO conversations (id, contact_user_id, contact_public_id, updated_at) " +
                            "VALUES ('conversation-1', 'contact-1', 'alice', 123)",
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
            callback = object : SupportSQLiteOpenHelper.Callback(7) {
                override fun onCreate(db: SupportSQLiteDatabase) = Unit

                override fun onUpgrade(db: SupportSQLiteDatabase, oldVersion: Int, newVersion: Int) {
                    assertEquals(6, oldVersion)
                    assertEquals(7, newVersion)
                    AppDatabase.MIGRATION_6_7.migrate(db)
                }
            },
        )

        migrated.writableDatabase.query(
            "SELECT bubble_id FROM conversations WHERE id = 'conversation-1'",
        ).use { cursor ->
            assertTrue(cursor.moveToFirst())
            assertEquals("main-bubble", cursor.getString(0))
        }
        migrated.close()
    }

    @Test
    fun migration4To5AddsTrustStateAndIdentityEvents() {
        val dbPath = File(tempFolder.root, "trust-$DB_NAME").absolutePath
        openDatabase(
            dbPath = dbPath,
            callback = object : SupportSQLiteOpenHelper.Callback(4) {
                override fun onCreate(db: SupportSQLiteDatabase) {
                    createVersion4ContactDevices(db)
                    db.execSQL(
                        "INSERT INTO contact_devices " +
                            "(device_id, contact_user_id, identity_key, verified_safety_number, verified_at) " +
                            "VALUES ('device-1', 'contact-1', 'identity-1', 'safety-1', 123)",
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
            callback = object : SupportSQLiteOpenHelper.Callback(5) {
                override fun onCreate(db: SupportSQLiteDatabase) = Unit

                override fun onUpgrade(db: SupportSQLiteDatabase, oldVersion: Int, newVersion: Int) {
                    assertEquals(4, oldVersion)
                    assertEquals(5, newVersion)
                    AppDatabase.MIGRATION_4_5.migrate(db)
                }
            },
        )

        migrated.writableDatabase.query(
            "SELECT trust_state, registration_id, protocol_device_id FROM contact_devices WHERE device_id = 'device-1'",
        ).use { cursor ->
            assertTrue(cursor.moveToFirst())
            assertEquals("UNVERIFIED", cursor.getString(0))
            assertTrue(cursor.isNull(1))
            assertTrue(cursor.isNull(2))
        }
        migrated.writableDatabase.query(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'contact_device_identity_events'",
        ).use { cursor ->
            assertTrue(cursor.moveToFirst())
        }
        migrated.close()
    }

    @Test
    fun migration5To6AddsBubbleAndRelayTables() {
        val dbPath = File(tempFolder.root, "bubbles-$DB_NAME").absolutePath
        openDatabase(
            dbPath = dbPath,
            callback = object : SupportSQLiteOpenHelper.Callback(5) {
                override fun onCreate(db: SupportSQLiteDatabase) = Unit

                override fun onUpgrade(db: SupportSQLiteDatabase, oldVersion: Int, newVersion: Int) = Unit
            },
        ).apply {
            writableDatabase
            close()
        }

        val migrated = openDatabase(
            dbPath = dbPath,
            callback = object : SupportSQLiteOpenHelper.Callback(6) {
                override fun onCreate(db: SupportSQLiteDatabase) = Unit

                override fun onUpgrade(db: SupportSQLiteDatabase, oldVersion: Int, newVersion: Int) {
                    assertEquals(5, oldVersion)
                    assertEquals(6, newVersion)
                    AppDatabase.MIGRATION_5_6.migrate(db)
                }
            },
        )

        listOf("relays", "bubbles", "bubble_members", "bubble_relays", "bubble_services").forEach { table ->
            migrated.writableDatabase.query(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name = '$table'",
            ).use { cursor ->
                assertTrue("missing table $table", cursor.moveToFirst())
            }
        }
        migrated.close()
    }

    @Test
    fun migration7To8AddsBubbleScopeToGroupsAndChannels() {
        val dbPath = File(tempFolder.root, "group-channel-bubbles-$DB_NAME").absolutePath
        openDatabase(
            dbPath = dbPath,
            callback = object : SupportSQLiteOpenHelper.Callback(7) {
                override fun onCreate(db: SupportSQLiteDatabase) {
                    createVersion7GroupsChannels(db)
                    db.execSQL(
                        "INSERT INTO groups (id, title, owner_user_id, created_at) " +
                            "VALUES ('group-1', 'Projet', 'owner-1', '2026-07-01T10:00:00Z')",
                    )
                    db.execSQL(
                        "INSERT INTO group_messages " +
                            "(id, group_id, sender_device_id, message_type, ciphertext, created_at) " +
                            "VALUES ('group-message-1', 'group-1', 'device-1', 'opaque', 'ciphertext', " +
                            "'2026-07-01T10:01:00Z')",
                    )
                    db.execSQL(
                        "INSERT INTO channels (id, title, description, owner_user_id, created_at) " +
                            "VALUES ('channel-1', 'Annonces', NULL, 'owner-1', '2026-07-01T10:00:00Z')",
                    )
                    db.execSQL(
                        "INSERT INTO channel_posts " +
                            "(id, channel_id, sender_device_id, post_type, ciphertext, created_at) " +
                            "VALUES ('post-1', 'channel-1', 'device-1', 'opaque', 'ciphertext', " +
                            "'2026-07-01T10:02:00Z')",
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
            callback = object : SupportSQLiteOpenHelper.Callback(8) {
                override fun onCreate(db: SupportSQLiteDatabase) = Unit

                override fun onUpgrade(db: SupportSQLiteDatabase, oldVersion: Int, newVersion: Int) {
                    assertEquals(7, oldVersion)
                    assertEquals(8, newVersion)
                    AppDatabase.MIGRATION_7_8.migrate(db)
                }
            },
        )

        listOf(
            "groups",
            "group_messages",
            "channels",
            "channel_posts",
        ).forEach { table ->
            migrated.writableDatabase.query("SELECT bubble_id FROM $table LIMIT 1").use { cursor ->
                assertTrue("missing bubble_id for $table", cursor.moveToFirst())
                assertEquals("main-bubble", cursor.getString(0))
            }
        }
        migrated.close()
    }

    @Test
    fun migration8To9AddsBubbleScopeToCalls() {
        val dbPath = File(tempFolder.root, "call-bubbles-$DB_NAME").absolutePath
        openDatabase(
            dbPath = dbPath,
            callback = object : SupportSQLiteOpenHelper.Callback(8) {
                override fun onCreate(db: SupportSQLiteDatabase) {
                    createVersion8CallEvents(db)
                    db.execSQL(
                        "INSERT INTO call_events " +
                            "(id, call_id, call_kind, state, event_kind, created_at) " +
                            "VALUES ('call-event-1', 'call-1', 'audio', 'ringing', 'created', " +
                            "'2026-07-01T10:00:00Z')",
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
            callback = object : SupportSQLiteOpenHelper.Callback(9) {
                override fun onCreate(db: SupportSQLiteDatabase) = Unit

                override fun onUpgrade(db: SupportSQLiteDatabase, oldVersion: Int, newVersion: Int) {
                    assertEquals(8, oldVersion)
                    assertEquals(9, newVersion)
                    AppDatabase.MIGRATION_8_9.migrate(db)
                }
            },
        )

        migrated.writableDatabase.query("SELECT bubble_id FROM call_events WHERE id = 'call-event-1'").use {
            assertTrue(it.moveToFirst())
            assertEquals("main-bubble", it.getString(0))
        }
        migrated.close()
    }

    @Test
    fun migration9To10AddsBubbleScopeToAttachments() {
        val dbPath = File(tempFolder.root, "attachment-bubbles-$DB_NAME").absolutePath
        openDatabase(
            dbPath = dbPath,
            callback = object : SupportSQLiteOpenHelper.Callback(9) {
                override fun onCreate(db: SupportSQLiteDatabase) {
                    createVersion9Attachments(db)
                    db.execSQL(
                        "INSERT INTO attachments " +
                            "(blob_id, content_type, size_bytes, sha256, `key`, nonce, download_secret) " +
                            "VALUES ('blob-1', 'application/octet-stream', 64, 'sha256', " +
                            "'key', 'nonce', 'download-secret')",
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
            callback = object : SupportSQLiteOpenHelper.Callback(10) {
                override fun onCreate(db: SupportSQLiteDatabase) = Unit

                override fun onUpgrade(db: SupportSQLiteDatabase, oldVersion: Int, newVersion: Int) {
                    assertEquals(9, oldVersion)
                    assertEquals(10, newVersion)
                    AppDatabase.MIGRATION_9_10.migrate(db)
                }
            },
        )

        migrated.writableDatabase.query("SELECT bubble_id FROM attachments WHERE blob_id = 'blob-1'").use {
            assertTrue(it.moveToFirst())
            assertEquals("main-bubble", it.getString(0))
        }
        migrated.close()
    }

    @Test
    fun migration10To11AddsEncryptedLocalBodyToGroupMessages() {
        val dbPath = File(tempFolder.root, "group-message-local-body-$DB_NAME").absolutePath
        openDatabase(
            dbPath = dbPath,
            callback = object : SupportSQLiteOpenHelper.Callback(10) {
                override fun onCreate(db: SupportSQLiteDatabase) {
                    createVersion10GroupMessages(db)
                    db.execSQL(
                        "INSERT INTO group_messages " +
                            "(id, group_id, bubble_id, sender_device_id, message_type, ciphertext, created_at) " +
                            "VALUES ('message-1', 'group-1', 'bubble-1', 'device-1', " +
                            "'opaque', 'ciphertext', '2026-07-01T10:00:00Z')",
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
            callback = object : SupportSQLiteOpenHelper.Callback(11) {
                override fun onCreate(db: SupportSQLiteDatabase) = Unit

                override fun onUpgrade(db: SupportSQLiteDatabase, oldVersion: Int, newVersion: Int) {
                    assertEquals(10, oldVersion)
                    assertEquals(11, newVersion)
                    AppDatabase.MIGRATION_10_11.migrate(db)
                }
            },
        )

        migrated.writableDatabase.query(
            "SELECT encrypted_local_body FROM group_messages WHERE id = 'message-1'",
        ).use {
            assertTrue(it.moveToFirst())
            assertEquals("", it.getString(0))
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

    private fun createVersion3ContactDevices(db: SupportSQLiteDatabase) {
        db.execSQL(
            "CREATE TABLE IF NOT EXISTS contact_devices (" +
                "device_id TEXT NOT NULL, " +
                "contact_user_id TEXT NOT NULL, " +
                "identity_key TEXT, " +
                "PRIMARY KEY(device_id)" +
                ")",
        )
        db.execSQL(
            "CREATE INDEX IF NOT EXISTS index_contact_devices_contact_user_id " +
                "ON contact_devices(contact_user_id)",
        )
    }

    private fun createVersion4ContactDevices(db: SupportSQLiteDatabase) {
        db.execSQL(
            "CREATE TABLE IF NOT EXISTS contact_devices (" +
                "device_id TEXT NOT NULL, " +
                "contact_user_id TEXT NOT NULL, " +
                "identity_key TEXT, " +
                "verified_safety_number TEXT, " +
                "verified_at INTEGER, " +
                "PRIMARY KEY(device_id)" +
                ")",
        )
        db.execSQL(
            "CREATE INDEX IF NOT EXISTS index_contact_devices_contact_user_id " +
                "ON contact_devices(contact_user_id)",
        )
    }

    private fun createVersion1ContactDevices(db: SupportSQLiteDatabase) {
        db.execSQL(
            "CREATE TABLE IF NOT EXISTS contact_devices (" +
                "device_id TEXT NOT NULL, " +
                "contact_user_id TEXT NOT NULL, " +
                "PRIMARY KEY(device_id)" +
                ")",
        )
        db.execSQL(
            "CREATE INDEX IF NOT EXISTS index_contact_devices_contact_user_id " +
                "ON contact_devices(contact_user_id)",
        )
    }

    private fun createVersion6Conversations(db: SupportSQLiteDatabase) {
        db.execSQL(
            "CREATE TABLE IF NOT EXISTS conversations (" +
                "id TEXT NOT NULL, " +
                "contact_user_id TEXT NOT NULL, " +
                "contact_public_id TEXT NOT NULL, " +
                "updated_at INTEGER NOT NULL, " +
                "PRIMARY KEY(id)" +
                ")",
        )
    }

    private fun createVersion7GroupsChannels(db: SupportSQLiteDatabase) {
        db.execSQL(
            "CREATE TABLE IF NOT EXISTS groups (" +
                "id TEXT NOT NULL, " +
                "title TEXT NOT NULL, " +
                "owner_user_id TEXT NOT NULL, " +
                "created_at TEXT NOT NULL, " +
                "PRIMARY KEY(id)" +
                ")",
        )
        db.execSQL(
            "CREATE TABLE IF NOT EXISTS group_messages (" +
                "id TEXT NOT NULL, " +
                "group_id TEXT NOT NULL, " +
                "sender_device_id TEXT NOT NULL, " +
                "message_type TEXT NOT NULL, " +
                "ciphertext TEXT NOT NULL, " +
                "created_at TEXT NOT NULL, " +
                "PRIMARY KEY(id)" +
                ")",
        )
        db.execSQL(
            "CREATE INDEX IF NOT EXISTS index_group_messages_group_id_created_at " +
                "ON group_messages(group_id, created_at)",
        )
        db.execSQL(
            "CREATE TABLE IF NOT EXISTS channels (" +
                "id TEXT NOT NULL, " +
                "title TEXT NOT NULL, " +
                "description TEXT, " +
                "owner_user_id TEXT NOT NULL, " +
                "created_at TEXT NOT NULL, " +
                "PRIMARY KEY(id)" +
                ")",
        )
        db.execSQL(
            "CREATE TABLE IF NOT EXISTS channel_posts (" +
                "id TEXT NOT NULL, " +
                "channel_id TEXT NOT NULL, " +
                "sender_device_id TEXT NOT NULL, " +
                "post_type TEXT NOT NULL, " +
                "ciphertext TEXT NOT NULL, " +
                "created_at TEXT NOT NULL, " +
                "PRIMARY KEY(id)" +
                ")",
        )
        db.execSQL(
            "CREATE INDEX IF NOT EXISTS index_channel_posts_channel_id_created_at " +
                "ON channel_posts(channel_id, created_at)",
        )
    }

    private fun createVersion8CallEvents(db: SupportSQLiteDatabase) {
        db.execSQL(
            "CREATE TABLE IF NOT EXISTS call_events (" +
                "id TEXT NOT NULL, " +
                "call_id TEXT NOT NULL, " +
                "call_kind TEXT NOT NULL, " +
                "state TEXT NOT NULL, " +
                "event_kind TEXT NOT NULL, " +
                "created_at TEXT NOT NULL, " +
                "PRIMARY KEY(id)" +
                ")",
        )
        db.execSQL(
            "CREATE INDEX IF NOT EXISTS index_call_events_call_id_created_at " +
                "ON call_events(call_id, created_at)",
        )
    }

    private fun createVersion10GroupMessages(db: SupportSQLiteDatabase) {
        db.execSQL(
            "CREATE TABLE IF NOT EXISTS group_messages (" +
                "id TEXT NOT NULL, " +
                "group_id TEXT NOT NULL, " +
                "sender_device_id TEXT NOT NULL, " +
                "message_type TEXT NOT NULL, " +
                "ciphertext TEXT NOT NULL, " +
                "created_at TEXT NOT NULL, " +
                "bubble_id TEXT NOT NULL DEFAULT 'main-bubble', " +
                "PRIMARY KEY(id)" +
                ")",
        )
        db.execSQL(
            "CREATE INDEX IF NOT EXISTS index_group_messages_group_id_created_at " +
                "ON group_messages(group_id, created_at)",
        )
        db.execSQL(
            "CREATE INDEX IF NOT EXISTS index_group_messages_bubble_id_group_id_created_at " +
                "ON group_messages(bubble_id, group_id, created_at)",
        )
    }

    private fun createVersion9Attachments(db: SupportSQLiteDatabase) {
        db.execSQL(
            "CREATE TABLE IF NOT EXISTS attachments (" +
                "blob_id TEXT NOT NULL, " +
                "content_type TEXT NOT NULL, " +
                "size_bytes INTEGER NOT NULL, " +
                "sha256 TEXT NOT NULL, " +
                "`key` TEXT NOT NULL, " +
                "nonce TEXT NOT NULL, " +
                "download_secret TEXT NOT NULL, " +
                "PRIMARY KEY(blob_id)" +
                ")",
        )
    }

    private companion object {
        const val DB_NAME = "migration-test.db"
    }
}
