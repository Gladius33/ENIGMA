package com.enigma.securechat.data.db

import androidx.room.Database
import androidx.room.migration.Migration
import androidx.room.RoomDatabase
import androidx.sqlite.db.SupportSQLiteDatabase

@Database(
    entities = [
        ContactEntity::class,
        ContactDeviceEntity::class,
        ContactDeviceIdentityEventEntity::class,
        ConversationEntity::class,
        MessageEntity::class,
        GroupEntity::class,
        GroupMemberEntity::class,
        GroupMessageEntity::class,
        ChannelEntity::class,
        ChannelPostEntity::class,
        CallEventEntity::class,
        AttachmentEntity::class,
        RelayEntity::class,
        BubbleEntity::class,
        BubbleMemberEntity::class,
        BubbleRelayEntity::class,
        BubbleServiceEntity::class,
    ],
    version = 12,
    exportSchema = true,
)
abstract class AppDatabase : RoomDatabase() {
    abstract fun contactDao(): ContactDao
    abstract fun contactDeviceDao(): ContactDeviceDao
    abstract fun conversationDao(): ConversationDao
    abstract fun messageDao(): MessageDao
    abstract fun groupDao(): GroupDao
    abstract fun groupMessageDao(): GroupMessageDao
    abstract fun channelDao(): ChannelDao
    abstract fun channelPostDao(): ChannelPostDao
    abstract fun callEventDao(): CallEventDao
    abstract fun attachmentDao(): AttachmentDao
    abstract fun relayDao(): RelayDao
    abstract fun bubbleDao(): BubbleDao

    companion object {
        val MIGRATION_1_2 = object : Migration(1, 2) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL(
                    "CREATE TABLE IF NOT EXISTS `groups` (`id` TEXT NOT NULL, `title` TEXT NOT NULL, `owner_user_id` TEXT NOT NULL, `created_at` TEXT NOT NULL, PRIMARY KEY(`id`))",
                )
                db.execSQL(
                    "CREATE TABLE IF NOT EXISTS `group_members` (`group_id` TEXT NOT NULL, `user_id` TEXT NOT NULL, `public_id` TEXT NOT NULL, `role` TEXT NOT NULL, PRIMARY KEY(`group_id`, `user_id`))",
                )
                db.execSQL(
                    "CREATE TABLE IF NOT EXISTS `group_messages` (`id` TEXT NOT NULL, `group_id` TEXT NOT NULL, `sender_device_id` TEXT NOT NULL, `message_type` TEXT NOT NULL, `ciphertext` TEXT NOT NULL, `created_at` TEXT NOT NULL, PRIMARY KEY(`id`))",
                )
                db.execSQL(
                    "CREATE INDEX IF NOT EXISTS `index_group_messages_group_id_created_at` ON `group_messages` (`group_id`, `created_at`)",
                )
                db.execSQL(
                    "CREATE TABLE IF NOT EXISTS `channels` (`id` TEXT NOT NULL, `title` TEXT NOT NULL, `description` TEXT, `owner_user_id` TEXT NOT NULL, `created_at` TEXT NOT NULL, PRIMARY KEY(`id`))",
                )
                db.execSQL(
                    "CREATE TABLE IF NOT EXISTS `channel_posts` (`id` TEXT NOT NULL, `channel_id` TEXT NOT NULL, `sender_device_id` TEXT NOT NULL, `post_type` TEXT NOT NULL, `ciphertext` TEXT NOT NULL, `created_at` TEXT NOT NULL, PRIMARY KEY(`id`))",
                )
                db.execSQL(
                    "CREATE INDEX IF NOT EXISTS `index_channel_posts_channel_id_created_at` ON `channel_posts` (`channel_id`, `created_at`)",
                )
                db.execSQL(
                    "CREATE TABLE IF NOT EXISTS `call_events` (`id` TEXT NOT NULL, `call_id` TEXT NOT NULL, `call_kind` TEXT NOT NULL, `state` TEXT NOT NULL, `event_kind` TEXT NOT NULL, `created_at` TEXT NOT NULL, PRIMARY KEY(`id`))",
                )
                db.execSQL(
                    "CREATE INDEX IF NOT EXISTS `index_call_events_call_id_created_at` ON `call_events` (`call_id`, `created_at`)",
                )
                db.execSQL(
                    "CREATE TABLE IF NOT EXISTS `attachments` (`blob_id` TEXT NOT NULL, `content_type` TEXT NOT NULL, `size_bytes` INTEGER NOT NULL, `sha256` TEXT NOT NULL, `key` TEXT NOT NULL, `nonce` TEXT NOT NULL, `download_secret` TEXT NOT NULL, PRIMARY KEY(`blob_id`))",
                )
            }
        }

        val MIGRATION_2_3 = object : Migration(2, 3) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL("ALTER TABLE `contact_devices` ADD COLUMN `identity_key` TEXT")
            }
        }

        val MIGRATION_3_4 = object : Migration(3, 4) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL("ALTER TABLE `contact_devices` ADD COLUMN `verified_safety_number` TEXT")
                db.execSQL("ALTER TABLE `contact_devices` ADD COLUMN `verified_at` INTEGER")
            }
        }

        val MIGRATION_4_5 = object : Migration(4, 5) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL("ALTER TABLE `contact_devices` ADD COLUMN `registration_id` INTEGER")
                db.execSQL("ALTER TABLE `contact_devices` ADD COLUMN `protocol_device_id` INTEGER")
                db.execSQL("ALTER TABLE `contact_devices` ADD COLUMN `trust_state` TEXT NOT NULL DEFAULT 'UNVERIFIED'")
                db.execSQL("ALTER TABLE `contact_devices` ADD COLUMN `identity_first_seen_at` INTEGER")
                db.execSQL("ALTER TABLE `contact_devices` ADD COLUMN `identity_last_changed_at` INTEGER")
                db.execSQL("ALTER TABLE `contact_devices` ADD COLUMN `blocked_at` INTEGER")
                db.execSQL(
                    "CREATE TABLE IF NOT EXISTS `contact_device_identity_events` (" +
                        "`id` TEXT NOT NULL, " +
                        "`contact_user_id` TEXT NOT NULL, " +
                        "`device_id` TEXT NOT NULL, " +
                        "`event_type` TEXT NOT NULL, " +
                        "`old_identity_key_hash` TEXT, " +
                        "`new_identity_key_hash` TEXT, " +
                        "`created_at` INTEGER NOT NULL, " +
                        "PRIMARY KEY(`id`)" +
                        ")",
                )
                db.execSQL(
                    "CREATE INDEX IF NOT EXISTS `index_contact_device_identity_events_contact_user_id_device_id_created_at` " +
                        "ON `contact_device_identity_events` (`contact_user_id`, `device_id`, `created_at`)",
                )
            }
        }

        val MIGRATION_5_6 = object : Migration(5, 6) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL(
                    "CREATE TABLE IF NOT EXISTS `relays` (" +
                        "`id` TEXT NOT NULL, " +
                        "`name` TEXT NOT NULL, " +
                        "`url` TEXT NOT NULL, " +
                        "`public_key` TEXT, " +
                        "`type` TEXT NOT NULL, " +
                        "`trust_state` TEXT NOT NULL, " +
                        "`is_official` INTEGER NOT NULL, " +
                        "`created_at` INTEGER NOT NULL, " +
                        "`last_seen_at` INTEGER, " +
                        "PRIMARY KEY(`id`)" +
                        ")",
                )
                db.execSQL("CREATE INDEX IF NOT EXISTS `index_relays_type` ON `relays` (`type`)")
                db.execSQL("CREATE INDEX IF NOT EXISTS `index_relays_is_official` ON `relays` (`is_official`)")
                db.execSQL(
                    "CREATE TABLE IF NOT EXISTS `bubbles` (" +
                        "`id` TEXT NOT NULL, " +
                        "`slug` TEXT NOT NULL, " +
                        "`name` TEXT NOT NULL, " +
                        "`description` TEXT, " +
                        "`mode` TEXT NOT NULL, " +
                        "`visibility` TEXT NOT NULL, " +
                        "`join_policy` TEXT NOT NULL, " +
                        "`index_policy` TEXT NOT NULL, " +
                        "`owner_identity_id` TEXT, " +
                        "`public_key` TEXT, " +
                        "`created_at` INTEGER NOT NULL, " +
                        "`updated_at` INTEGER NOT NULL, " +
                        "`deleted_at` INTEGER, " +
                        "PRIMARY KEY(`id`)" +
                        ")",
                )
                db.execSQL("CREATE UNIQUE INDEX IF NOT EXISTS `index_bubbles_slug` ON `bubbles` (`slug`)")
                db.execSQL("CREATE INDEX IF NOT EXISTS `index_bubbles_mode` ON `bubbles` (`mode`)")
                db.execSQL(
                    "CREATE TABLE IF NOT EXISTS `bubble_members` (" +
                        "`bubble_id` TEXT NOT NULL, " +
                        "`identity_id` TEXT NOT NULL, " +
                        "`role` TEXT NOT NULL, " +
                        "`status` TEXT NOT NULL, " +
                        "`joined_at` INTEGER NOT NULL, " +
                        "PRIMARY KEY(`bubble_id`, `identity_id`)" +
                        ")",
                )
                db.execSQL(
                    "CREATE TABLE IF NOT EXISTS `bubble_relays` (" +
                        "`bubble_id` TEXT NOT NULL, " +
                        "`relay_id` TEXT NOT NULL, " +
                        "`role` TEXT NOT NULL, " +
                        "`priority` INTEGER NOT NULL, " +
                        "`required` INTEGER NOT NULL, " +
                        "`fallback_allowed` INTEGER NOT NULL, " +
                        "PRIMARY KEY(`bubble_id`, `relay_id`)" +
                        ")",
                )
                db.execSQL(
                    "CREATE TABLE IF NOT EXISTS `bubble_services` (" +
                        "`id` TEXT NOT NULL, " +
                        "`bubble_id` TEXT NOT NULL, " +
                        "`service_type` TEXT NOT NULL, " +
                        "`name` TEXT NOT NULL, " +
                        "`slug` TEXT NOT NULL, " +
                        "`visibility` TEXT NOT NULL, " +
                        "`index_policy` TEXT NOT NULL, " +
                        "`created_at` INTEGER NOT NULL, " +
                        "PRIMARY KEY(`id`)" +
                        ")",
                )
                db.execSQL(
                    "CREATE UNIQUE INDEX IF NOT EXISTS `index_bubble_services_bubble_id_slug` " +
                        "ON `bubble_services` (`bubble_id`, `slug`)",
                )
            }
        }

        val MIGRATION_6_7 = object : Migration(6, 7) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL(
                    "ALTER TABLE `conversations` ADD COLUMN `bubble_id` TEXT NOT NULL DEFAULT 'main-bubble'",
                )
                db.execSQL(
                    "CREATE INDEX IF NOT EXISTS `index_conversations_bubble_id_updated_at` " +
                        "ON `conversations` (`bubble_id`, `updated_at`)",
                )
                db.execSQL(
                    "CREATE UNIQUE INDEX IF NOT EXISTS `index_conversations_contact_user_id_bubble_id` " +
                        "ON `conversations` (`contact_user_id`, `bubble_id`)",
                )
            }
        }

        val MIGRATION_7_8 = object : Migration(7, 8) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL("ALTER TABLE `groups` ADD COLUMN `bubble_id` TEXT NOT NULL DEFAULT 'main-bubble'")
                db.execSQL(
                    "CREATE INDEX IF NOT EXISTS `index_groups_bubble_id_created_at` " +
                        "ON `groups` (`bubble_id`, `created_at`)",
                )
                db.execSQL(
                    "ALTER TABLE `group_messages` ADD COLUMN `bubble_id` TEXT NOT NULL DEFAULT 'main-bubble'",
                )
                db.execSQL(
                    "CREATE INDEX IF NOT EXISTS `index_group_messages_bubble_id_group_id_created_at` " +
                        "ON `group_messages` (`bubble_id`, `group_id`, `created_at`)",
                )
                db.execSQL("ALTER TABLE `channels` ADD COLUMN `bubble_id` TEXT NOT NULL DEFAULT 'main-bubble'")
                db.execSQL(
                    "CREATE INDEX IF NOT EXISTS `index_channels_bubble_id_created_at` " +
                        "ON `channels` (`bubble_id`, `created_at`)",
                )
                db.execSQL(
                    "ALTER TABLE `channel_posts` ADD COLUMN `bubble_id` TEXT NOT NULL DEFAULT 'main-bubble'",
                )
                db.execSQL(
                    "CREATE INDEX IF NOT EXISTS `index_channel_posts_bubble_id_channel_id_created_at` " +
                        "ON `channel_posts` (`bubble_id`, `channel_id`, `created_at`)",
                )
            }
        }

        val MIGRATION_8_9 = object : Migration(8, 9) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL(
                    "ALTER TABLE `call_events` ADD COLUMN `bubble_id` TEXT NOT NULL DEFAULT 'main-bubble'",
                )
                db.execSQL(
                    "CREATE INDEX IF NOT EXISTS `index_call_events_bubble_id_created_at` " +
                        "ON `call_events` (`bubble_id`, `created_at`)",
                )
            }
        }

        val MIGRATION_9_10 = object : Migration(9, 10) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL(
                    "ALTER TABLE `attachments` ADD COLUMN `bubble_id` TEXT NOT NULL DEFAULT 'main-bubble'",
                )
                db.execSQL(
                    "CREATE INDEX IF NOT EXISTS `index_attachments_bubble_id` " +
                        "ON `attachments` (`bubble_id`)",
                )
            }
        }

        val MIGRATION_10_11 = object : Migration(10, 11) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL(
                    "ALTER TABLE `group_messages` ADD COLUMN `encrypted_local_body` TEXT NOT NULL DEFAULT ''",
                )
            }
        }

        val MIGRATION_11_12 = object : Migration(11, 12) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL("ALTER TABLE `messages` ADD COLUMN `client_message_id` TEXT NOT NULL DEFAULT ''")
                db.execSQL("UPDATE `messages` SET `client_message_id` = `id` WHERE `client_message_id` = ''")
                db.execSQL("ALTER TABLE `messages` ADD COLUMN `transport` TEXT NOT NULL DEFAULT 'RELAY'")
                db.execSQL(
                    "ALTER TABLE `messages` ADD COLUMN `peer_identity_state` TEXT NOT NULL DEFAULT 'UNKNOWN'",
                )
                db.execSQL(
                    "CREATE UNIQUE INDEX IF NOT EXISTS `index_messages_sender_device_id_client_message_id` " +
                        "ON `messages` (`sender_device_id`, `client_message_id`)",
                )
            }
        }
    }
}
