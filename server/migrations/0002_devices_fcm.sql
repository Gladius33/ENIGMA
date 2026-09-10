ALTER TABLE devices
    ADD COLUMN fcm_token TEXT NULL,
    ADD COLUMN fcm_token_updated_at TIMESTAMPTZ NULL,
    ADD COLUMN push_enabled BOOLEAN NOT NULL DEFAULT TRUE;

CREATE INDEX devices_user_platform_active_idx
    ON devices(user_id, platform, created_at)
    WHERE revoked_at IS NULL;

