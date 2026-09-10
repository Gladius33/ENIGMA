CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE users (
    id UUID PRIMARY KEY,
    public_id TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    disabled_at TIMESTAMPTZ
);

CREATE TABLE sessions (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ
);

CREATE INDEX sessions_user_id_idx ON sessions(user_id);

CREATE TABLE devices (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    display_name TEXT NOT NULL,
    platform TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ
);

CREATE INDEX devices_user_id_idx ON devices(user_id);

CREATE TABLE identity_keys (
    device_id UUID PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    public_key TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE signed_prekeys (
    device_id UUID PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    key_id BIGINT NOT NULL,
    public_key TEXT NOT NULL,
    signature TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE one_time_prekeys (
    id UUID PRIMARY KEY,
    device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    key_id BIGINT NOT NULL,
    public_key TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(device_id, key_id)
);

CREATE INDEX one_time_prekeys_device_id_idx ON one_time_prekeys(device_id, created_at);

CREATE TABLE message_queue (
    id UUID PRIMARY KEY,
    sender_device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    recipient_device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    ciphertext TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX message_queue_recipient_idx ON message_queue(recipient_device_id, created_at);
CREATE INDEX message_queue_expires_at_idx ON message_queue(expires_at);

CREATE TABLE message_receipts (
    id UUID PRIMARY KEY,
    message_id UUID NOT NULL,
    recipient_device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    status TEXT NOT NULL CHECK (status IN ('delivered')),
    received_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX message_receipts_message_id_idx ON message_receipts(message_id);
CREATE INDEX message_receipts_recipient_device_id_idx ON message_receipts(recipient_device_id);

CREATE TABLE attachments (
    id UUID PRIMARY KEY,
    blob_id UUID NOT NULL UNIQUE,
    owner_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    object_key TEXT NOT NULL UNIQUE,
    size_bytes BIGINT NOT NULL CHECK (size_bytes > 0),
    sha256 TEXT NOT NULL,
    content_type TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX attachments_owner_id_idx ON attachments(owner_id);
CREATE INDEX attachments_expires_at_idx ON attachments(expires_at);
