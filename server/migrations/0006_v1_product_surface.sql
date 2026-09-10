CREATE TABLE contacts (
    owner_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    contact_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (owner_user_id, contact_user_id),
    CHECK (owner_user_id <> contact_user_id)
);

CREATE INDEX contacts_contact_user_id_idx ON contacts(contact_user_id);

CREATE TABLE groups (
    id UUID PRIMARY KEY,
    title TEXT NOT NULL,
    owner_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    archived_at TIMESTAMPTZ
);

CREATE TABLE group_members (
    group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role TEXT NOT NULL CHECK (role IN ('owner', 'admin', 'member')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    removed_at TIMESTAMPTZ,
    PRIMARY KEY (group_id, user_id)
);

CREATE INDEX group_members_user_id_idx ON group_members(user_id) WHERE removed_at IS NULL;

CREATE TABLE group_message_queue (
    id UUID PRIMARY KEY,
    group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    sender_device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    client_message_id UUID NOT NULL,
    message_type TEXT NOT NULL DEFAULT 'opaque',
    ciphertext TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    UNIQUE(sender_device_id, client_message_id)
);

CREATE INDEX group_message_queue_group_created_idx ON group_message_queue(group_id, created_at);
CREATE INDEX group_message_queue_expires_at_idx ON group_message_queue(expires_at);

CREATE TABLE group_receipts (
    id UUID PRIMARY KEY,
    message_id UUID NOT NULL,
    group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    recipient_device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    status TEXT NOT NULL CHECK (status IN ('delivered', 'read')),
    received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(message_id, recipient_device_id, status)
);

CREATE INDEX group_receipts_device_idx ON group_receipts(recipient_device_id);

CREATE TABLE channels (
    id UUID PRIMARY KEY,
    title TEXT NOT NULL,
    description TEXT,
    avatar_blob_id UUID,
    owner_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    archived_at TIMESTAMPTZ
);

CREATE TABLE channel_subscribers (
    channel_id UUID NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role TEXT NOT NULL CHECK (role IN ('owner', 'admin', 'subscriber')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    unsubscribed_at TIMESTAMPTZ,
    PRIMARY KEY (channel_id, user_id)
);

CREATE INDEX channel_subscribers_user_id_idx
    ON channel_subscribers(user_id)
    WHERE unsubscribed_at IS NULL;

CREATE TABLE channel_posts_queue (
    id UUID PRIMARY KEY,
    channel_id UUID NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
    sender_device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    client_post_id UUID NOT NULL,
    post_type TEXT NOT NULL DEFAULT 'opaque',
    ciphertext TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    UNIQUE(sender_device_id, client_post_id)
);

CREATE INDEX channel_posts_queue_channel_created_idx ON channel_posts_queue(channel_id, created_at);
CREATE INDEX channel_posts_queue_expires_at_idx ON channel_posts_queue(expires_at);

CREATE TABLE channel_post_receipts (
    id UUID PRIMARY KEY,
    post_id UUID NOT NULL,
    channel_id UUID NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
    recipient_device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    status TEXT NOT NULL CHECK (status IN ('delivered')),
    received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(post_id, recipient_device_id)
);

CREATE TABLE calls (
    id UUID PRIMARY KEY,
    creator_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    call_kind TEXT NOT NULL CHECK (call_kind IN ('audio', 'video')),
    state TEXT NOT NULL CHECK (state IN ('ringing', 'accepted', 'rejected', 'ended', 'expired')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE call_participants (
    call_id UUID NOT NULL REFERENCES calls(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role TEXT NOT NULL CHECK (role IN ('caller', 'callee')),
    joined_at TIMESTAMPTZ,
    left_at TIMESTAMPTZ,
    PRIMARY KEY (call_id, user_id)
);

CREATE INDEX call_participants_user_id_idx ON call_participants(user_id);

CREATE TABLE call_signaling_events (
    id UUID PRIMARY KEY,
    call_id UUID NOT NULL REFERENCES calls(id) ON DELETE CASCADE,
    sender_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    event_kind TEXT NOT NULL CHECK (event_kind IN ('offer', 'answer', 'ice', 'hangup', 'reject', 'accept')),
    payload TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX call_signaling_events_call_created_idx
    ON call_signaling_events(call_id, created_at);
