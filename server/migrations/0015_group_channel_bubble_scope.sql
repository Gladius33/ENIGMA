ALTER TABLE groups
    ADD COLUMN IF NOT EXISTS bubble_id UUID;

ALTER TABLE group_message_queue
    ADD COLUMN IF NOT EXISTS bubble_id UUID;

ALTER TABLE group_receipts
    ADD COLUMN IF NOT EXISTS bubble_id UUID;

ALTER TABLE channels
    ADD COLUMN IF NOT EXISTS bubble_id UUID;

ALTER TABLE channel_posts_queue
    ADD COLUMN IF NOT EXISTS bubble_id UUID;

ALTER TABLE channel_post_receipts
    ADD COLUMN IF NOT EXISTS bubble_id UUID;

WITH referenced_users AS (
    SELECT owner_user_id AS user_id FROM groups
    UNION
    SELECT owner_user_id AS user_id FROM channels
),
main_bubbles AS (
    INSERT INTO bubbles
        (id, slug, name, description, mode, visibility, join_policy, index_policy, owner_identity_id)
    SELECT
        gen_random_uuid(),
        'main-' || replace(user_id::text, '-', ''),
        'Main Bubble',
        'Conversations Enigma globales',
        'MAIN_GLOBAL',
        'PRIVATE',
        'CLOSED',
        'INDEX_FORBIDDEN',
        user_id
    FROM referenced_users
    ON CONFLICT (slug) DO UPDATE
    SET owner_identity_id = COALESCE(bubbles.owner_identity_id, EXCLUDED.owner_identity_id),
        deleted_at = NULL,
        updated_at = now()
    RETURNING id, owner_identity_id
)
INSERT INTO bubble_members (bubble_id, identity_id, role, status)
SELECT id, owner_identity_id, 'owner', 'active'
FROM main_bubbles
WHERE owner_identity_id IS NOT NULL
ON CONFLICT (bubble_id, identity_id)
DO UPDATE SET status = 'active';

WITH referenced_users AS (
    SELECT owner_user_id AS user_id FROM groups
    UNION
    SELECT owner_user_id AS user_id FROM channels
)
INSERT INTO bubble_relays (bubble_id, relay_id, role, priority, required, fallback_allowed)
SELECT b.id, '00000000-0000-0000-0000-000000000001', 'primary', 0, true, false
FROM bubbles b
JOIN referenced_users ru ON b.slug = 'main-' || replace(ru.user_id::text, '-', '')
ON CONFLICT (bubble_id, relay_id) DO NOTHING;

UPDATE groups g
SET bubble_id = b.id
FROM bubbles b
WHERE b.slug = 'main-' || replace(g.owner_user_id::text, '-', '')
  AND g.bubble_id IS NULL;

UPDATE group_message_queue gm
SET bubble_id = g.bubble_id
FROM groups g
WHERE g.id = gm.group_id
  AND gm.bubble_id IS NULL;

UPDATE group_receipts gr
SET bubble_id = g.bubble_id
FROM groups g
WHERE g.id = gr.group_id
  AND gr.bubble_id IS NULL;

UPDATE channels c
SET bubble_id = b.id
FROM bubbles b
WHERE b.slug = 'main-' || replace(c.owner_user_id::text, '-', '')
  AND c.bubble_id IS NULL;

UPDATE channel_posts_queue cp
SET bubble_id = c.bubble_id
FROM channels c
WHERE c.id = cp.channel_id
  AND cp.bubble_id IS NULL;

UPDATE channel_post_receipts cpr
SET bubble_id = c.bubble_id
FROM channels c
WHERE c.id = cpr.channel_id
  AND cpr.bubble_id IS NULL;

ALTER TABLE groups
    ALTER COLUMN bubble_id SET NOT NULL;

ALTER TABLE group_message_queue
    ALTER COLUMN bubble_id SET NOT NULL;

ALTER TABLE group_receipts
    ALTER COLUMN bubble_id SET NOT NULL;

ALTER TABLE channels
    ALTER COLUMN bubble_id SET NOT NULL;

ALTER TABLE channel_posts_queue
    ALTER COLUMN bubble_id SET NOT NULL;

ALTER TABLE channel_post_receipts
    ALTER COLUMN bubble_id SET NOT NULL;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'groups_bubble_id_fkey'
    ) THEN
        ALTER TABLE groups
            ADD CONSTRAINT groups_bubble_id_fkey
            FOREIGN KEY (bubble_id) REFERENCES bubbles(id) ON DELETE RESTRICT;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'group_message_queue_bubble_id_fkey'
    ) THEN
        ALTER TABLE group_message_queue
            ADD CONSTRAINT group_message_queue_bubble_id_fkey
            FOREIGN KEY (bubble_id) REFERENCES bubbles(id) ON DELETE RESTRICT;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'group_receipts_bubble_id_fkey'
    ) THEN
        ALTER TABLE group_receipts
            ADD CONSTRAINT group_receipts_bubble_id_fkey
            FOREIGN KEY (bubble_id) REFERENCES bubbles(id) ON DELETE RESTRICT;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'channels_bubble_id_fkey'
    ) THEN
        ALTER TABLE channels
            ADD CONSTRAINT channels_bubble_id_fkey
            FOREIGN KEY (bubble_id) REFERENCES bubbles(id) ON DELETE RESTRICT;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'channel_posts_queue_bubble_id_fkey'
    ) THEN
        ALTER TABLE channel_posts_queue
            ADD CONSTRAINT channel_posts_queue_bubble_id_fkey
            FOREIGN KEY (bubble_id) REFERENCES bubbles(id) ON DELETE RESTRICT;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'channel_post_receipts_bubble_id_fkey'
    ) THEN
        ALTER TABLE channel_post_receipts
            ADD CONSTRAINT channel_post_receipts_bubble_id_fkey
            FOREIGN KEY (bubble_id) REFERENCES bubbles(id) ON DELETE RESTRICT;
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS groups_member_bubble_updated_idx
    ON groups(bubble_id, updated_at DESC)
    WHERE archived_at IS NULL;

CREATE INDEX IF NOT EXISTS group_message_queue_bubble_group_created_idx
    ON group_message_queue(bubble_id, group_id, created_at);

CREATE INDEX IF NOT EXISTS group_receipts_device_bubble_idx
    ON group_receipts(recipient_device_id, bubble_id);

CREATE INDEX IF NOT EXISTS channels_bubble_created_idx
    ON channels(bubble_id, created_at DESC)
    WHERE archived_at IS NULL;

CREATE INDEX IF NOT EXISTS channel_posts_queue_bubble_channel_created_idx
    ON channel_posts_queue(bubble_id, channel_id, created_at);

CREATE INDEX IF NOT EXISTS channel_post_receipts_device_bubble_idx
    ON channel_post_receipts(recipient_device_id, bubble_id);
