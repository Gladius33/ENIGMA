ALTER TABLE message_queue
    ADD COLUMN IF NOT EXISTS bubble_id UUID;

ALTER TABLE message_receipts
    ADD COLUMN IF NOT EXISTS bubble_id UUID;

WITH referenced_users AS (
    SELECT d.user_id
    FROM message_queue mq
    JOIN devices d ON d.id = mq.sender_device_id
    UNION
    SELECT d.user_id
    FROM message_queue mq
    JOIN devices d ON d.id = mq.recipient_device_id
    UNION
    SELECT d.user_id
    FROM message_receipts mr
    JOIN devices d ON d.id = mr.recipient_device_id
    UNION
    SELECT d.user_id
    FROM message_receipts mr
    JOIN devices d ON d.id = mr.sender_device_id
    WHERE mr.sender_device_id IS NOT NULL
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
    SELECT d.user_id
    FROM message_queue mq
    JOIN devices d ON d.id = mq.sender_device_id
    UNION
    SELECT d.user_id
    FROM message_queue mq
    JOIN devices d ON d.id = mq.recipient_device_id
    UNION
    SELECT d.user_id
    FROM message_receipts mr
    JOIN devices d ON d.id = mr.recipient_device_id
    UNION
    SELECT d.user_id
    FROM message_receipts mr
    JOIN devices d ON d.id = mr.sender_device_id
    WHERE mr.sender_device_id IS NOT NULL
)
INSERT INTO bubble_relays (bubble_id, relay_id, role, priority, required, fallback_allowed)
SELECT b.id, '00000000-0000-0000-0000-000000000001', 'primary', 0, true, false
FROM bubbles b
JOIN referenced_users ru ON b.slug = 'main-' || replace(ru.user_id::text, '-', '')
ON CONFLICT (bubble_id, relay_id) DO NOTHING;

UPDATE message_queue mq
SET bubble_id = b.id
FROM devices sender
JOIN bubbles b ON b.slug = 'main-' || replace(sender.user_id::text, '-', '')
WHERE sender.id = mq.sender_device_id
  AND mq.bubble_id IS NULL;

WITH receipt_bubbles AS (
    SELECT mr.id, COALESCE(mq.bubble_id, sender_b.id, recipient_b.id) AS bubble_id
    FROM message_receipts mr
    JOIN devices recipient ON recipient.id = mr.recipient_device_id
    LEFT JOIN devices sender ON sender.id = mr.sender_device_id
    LEFT JOIN bubbles sender_b ON sender_b.slug = 'main-' || replace(sender.user_id::text, '-', '')
    LEFT JOIN bubbles recipient_b ON recipient_b.slug = 'main-' || replace(recipient.user_id::text, '-', '')
    LEFT JOIN message_queue mq ON mq.id = mr.message_id
    WHERE mr.bubble_id IS NULL
)
UPDATE message_receipts mr
SET bubble_id = receipt_bubbles.bubble_id
FROM receipt_bubbles
WHERE mr.id = receipt_bubbles.id
  AND receipt_bubbles.bubble_id IS NOT NULL;

ALTER TABLE message_queue
    ALTER COLUMN bubble_id SET NOT NULL;

ALTER TABLE message_receipts
    ALTER COLUMN bubble_id SET NOT NULL;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'message_queue_bubble_id_fkey'
    ) THEN
        ALTER TABLE message_queue
            ADD CONSTRAINT message_queue_bubble_id_fkey
            FOREIGN KEY (bubble_id) REFERENCES bubbles(id) ON DELETE RESTRICT;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'message_receipts_bubble_id_fkey'
    ) THEN
        ALTER TABLE message_receipts
            ADD CONSTRAINT message_receipts_bubble_id_fkey
            FOREIGN KEY (bubble_id) REFERENCES bubbles(id) ON DELETE RESTRICT;
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS message_queue_recipient_bubble_created_idx
    ON message_queue(recipient_device_id, bubble_id, created_at);

CREATE INDEX IF NOT EXISTS message_queue_sender_bubble_created_idx
    ON message_queue(sender_device_id, bubble_id, created_at);

CREATE INDEX IF NOT EXISTS message_receipts_sender_bubble_delivered_idx
    ON message_receipts(sender_device_id, bubble_id, delivered_at DESC)
    WHERE sender_device_id IS NOT NULL;
