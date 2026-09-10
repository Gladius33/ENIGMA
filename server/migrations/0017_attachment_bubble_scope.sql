ALTER TABLE attachments
    ADD COLUMN IF NOT EXISTS bubble_id UUID;

WITH referenced_users AS (
    SELECT owner_id AS user_id FROM attachments
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
    SELECT owner_id AS user_id FROM attachments
)
INSERT INTO bubble_relays (bubble_id, relay_id, role, priority, required, fallback_allowed)
SELECT b.id, '00000000-0000-0000-0000-000000000001', 'primary', 0, true, false
FROM bubbles b
JOIN referenced_users ru ON b.slug = 'main-' || replace(ru.user_id::text, '-', '')
ON CONFLICT (bubble_id, relay_id) DO NOTHING;

UPDATE attachments a
SET bubble_id = b.id
FROM bubbles b
WHERE b.slug = 'main-' || replace(a.owner_id::text, '-', '')
  AND a.bubble_id IS NULL;

ALTER TABLE attachments
    ALTER COLUMN bubble_id SET NOT NULL;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'attachments_bubble_id_fkey'
    ) THEN
        ALTER TABLE attachments
            ADD CONSTRAINT attachments_bubble_id_fkey
            FOREIGN KEY (bubble_id) REFERENCES bubbles(id) ON DELETE RESTRICT;
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS attachments_bubble_status_expires_at_idx
    ON attachments(bubble_id, status, expires_at);
