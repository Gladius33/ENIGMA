ALTER TABLE calls
    ADD COLUMN IF NOT EXISTS bubble_id UUID;

ALTER TABLE call_signaling_events
    ADD COLUMN IF NOT EXISTS bubble_id UUID;

WITH referenced_users AS (
    SELECT creator_user_id AS user_id FROM calls
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
    SELECT creator_user_id AS user_id FROM calls
)
INSERT INTO bubble_relays (bubble_id, relay_id, role, priority, required, fallback_allowed)
SELECT b.id, '00000000-0000-0000-0000-000000000001', 'primary', 0, true, false
FROM bubbles b
JOIN referenced_users ru ON b.slug = 'main-' || replace(ru.user_id::text, '-', '')
ON CONFLICT (bubble_id, relay_id) DO NOTHING;

UPDATE calls c
SET bubble_id = b.id
FROM bubbles b
WHERE b.slug = 'main-' || replace(c.creator_user_id::text, '-', '')
  AND c.bubble_id IS NULL;

UPDATE call_signaling_events cse
SET bubble_id = c.bubble_id
FROM calls c
WHERE c.id = cse.call_id
  AND cse.bubble_id IS NULL;

ALTER TABLE calls
    ALTER COLUMN bubble_id SET NOT NULL;

ALTER TABLE call_signaling_events
    ALTER COLUMN bubble_id SET NOT NULL;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'calls_bubble_id_fkey'
    ) THEN
        ALTER TABLE calls
            ADD CONSTRAINT calls_bubble_id_fkey
            FOREIGN KEY (bubble_id) REFERENCES bubbles(id) ON DELETE RESTRICT;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'call_signaling_events_bubble_id_fkey'
    ) THEN
        ALTER TABLE call_signaling_events
            ADD CONSTRAINT call_signaling_events_bubble_id_fkey
            FOREIGN KEY (bubble_id) REFERENCES bubbles(id) ON DELETE RESTRICT;
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS calls_bubble_updated_idx
    ON calls(bubble_id, updated_at DESC);

CREATE INDEX IF NOT EXISTS call_signaling_events_bubble_call_created_idx
    ON call_signaling_events(bubble_id, call_id, created_at);
