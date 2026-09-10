-- Existing invalid avatar pointers must not prevent rollout of the invariant.
-- The trigger also serializes avatar binding against attachment purge via KEY SHARE.
UPDATE channels c
SET avatar_blob_id = NULL
WHERE c.avatar_blob_id IS NOT NULL
  AND NOT EXISTS (
      SELECT 1
      FROM attachments a
      WHERE a.blob_id = c.avatar_blob_id
        AND a.owner_id = c.owner_user_id
        AND a.bubble_id = c.bubble_id
        AND a.status = 'verified'
        AND a.expires_at > now()
  );

CREATE OR REPLACE FUNCTION enforce_channel_avatar_integrity()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.avatar_blob_id IS NULL THEN
        RETURN NEW;
    END IF;

    PERFORM 1
    FROM attachments a
    WHERE a.blob_id = NEW.avatar_blob_id
      AND a.owner_id = NEW.owner_user_id
      AND a.bubble_id = NEW.bubble_id
      AND a.status = 'verified'
      AND a.expires_at > now()
    FOR KEY SHARE;

    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'INVALID_CHANNEL_AVATAR';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER channels_avatar_integrity
BEFORE INSERT OR UPDATE OF avatar_blob_id, bubble_id, owner_user_id
ON channels
FOR EACH ROW
EXECUTE FUNCTION enforce_channel_avatar_integrity();
