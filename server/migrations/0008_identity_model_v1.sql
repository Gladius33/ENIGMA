ALTER TABLE users
    ADD COLUMN IF NOT EXISTS display_name TEXT,
    ADD COLUMN IF NOT EXISTS canonical_handle TEXT,
    ADD COLUMN IF NOT EXISTS public_handle TEXT,
    ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'active',
    ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS recovery_key_verifier TEXT;

ALTER TABLE devices
    ADD COLUMN IF NOT EXISTS device_public_key TEXT;

UPDATE users
SET
    display_name = COALESCE(display_name, public_id),
    canonical_handle = COALESCE(canonical_handle, lower(public_id)),
    public_handle = COALESCE(public_handle, '@' || lower(public_id)),
    status = COALESCE(status, 'active'),
    updated_at = COALESCE(updated_at, created_at);

ALTER TABLE users
    ALTER COLUMN display_name SET NOT NULL,
    ALTER COLUMN canonical_handle SET NOT NULL,
    ALTER COLUMN public_handle SET NOT NULL;

ALTER TABLE users
    DROP CONSTRAINT IF EXISTS users_status_check;

ALTER TABLE users
    ADD CONSTRAINT users_status_check CHECK (status IN ('active', 'deleted'));

CREATE UNIQUE INDEX IF NOT EXISTS users_canonical_handle_unique_idx
    ON users(canonical_handle);

CREATE TABLE IF NOT EXISTS identity_tombstones (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    canonical_handle TEXT NOT NULL UNIQUE,
    handle_hash TEXT NOT NULL UNIQUE,
    deleted_identity_id UUID NOT NULL,
    deleted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    reason TEXT NOT NULL
);
