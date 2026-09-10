ALTER TABLE attachments
    ADD COLUMN status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'verified', 'expired', 'deleted')),
    ADD COLUMN completed_at TIMESTAMPTZ,
    ADD COLUMN verified_at TIMESTAMPTZ,
    ADD COLUMN actual_size_bytes BIGINT,
    ADD COLUMN actual_sha256 TEXT,
    ADD COLUMN last_error TEXT;

CREATE INDEX attachments_status_expires_at_idx
    ON attachments(status, expires_at);
