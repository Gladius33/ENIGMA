CREATE TABLE pairing_rendezvous (
    pairing_session_id UUID PRIMARY KEY,
    device_id UUID NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    platform TEXT NOT NULL,
    protocol_version INTEGER NOT NULL,
    min_supported_version INTEGER NOT NULL,
    capabilities BIGINT NOT NULL,
    expires_at_unix_ms BIGINT NOT NULL,
    pairing_public_key TEXT NOT NULL,
    target_identity_key TEXT NOT NULL,
    claim_secret_hash TEXT NOT NULL,
    candidate_commitment TEXT NOT NULL,
    authorized_user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    authorizing_device_id UUID REFERENCES devices(id) ON DELETE CASCADE,
    authorized_at TIMESTAMPTZ,
    claimed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (platform IN ('windows', 'linux')),
    CHECK (protocol_version >= 1),
    CHECK (min_supported_version >= 1),
    CHECK (min_supported_version <= protocol_version),
    CHECK (capabilities >= 0),
    CHECK (expires_at_unix_ms > 0),
    CHECK (length(claim_secret_hash) = 64),
    CHECK (authorized_at IS NULL OR authorized_user_id IS NOT NULL),
    CHECK (authorized_at IS NULL OR authorizing_device_id IS NOT NULL),
    CHECK (claimed_at IS NULL OR authorized_at IS NOT NULL)
);

CREATE INDEX pairing_rendezvous_expiry_idx
    ON pairing_rendezvous(expires_at_unix_ms);

CREATE INDEX pairing_rendezvous_authorized_user_idx
    ON pairing_rendezvous(authorized_user_id)
    WHERE authorized_user_id IS NOT NULL;
