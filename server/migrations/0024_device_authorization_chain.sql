CREATE TABLE device_authorizations (
    device_id UUID PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    authorizing_device_id UUID NOT NULL REFERENCES devices(id) ON DELETE RESTRICT,
    pairing_session_id UUID NOT NULL UNIQUE,
    protocol_version INTEGER NOT NULL,
    min_supported_version INTEGER NOT NULL,
    capabilities BIGINT NOT NULL,
    target_identity_key TEXT NOT NULL,
    authorizer_identity_key TEXT NOT NULL,
    canonical_payload TEXT NOT NULL,
    authorizer_signature TEXT NOT NULL,
    issued_at_unix_ms BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (device_id <> authorizing_device_id),
    CHECK (protocol_version >= 1),
    CHECK (min_supported_version >= 1),
    CHECK (min_supported_version <= protocol_version),
    CHECK (capabilities >= 0)
);

CREATE INDEX device_authorizations_authorizer_idx
    ON device_authorizations(authorizing_device_id);
