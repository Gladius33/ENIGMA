ALTER TABLE identity_keys
    ADD COLUMN registration_id INTEGER,
    ADD COLUMN protocol_device_id INTEGER;

ALTER TABLE identity_keys
    ADD CONSTRAINT identity_keys_signal_registration_id_check
        CHECK (registration_id IS NULL OR registration_id > 0),
    ADD CONSTRAINT identity_keys_signal_protocol_device_id_check
        CHECK (protocol_device_id IS NULL OR protocol_device_id BETWEEN 1 AND 127),
    ADD CONSTRAINT identity_keys_signal_metadata_pair_check
        CHECK (
            (registration_id IS NULL AND protocol_device_id IS NULL)
            OR (registration_id IS NOT NULL AND protocol_device_id IS NOT NULL)
        );

ALTER TABLE signed_prekeys
    ADD COLUMN kyber_key_id BIGINT,
    ADD COLUMN kyber_public_key TEXT,
    ADD COLUMN kyber_signature TEXT;

ALTER TABLE signed_prekeys
    ADD CONSTRAINT signed_prekeys_kyber_key_id_check
        CHECK (kyber_key_id IS NULL OR kyber_key_id >= 0),
    ADD CONSTRAINT signed_prekeys_kyber_metadata_all_or_none_check
        CHECK (
            (kyber_key_id IS NULL AND kyber_public_key IS NULL AND kyber_signature IS NULL)
            OR (kyber_key_id IS NOT NULL AND kyber_public_key IS NOT NULL AND kyber_signature IS NOT NULL)
        );
