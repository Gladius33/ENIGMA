CREATE TABLE relays (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL,
    url TEXT NOT NULL,
    public_key TEXT,
    type TEXT NOT NULL CHECK (type IN ('OFFICIAL', 'CUSTOM', 'COMMUNITY', 'PRIVATE', 'ORGANIZATION', 'LOCAL')),
    trust_level TEXT NOT NULL CHECK (trust_level IN ('UNVERIFIED', 'VERIFIED', 'BLOCKED')),
    is_official BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at TIMESTAMPTZ
);

CREATE INDEX relays_type_idx ON relays(type);
CREATE UNIQUE INDEX relays_single_official_idx ON relays(is_official) WHERE is_official;

INSERT INTO relays (id, name, url, type, trust_level, is_official, last_seen_at)
VALUES (
    '00000000-0000-0000-0000-000000000001',
    'Relais officiel Enigma',
    'https://relay.example.invalid/',
    'OFFICIAL',
    'VERIFIED',
    true,
    now()
);

CREATE TABLE bubbles (
    id UUID PRIMARY KEY,
    slug TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    mode TEXT NOT NULL CHECK (mode IN ('MAIN_GLOBAL', 'PRIVATE_CONNECTED', 'PRIVATE_ISOLATED', 'COMMUNITY', 'ORGANIZATION')),
    visibility TEXT NOT NULL CHECK (visibility IN ('PUBLIC', 'UNLISTED', 'PRIVATE', 'SECRET')),
    join_policy TEXT NOT NULL CHECK (join_policy IN ('OPEN', 'REQUEST_APPROVAL', 'INVITE_ONLY', 'ADMIN_MANAGED', 'CLOSED')),
    index_policy TEXT NOT NULL CHECK (index_policy IN ('INDEX_ALLOWED_BY_DEFAULT', 'INDEX_OPT_IN', 'INDEX_OPT_OUT', 'INDEX_FORBIDDEN', 'PRIVATE_ONLY')),
    owner_identity_id UUID REFERENCES users(id) ON DELETE SET NULL,
    public_key TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at TIMESTAMPTZ
);

CREATE INDEX bubbles_owner_identity_id_idx ON bubbles(owner_identity_id) WHERE deleted_at IS NULL;

CREATE TABLE bubble_members (
    bubble_id UUID NOT NULL REFERENCES bubbles(id) ON DELETE CASCADE,
    identity_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role TEXT NOT NULL CHECK (role IN ('owner', 'admin', 'member')),
    status TEXT NOT NULL CHECK (status IN ('active', 'invited', 'removed')),
    joined_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (bubble_id, identity_id)
);

CREATE INDEX bubble_members_identity_id_idx ON bubble_members(identity_id) WHERE status = 'active';

CREATE TABLE bubble_relays (
    bubble_id UUID NOT NULL REFERENCES bubbles(id) ON DELETE CASCADE,
    relay_id UUID NOT NULL REFERENCES relays(id) ON DELETE CASCADE,
    role TEXT NOT NULL CHECK (role IN ('primary', 'fallback', 'community', 'organization')),
    priority INTEGER NOT NULL,
    required BOOLEAN NOT NULL DEFAULT false,
    fallback_allowed BOOLEAN NOT NULL DEFAULT true,
    PRIMARY KEY (bubble_id, relay_id)
);

CREATE TABLE bubble_services (
    id UUID PRIMARY KEY,
    bubble_id UUID NOT NULL REFERENCES bubbles(id) ON DELETE CASCADE,
    service_type TEXT NOT NULL,
    name TEXT NOT NULL,
    slug TEXT NOT NULL,
    visibility TEXT NOT NULL CHECK (visibility IN ('PUBLIC', 'UNLISTED', 'PRIVATE', 'SECRET')),
    index_policy TEXT NOT NULL CHECK (index_policy IN ('INDEX_ALLOWED_BY_DEFAULT', 'INDEX_OPT_IN', 'INDEX_OPT_OUT', 'INDEX_FORBIDDEN', 'PRIVATE_ONLY')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (bubble_id, slug)
);
