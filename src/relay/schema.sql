-- Server-only mailbox + public-tree database. Never store wrapped shares
-- or private key material here. Envelopes are opaque blobs indexed by the
-- recipient encryption-key fingerprint from the outer .kqpb header.
-- `org_tree_docs` is a document store: one JSON public tree per label
-- (the full org context). Pushing envelopes updates those documents.
-- Personal devices translate a sliced copy into local SQLite.

-- Legacy single-row issuer table. New mailboxes leave this empty.
-- Customer keys are minted by `POST /api/v1/{provider_id}/register`.
CREATE TABLE IF NOT EXISTS licensee_issuer (
    id          INTEGER PRIMARY KEY CHECK (id = 1),
    key_hash    TEXT NOT NULL,
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE IF NOT EXISTS api_keys (
    id                      INTEGER PRIMARY KEY,
    key_hash                TEXT NOT NULL UNIQUE,
    scope                   TEXT NOT NULL CHECK (scope IN ('inbox.push', 'inbox.pull', 'admin')),
    recipient_fingerprint   TEXT,
    label                   TEXT,
    created_at              TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    expires_at              TEXT,
    revoked_at              TEXT,
    last_used_at            TEXT,
    CHECK (
        (scope = 'inbox.pull' AND recipient_fingerprint IS NOT NULL)
        OR (scope != 'inbox.pull' AND recipient_fingerprint IS NULL)
    )
);

CREATE TABLE IF NOT EXISTS mailbox (
    id                      INTEGER PRIMARY KEY,
    recipient_fingerprint   TEXT NOT NULL,
    envelope                BLOB NOT NULL,
    content_hash            TEXT NOT NULL,
    created_at              TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    -- UTC cutoff `YYYY-MM-DD HH:MM:00`. NULL means the envelope does not expire.
    -- The host scan (and inbox pull) delete expired rows so they cannot be fetched.
    expires_at              TEXT,
    UNIQUE (recipient_fingerprint, content_hash)
);

CREATE INDEX IF NOT EXISTS idx_mailbox_recipient
    ON mailbox (recipient_fingerprint, id);

-- Who registered which API key: provider group, hardware token, and when.
-- `hardware_public_key` is hex of the 32-byte Ed25519 verifying key.
-- `hardware_fingerprint` is hex(SHA-256(public_key)). Never store a bearer.
-- `keyquorum_signature` is hex of the relay identity signature over the receipt.
CREATE TABLE IF NOT EXISTS api_key_registrations (
    id                      INTEGER PRIMARY KEY,
    provider_id             TEXT NOT NULL,
    hardware_fingerprint    TEXT NOT NULL,
    hardware_public_key     TEXT NOT NULL,
    api_key_id              INTEGER NOT NULL UNIQUE,
    registered_at           TEXT NOT NULL,
    keyquorum_signature     TEXT NOT NULL,
    FOREIGN KEY (api_key_id) REFERENCES api_keys(id)
);

CREATE INDEX IF NOT EXISTS idx_registrations_provider
    ON api_key_registrations (provider_id, hardware_fingerprint, registered_at);

-- Full public split-tree as a JSON document (no wrapped shares, no private keys).
CREATE TABLE IF NOT EXISTS org_tree_docs (
    label         TEXT PRIMARY KEY,
    generation    INTEGER NOT NULL CHECK (generation > 0),
    document      TEXT NOT NULL,
    updated_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

-- Privileged provider-auth attempts. Never store bearers, private keys,
-- challenge nonces, or other reusable secrets.
CREATE TABLE IF NOT EXISTS provider_auth_events (
    id                      INTEGER PRIMARY KEY,
    operation               TEXT NOT NULL,
    provider_id             TEXT,
    network_id              TEXT,
    hardware_fingerprints   TEXT,
    success                 INTEGER NOT NULL CHECK (success IN (0, 1)),
    attempted_at            TEXT NOT NULL DEFAULT (
        strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
    )
);
