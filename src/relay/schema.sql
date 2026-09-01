-- Server-only mailbox + public-tree database. Never store wrapped shares
-- or private key material here. Envelopes are opaque blobs indexed by the
-- recipient encryption-key fingerprint from the outer .kqpb header.
-- `org_tree_docs` is a document store: one JSON public tree per label
-- (the full org context). Pushing envelopes updates those documents.
-- Personal devices translate a sliced copy into local SQLite.

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
    UNIQUE (recipient_fingerprint, content_hash)
);

CREATE INDEX IF NOT EXISTS idx_mailbox_recipient
    ON mailbox (recipient_fingerprint, id);

-- Full public split-tree as a JSON document (no wrapped shares, no private keys).
CREATE TABLE IF NOT EXISTS org_tree_docs (
    label         TEXT PRIMARY KEY,
    generation    INTEGER NOT NULL CHECK (generation > 0),
    document      TEXT NOT NULL,
    updated_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
