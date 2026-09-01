-- Server-only mailbox + public-tree database. Never store wrapped shares
-- or private key material here. Envelopes are opaque blobs indexed by the
-- recipient encryption-key fingerprint from the outer .kqpb header. The
-- org_* tables hold the canonical *public* split-tree topology so each
-- personal store can fetch only the slice that person needs.

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

-- Canonical public split-tree topology (no wrapped shares, no private keys).
CREATE TABLE IF NOT EXISTS org_trees (
    id            INTEGER PRIMARY KEY,
    label         TEXT NOT NULL UNIQUE,
    generation    INTEGER NOT NULL CHECK (generation > 0),
    updated_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE IF NOT EXISTS org_nodes (
    id                        INTEGER PRIMARY KEY,
    tree_id                   INTEGER NOT NULL REFERENCES org_trees(id) ON DELETE CASCADE,
    label                     TEXT NOT NULL,
    parent_label              TEXT,
    threshold                 INTEGER CHECK (threshold IS NULL OR threshold > 0),
    is_active                 INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1)),
    encryption_fingerprint    TEXT,
    encryption_public_key     TEXT,
    UNIQUE (tree_id, label),
    CHECK (
        (threshold IS NOT NULL AND encryption_fingerprint IS NULL AND encryption_public_key IS NULL)
        OR (threshold IS NULL AND encryption_fingerprint IS NOT NULL AND encryption_public_key IS NOT NULL)
    )
);

CREATE INDEX IF NOT EXISTS idx_org_nodes_fingerprint
    ON org_nodes (tree_id, encryption_fingerprint);

CREATE TABLE IF NOT EXISTS org_whitelist (
    tree_id     INTEGER NOT NULL REFERENCES org_trees(id) ON DELETE CASCADE,
    from_label  TEXT NOT NULL,
    to_label    TEXT NOT NULL,
    PRIMARY KEY (tree_id, from_label, to_label)
);

CREATE TABLE IF NOT EXISTS org_links (
    tree_id     INTEGER NOT NULL REFERENCES org_trees(id) ON DELETE CASCADE,
    from_label  TEXT NOT NULL,
    to_label    TEXT NOT NULL,
    PRIMARY KEY (tree_id, from_label, to_label)
);
