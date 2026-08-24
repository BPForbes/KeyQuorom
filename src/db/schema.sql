-- KeyQuorum local storage schema.
--
-- A protected file's encryption key is split into shares, each wrapped for
-- one registered hardware key. Unlocking a file requires presenting enough
-- hardware keys to reconstruct at least `quorum_threshold` shares.

CREATE TABLE IF NOT EXISTS hardware_keys (
    id            INTEGER PRIMARY KEY,
    label         TEXT NOT NULL,
    fingerprint   TEXT NOT NULL UNIQUE,
    public_key    BLOB NOT NULL,
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    revoked_at    TEXT
);

CREATE TABLE IF NOT EXISTS files (
    id                INTEGER PRIMARY KEY,
    name              TEXT NOT NULL,
    encrypted_path    TEXT NOT NULL UNIQUE,
    content_hash      TEXT NOT NULL,
    quorum_threshold  INTEGER NOT NULL CHECK (quorum_threshold > 0),
    created_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

-- Which hardware keys are registered for a file's quorum, and the key
-- share wrapped for each one.
CREATE TABLE IF NOT EXISTS file_key_shares (
    file_id          INTEGER NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    hardware_key_id  INTEGER NOT NULL REFERENCES hardware_keys(id) ON DELETE CASCADE,
    wrapped_share    BLOB NOT NULL,
    PRIMARY KEY (file_id, hardware_key_id)
);

-- Audit log of unlock attempts, successful or not.
CREATE TABLE IF NOT EXISTS unlock_events (
    id              INTEGER PRIMARY KEY,
    file_id         INTEGER NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    attempted_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    success         INTEGER NOT NULL CHECK (success IN (0, 1)),
    keys_presented  TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_file_key_shares_hardware_key
    ON file_key_shares (hardware_key_id);

CREATE INDEX IF NOT EXISTS idx_unlock_events_file
    ON unlock_events (file_id);
