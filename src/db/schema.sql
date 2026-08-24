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
    quorum_threshold  INTEGER NOT NULL CHECK (
        quorum_threshold > 0 AND typeof(quorum_threshold) = 'integer'
    ),
    created_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

-- Which hardware keys are registered for a file's quorum, and the key
-- share wrapped for each one. A hardware key that still backs a share is
-- protected from deletion (ON DELETE RESTRICT) rather than silently
-- cascading, since losing a share out from under a file can drop it below
-- its quorum_threshold and make it permanently unrecoverable.
CREATE TABLE IF NOT EXISTS file_key_shares (
    file_id          INTEGER NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    hardware_key_id  INTEGER NOT NULL REFERENCES hardware_keys(id) ON DELETE RESTRICT,
    wrapped_share    BLOB NOT NULL,
    PRIMARY KEY (file_id, hardware_key_id)
);

-- Guard against removing a share (directly, or as a side effect of trying
-- to delete/unbind a hardware key) when doing so would drop a file's
-- remaining shares below its quorum_threshold.
CREATE TRIGGER IF NOT EXISTS trg_file_key_shares_guard_quorum
BEFORE DELETE ON file_key_shares
FOR EACH ROW
WHEN (
    SELECT count(*) FROM file_key_shares WHERE file_id = OLD.file_id
) - 1 < (
    SELECT quorum_threshold FROM files WHERE id = OLD.file_id
)
BEGIN
    SELECT RAISE(ABORT, 'cannot remove key share: file would fall below its quorum threshold');
END;

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
