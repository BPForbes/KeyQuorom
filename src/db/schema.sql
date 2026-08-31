-- KeyQuorum local storage schema.
--
-- A splittable secret ("key") is organized as a tree of `key_nodes`: a
-- SPLIT node divides its value via Shamir's Secret Sharing among its
-- children with its own threshold, recursively, down to LEAF nodes, each
-- of which is a share sealed to one registered hardware key. A protected
-- file references a key's root and is unlocked by reconstructing that
-- key's tree.

CREATE TABLE IF NOT EXISTS hardware_keys (
    id            INTEGER PRIMARY KEY,
    label         TEXT NOT NULL,
    key_type      TEXT NOT NULL CHECK (key_type IN ('encryption', 'signing')),
    fingerprint   TEXT NOT NULL UNIQUE,
    public_key    BLOB NOT NULL,
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    revoked_at    TEXT
);

-- A splittable secret in its own right, independent of any file — "key
-- split" is a capability on its own, not just a mechanism for protecting
-- files (see key_nodes below).
CREATE TABLE IF NOT EXISTS keys (
    id            INTEGER PRIMARY KEY,
    label         TEXT NOT NULL,
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

-- One row per node in a key's split tree. A node is either a SPLIT node
-- (threshold set, hardware_key_id/wrapped_share NULL — reconstructing it
-- means Shamir-recovering at least `threshold` of its children's values)
-- or a LEAF (hardware_key_id/wrapped_share set, threshold NULL — a share
-- sealed to one specific hardware key). parent_id NULL marks a key's root
-- node. A flat "M-of-N hardware keys" quorum is just a one-level tree: a
-- single SPLIT root with N LEAF children.
CREATE TABLE IF NOT EXISTS key_nodes (
    id                INTEGER PRIMARY KEY,
    key_id            INTEGER NOT NULL REFERENCES keys(id) ON DELETE CASCADE,
    parent_id         INTEGER REFERENCES key_nodes(id) ON DELETE CASCADE,
    label             TEXT NOT NULL,
    threshold         INTEGER CHECK (threshold IS NULL OR threshold > 0),
    hardware_key_id   INTEGER REFERENCES hardware_keys(id) ON DELETE RESTRICT,
    wrapped_share     BLOB,
    -- 0 after a PSS eviction; reconstruct ignores inactive children.
    is_active         INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1)),
    CHECK (
        (threshold IS NOT NULL AND hardware_key_id IS NULL AND wrapped_share IS NULL)
        OR (threshold IS NULL AND hardware_key_id IS NOT NULL AND wrapped_share IS NOT NULL)
    )
);

-- A signing-purpose hardware key must never become a quorum leaf: nobody
-- could ever unwrap it, since it isn't an encryption key. key_type isn't
-- checked anywhere else at the SQL layer, so this is load-bearing.
CREATE TRIGGER IF NOT EXISTS trg_key_nodes_guard_key_type
BEFORE INSERT ON key_nodes
FOR EACH ROW
WHEN NEW.hardware_key_id IS NOT NULL
AND (SELECT key_type FROM hardware_keys WHERE id = NEW.hardware_key_id) != 'encryption'
BEGIN
    SELECT RAISE(ABORT, 'cannot make a signing-only hardware key a quorum leaf');
END;

-- Same guard when `bind --public-key-file` reassigns a leaf's
-- hardware_key_id (node id stays put so pairings survive the rebind).
CREATE TRIGGER IF NOT EXISTS trg_key_nodes_guard_key_type_on_update
BEFORE UPDATE OF hardware_key_id ON key_nodes
FOR EACH ROW
WHEN NEW.hardware_key_id IS NOT NULL
AND (SELECT key_type FROM hardware_keys WHERE id = NEW.hardware_key_id) != 'encryption'
BEGIN
    SELECT RAISE(ABORT, 'cannot make a signing-only hardware key a quorum leaf');
END;

CREATE INDEX IF NOT EXISTS idx_key_nodes_parent ON key_nodes (parent_id);
CREATE INDEX IF NOT EXISTS idx_key_nodes_key ON key_nodes (key_id);
CREATE INDEX IF NOT EXISTS idx_key_nodes_hardware_key ON key_nodes (hardware_key_id);

-- Supervisor whitelist: node `node_id` may form a cross-branch pairing
-- with the node whose label is `peer_label` in the same key tree.
CREATE TABLE IF NOT EXISTS key_node_bridges (
    node_id     INTEGER NOT NULL REFERENCES key_nodes(id) ON DELETE CASCADE,
    peer_label  TEXT NOT NULL,
    PRIMARY KEY (node_id, peer_label)
);

CREATE INDEX IF NOT EXISTS idx_key_node_bridges_peer
    ON key_node_bridges (peer_label);

-- Established undirected pairing (no channel key material).
-- node_a_id < node_b_id so each pair has one row.
CREATE TABLE IF NOT EXISTS key_node_links (
    node_a_id       INTEGER NOT NULL REFERENCES key_nodes(id) ON DELETE CASCADE,
    node_b_id       INTEGER NOT NULL REFERENCES key_nodes(id) ON DELETE CASCADE,
    established_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    PRIMARY KEY (node_a_id, node_b_id),
    CHECK (node_a_id < node_b_id)
);

-- A hardware-key-quorum-protected file. No content hash is stored: an
-- unkeyed hash of the plaintext would leak a fingerprint of it
-- independent of whatever protects the file — AES-256-GCM's own
-- authentication tag is what verifies integrity on unlock.
CREATE TABLE IF NOT EXISTS files (
    id                INTEGER PRIMARY KEY,
    name              TEXT NOT NULL,
    encrypted_path    TEXT NOT NULL UNIQUE,
    key_id            INTEGER NOT NULL REFERENCES keys(id) ON DELETE RESTRICT,
    nonce             BLOB NOT NULL,
    created_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

-- Audit log of unlock attempts, successful or not.
CREATE TABLE IF NOT EXISTS unlock_events (
    id              INTEGER PRIMARY KEY,
    file_id         INTEGER NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    attempted_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    success         INTEGER NOT NULL CHECK (success IN (0, 1)),
    keys_presented  TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_unlock_events_file
    ON unlock_events (file_id);

-- Password manager: each entry is encrypted independently with a key
-- derived (Argon2id) from the vault master password and this row's own
-- salt, so nonces and salts never need to be coordinated across rows.
CREATE TABLE IF NOT EXISTS credentials (
    id            INTEGER PRIMARY KEY,
    label         TEXT NOT NULL,
    username      TEXT,
    kdf_salt      BLOB NOT NULL,
    nonce         BLOB NOT NULL,
    ciphertext    BLOB NOT NULL,
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

-- A file locked with a single password rather than a hardware-key quorum:
-- a lighter-weight protection tier, independent of the `files` / `keys`
-- quorum mechanism above. No separate content hash is stored: AES-256-GCM's
-- own authentication tag already proves the decrypted plaintext is intact,
-- and an unkeyed hash of the plaintext would otherwise leak a
-- password-independent fingerprint of it.
CREATE TABLE IF NOT EXISTS password_locked_files (
    id                INTEGER PRIMARY KEY,
    name              TEXT NOT NULL,
    encrypted_path    TEXT NOT NULL UNIQUE,
    kdf_salt          BLOB NOT NULL,
    nonce             BLOB NOT NULL,
    created_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

-- Time-limited, revocable share links. Only a hash of each share's bearer
-- token is stored, matching how the token is looked up on redemption; the
-- raw token itself is never persisted, only handed to the caller once.
CREATE TABLE IF NOT EXISTS credential_shares (
    id              INTEGER PRIMARY KEY,
    credential_id   INTEGER NOT NULL REFERENCES credentials(id) ON DELETE CASCADE,
    token_hash      TEXT NOT NULL UNIQUE,
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    expires_at      TEXT NOT NULL,
    max_uses        INTEGER CHECK (max_uses IS NULL OR max_uses > 0),
    use_count       INTEGER NOT NULL DEFAULT 0 CHECK (use_count >= 0),
    revoked_at      TEXT
);

CREATE TABLE IF NOT EXISTS file_shares (
    id              INTEGER PRIMARY KEY,
    file_id         INTEGER NOT NULL REFERENCES password_locked_files(id) ON DELETE CASCADE,
    token_hash      TEXT NOT NULL UNIQUE,
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    expires_at      TEXT NOT NULL,
    max_uses        INTEGER CHECK (max_uses IS NULL OR max_uses > 0),
    use_count       INTEGER NOT NULL DEFAULT 0 CHECK (use_count >= 0),
    revoked_at      TEXT
);

CREATE INDEX IF NOT EXISTS idx_credential_shares_credential
    ON credential_shares (credential_id);

CREATE INDEX IF NOT EXISTS idx_file_shares_file
    ON file_shares (file_id);

-- Optional 4-digit-PIN gate on a resource, layered on top of (never
-- instead of) that resource's real protection (master password, quorum,
-- or a recipient's real public key for shared content) — see pin.rs for
-- the honest caveat on what the attempt-lockout below can and can't
-- guarantee against an attacker with an offline copy of this database.
-- One generic table rather than duplicating these columns across five
-- different resource tables, since SQLite has no clean polymorphic FK;
-- mirrors how credential_shares/file_shares already are structurally
-- the same shape.
CREATE TABLE IF NOT EXISTS pins (
    id                  INTEGER PRIMARY KEY,
    resource_type       TEXT NOT NULL CHECK (resource_type IN (
        'credential', 'locked_file', 'quorum_file',
        'credential_share', 'file_share'
    )),
    resource_id         INTEGER NOT NULL,
    pin_hash            BLOB NOT NULL,
    pin_salt            BLOB NOT NULL,
    require_every_use   INTEGER NOT NULL DEFAULT 0 CHECK (require_every_use IN (0, 1)),
    ttl_seconds         INTEGER NOT NULL CHECK (ttl_seconds > 0),
    attempt_count       INTEGER NOT NULL DEFAULT 0,
    locked_at           TEXT,
    unlocked_until       TEXT,
    created_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    UNIQUE (resource_type, resource_id)
);

-- Private N-member sign bridges. Each person owns their node keys in their
-- own storage: this database holds public roster metadata plus at most the
-- sealed bridge secret for *local* members. Other members receive a
-- per-recipient package (KQPB) sealed to their encryption public key.
-- `uid` is stable across machines and key rotations; `salt` is redrawn
-- with the Ed25519 keypair on every membership-loss rotation.
CREATE TABLE IF NOT EXISTS private_bridges (
    id            INTEGER PRIMARY KEY,
    uid           TEXT NOT NULL UNIQUE,
    key_id        INTEGER REFERENCES keys(id) ON DELETE SET NULL,
    label         TEXT,
    generation    INTEGER NOT NULL CHECK (generation > 0),
    public_key    BLOB NOT NULL,
    salt          BLOB NOT NULL,
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    destroyed_at  TEXT
);

-- Signing members (`member`) and department/CXO supervisors who must be
-- notified but do not hold the shared signing secret (`supervisor`).
-- Direct parents of members are always on this roster (e.g. M.S.2 implies M.S).
CREATE TABLE IF NOT EXISTS private_bridge_members (
    bridge_id               INTEGER NOT NULL REFERENCES private_bridges(id) ON DELETE CASCADE,
    node_label              TEXT NOT NULL,
    encryption_public_key   BLOB NOT NULL,
    signing_public_key      BLOB,
    role                    TEXT NOT NULL CHECK (role IN ('member', 'supervisor')),
    is_local                INTEGER NOT NULL DEFAULT 0 CHECK (is_local IN (0, 1)),
    PRIMARY KEY (bridge_id, node_label),
    CHECK (
        (role = 'member' AND length(signing_public_key) = 32)
        OR (role = 'supervisor' AND signing_public_key IS NULL)
    )
);

-- Sealed `wrap_salt || bridge_ed25519_sk` for a local member only.
-- wrap_salt binds the ciphertext to this member row so a copied blob fails.
CREATE TABLE IF NOT EXISTS private_bridge_sealed_keys (
    bridge_id       INTEGER NOT NULL,
    node_label      TEXT NOT NULL,
    wrap_salt       BLOB NOT NULL,
    wrapped_secret  BLOB NOT NULL,
    PRIMARY KEY (bridge_id, node_label),
    FOREIGN KEY (bridge_id, node_label)
        REFERENCES private_bridge_members(bridge_id, node_label)
        ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS bridge_events (
    id            INTEGER PRIMARY KEY,
    bridge_id     INTEGER NOT NULL REFERENCES private_bridges(id) ON DELETE CASCADE,
    event_type    TEXT NOT NULL CHECK (event_type IN (
        'created', 'imported', 'member_removed', 'rotated', 'destroyed'
    )),
    detail        TEXT NOT NULL,
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_private_bridges_key ON private_bridges (key_id);
CREATE INDEX IF NOT EXISTS idx_bridge_events_bridge ON bridge_events (bridge_id);
