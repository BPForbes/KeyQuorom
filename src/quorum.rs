//! Hardware-key-quorum file protection: encrypts a file under a random
//! data key, then splits that key via `key_tree::split` so unlocking the
//! file means reconstructing that key's tree — a flat "M-of-N hardware
//! keys" quorum is just the simplest possible tree shape.

use crate::crypto::{self, NONCE_LEN};
use crate::error::{Error, Result};
use crate::key_tree::{self, NodeSpec, TreeSummary};
use crate::locked_files;
use rusqlite::{params, Connection};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use zeroize::Zeroizing;

pub struct FileStatus {
    pub id: i64,
    pub name: String,
    pub encrypted_path: String,
    pub created_at: String,
    pub tree: TreeSummary,
}

/// Encrypts `source_path` under a fresh random data key and splits that
/// key per `tree_spec`. The ciphertext is written first, outside any
/// database transaction (mirroring `locked_files::lock_file`'s reasoning:
/// `create_new` fails atomically if `encrypted_path` is already in use,
/// and this keeps the write lock held only for the DB work that follows).
/// The key-tree build and the `files` row insert happen in one
/// transaction, so a failure partway through never leaves a `files` row
/// pointing at an incomplete tree, or vice versa; on any failure the
/// just-written ciphertext file is removed too.
pub fn lock_file(
    conn: &mut Connection,
    source_path: &Path,
    encrypted_path: &Path,
    name: Option<&str>,
    tree_spec: &NodeSpec,
) -> Result<i64> {
    key_tree::validate(conn, tree_spec)?;
    let encrypted_path_str = encrypted_path.to_str().ok_or(Error::InvalidPath)?;

    let plaintext = fs::read(source_path)?;
    let data_key = crypto::random_key();
    let nonce = crypto::random_nonce();
    let ciphertext = crypto::encrypt(&data_key, &nonce, &plaintext);

    let name = name.map(str::to_owned).unwrap_or_else(|| {
        source_path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default()
    });

    locked_files::write_owner_only(encrypted_path, &ciphertext)?;

    let result = (|| -> Result<i64> {
        let tx = conn.transaction()?;
        let key_id = key_tree::build_tree(&tx, &name, &data_key[..], tree_spec)?;
        tx.execute(
            "INSERT INTO files (name, encrypted_path, key_id, nonce) VALUES (?1, ?2, ?3, ?4)",
            params![name, encrypted_path_str, key_id, nonce.to_vec()],
        )?;
        let file_id = tx.last_insert_rowid();
        tx.commit()?;
        Ok(file_id)
    })();

    // Everything that can fail — starting the transaction, building the
    // key tree, the insert, the commit — lives inside the closure above
    // and flows through this one `result`, so the just-written ciphertext
    // is always cleaned up on any failure, including one that happens
    // before a transaction ever opens (e.g. `conn` already has one active).
    if result.is_err() {
        let _ = fs::remove_file(encrypted_path);
    }
    result
}

pub fn status(conn: &Connection, file_id: i64) -> Result<FileStatus> {
    let (name, encrypted_path, key_id, created_at): (String, String, i64, String) = conn
        .query_row(
            "SELECT name, encrypted_path, key_id, created_at FROM files WHERE id = ?1",
            params![file_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )?;
    let tree = key_tree::describe(conn, key_id)?;

    Ok(FileStatus {
        id: file_id,
        name,
        encrypted_path,
        created_at,
        tree,
    })
}

/// `raw_shares` maps a leaf `key_nodes.id` to its already-unwrapped raw
/// share bytes — see `key_tree`'s module doc comment for why obtaining
/// them is the caller's responsibility this round.
pub fn unlock_file(
    conn: &Connection,
    file_id: i64,
    raw_shares: &HashMap<i64, Vec<u8>>,
) -> Result<Vec<u8>> {
    let (encrypted_path, key_id, nonce): (String, i64, Vec<u8>) = conn.query_row(
        "SELECT encrypted_path, key_id, nonce FROM files WHERE id = ?1",
        params![file_id],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;

    let result = reconstruct_and_decrypt(conn, key_id, &encrypted_path, &nonce, raw_shares);

    // Best-effort audit trail: unlock_events already existed in the schema
    // for exactly this, unused until now. A raw share's origin (which
    // hardware key it came from) isn't known yet without the deferred
    // unwrap step, so this logs only a count and the outcome.
    let _ = conn.execute(
        "INSERT INTO unlock_events (file_id, success, keys_presented) VALUES (?1, ?2, ?3)",
        params![
            file_id,
            result.is_ok() as i64,
            format!("{} raw share(s) presented", raw_shares.len())
        ],
    );

    result
}

fn reconstruct_and_decrypt(
    conn: &Connection,
    key_id: i64,
    encrypted_path: &str,
    nonce: &[u8],
    raw_shares: &HashMap<i64, Vec<u8>>,
) -> Result<Vec<u8>> {
    let data_key = Zeroizing::new(key_tree::reconstruct(conn, key_id, raw_shares)?);
    let data_key: Zeroizing<[u8; crypto::KEY_LEN]> = Zeroizing::new(
        data_key
            .as_slice()
            .try_into()
            .map_err(|_| Error::QuorumNotMet)?,
    );
    let nonce: [u8; NONCE_LEN] = nonce.try_into().map_err(|_| Error::IntegrityCheckFailed)?;

    let ciphertext = fs::read(encrypted_path)?;
    crypto::decrypt(&data_key, &nonce, &ciphertext).map_err(|_| Error::IntegrityCheckFailed)
}

#[cfg(test)]
#[path = "quorum/tests.rs"]
mod tests;
