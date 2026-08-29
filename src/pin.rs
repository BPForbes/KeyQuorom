//! Optional 4-digit-PIN gate on a resource, layered on top of — never
//! instead of — that resource's real protection (a master password, a
//! quorum, or a recipient's real public key for shared content).
//!
//! Honest caveat: this attempt-lockout lives in the same local SQLite
//! file an attacker may already have a full copy of, so it's a real
//! deterrent against someone guessing through the live CLI, but not a
//! hard guarantee against an attacker with an offline copy of the
//! database (they can reset the counter, or operate on a copy) — no
//! different in kind from how this project's password vault already
//! relies on Argon2id's cost-per-guess rather than the database's
//! secrecy.

use crate::crypto;
use crate::error::{Error, Result};
use rusqlite::{params, Connection, OptionalExtension};

const MAX_ATTEMPTS: i64 = 8;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ResourceType {
    Credential,
    LockedFile,
    QuorumFile,
    CredentialShare,
    FileShare,
}

impl ResourceType {
    fn as_str(self) -> &'static str {
        match self {
            ResourceType::Credential => "credential",
            ResourceType::LockedFile => "locked_file",
            ResourceType::QuorumFile => "quorum_file",
            ResourceType::CredentialShare => "credential_share",
            ResourceType::FileShare => "file_share",
        }
    }
}

fn is_four_digit_pin(pin: &str) -> bool {
    pin.len() == 4 && pin.bytes().all(|b| b.is_ascii_digit())
}

/// Sets (or replaces) a resource's PIN. Re-setting resets the attempt
/// counter, any lockout, and any outstanding unlocked-until window, since
/// it's effectively a fresh PIN.
pub fn set_pin(
    conn: &Connection,
    resource_type: ResourceType,
    resource_id: i64,
    pin: &str,
    require_every_use: bool,
    ttl_seconds: i64,
) -> Result<()> {
    if !is_four_digit_pin(pin) {
        return Err(Error::InvalidPin);
    }

    let salt = crypto::random_salt();
    let hash = crypto::derive_key(pin, &salt)?;

    conn.execute(
        "INSERT INTO pins (resource_type, resource_id, pin_hash, pin_salt, require_every_use, ttl_seconds)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT (resource_type, resource_id) DO UPDATE SET
             pin_hash = excluded.pin_hash,
             pin_salt = excluded.pin_salt,
             require_every_use = excluded.require_every_use,
             ttl_seconds = excluded.ttl_seconds,
             attempt_count = 0,
             locked_at = NULL,
             unlocked_until = NULL",
        params![
            resource_type.as_str(),
            resource_id,
            hash.to_vec(),
            salt.to_vec(),
            require_every_use as i64,
            ttl_seconds,
        ],
    )?;
    Ok(())
}

struct PinRow {
    id: i64,
    pin_hash: Vec<u8>,
    pin_salt: Vec<u8>,
    require_every_use: bool,
    ttl_seconds: i64,
    locked_at: Option<String>,
    unlocked_until: Option<String>,
}

fn get_pin_row(conn: &Connection, resource_type: ResourceType, resource_id: i64) -> Result<PinRow> {
    let row = conn
        .query_row(
            "SELECT id, pin_hash, pin_salt, require_every_use, ttl_seconds, locked_at, unlocked_until
             FROM pins WHERE resource_type = ?1 AND resource_id = ?2",
            params![resource_type.as_str(), resource_id],
            |row| {
                Ok(PinRow {
                    id: row.get(0)?,
                    pin_hash: row.get(1)?,
                    pin_salt: row.get(2)?,
                    require_every_use: row.get(3)?,
                    ttl_seconds: row.get(4)?,
                    locked_at: row.get(5)?,
                    unlocked_until: row.get(6)?,
                })
            },
        )
        .optional()?;
    row.ok_or(Error::PinNotSet)
}

/// Lets a caller decide up front whether to prompt for a PIN at all —
/// e.g. `access password --state 1` only asks for one when the resource
/// actually has one configured.
pub fn has_pin(conn: &Connection, resource_type: ResourceType, resource_id: i64) -> Result<bool> {
    match get_pin_row(conn, resource_type, resource_id) {
        Ok(_) => Ok(true),
        Err(Error::PinNotSet) => Ok(false),
        Err(e) => Err(e),
    }
}

/// Reports whether the caller must prompt for and verify a PIN now.
/// Resources without a PIN, and resources still inside a successful
/// one-time verification window, do not require another prompt.
pub fn verification_required(
    conn: &Connection,
    resource_type: ResourceType,
    resource_id: i64,
) -> Result<bool> {
    let row = match get_pin_row(conn, resource_type, resource_id) {
        Ok(row) => row,
        Err(Error::PinNotSet) => return Ok(false),
        Err(e) => return Err(e),
    };

    if row.require_every_use || row.locked_at.is_some() {
        return Ok(true);
    }

    let Some(unlocked_until) = row.unlocked_until else {
        return Ok(true);
    };
    conn.query_row(
        "SELECT datetime(?1) <= datetime('now')",
        params![unlocked_until],
        |row| row.get(0),
    )
    .map_err(Into::into)
}

pub fn verify_pin(
    conn: &Connection,
    resource_type: ResourceType,
    resource_id: i64,
    pin: &str,
) -> Result<()> {
    let row = get_pin_row(conn, resource_type, resource_id)?;

    if row.locked_at.is_some() {
        return Err(Error::PinLocked);
    }

    if !row.require_every_use {
        if let Some(unlocked_until) = &row.unlocked_until {
            let still_valid: bool = conn.query_row(
                "SELECT datetime(?1) > datetime('now')",
                params![unlocked_until],
                |row| row.get(0),
            )?;
            if still_valid {
                return Ok(());
            }
        }
    }

    let candidate_hash = crypto::derive_key(pin, &row.pin_salt)?;
    if candidate_hash.as_slice() != row.pin_hash.as_slice() {
        conn.execute(
            "UPDATE pins SET attempt_count = attempt_count + 1 WHERE id = ?1",
            params![row.id],
        )?;
        let attempt_count: i64 = conn.query_row(
            "SELECT attempt_count FROM pins WHERE id = ?1",
            params![row.id],
            |row| row.get(0),
        )?;
        if attempt_count >= MAX_ATTEMPTS {
            conn.execute(
                "UPDATE pins SET locked_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?1",
                params![row.id],
            )?;
        }
        return Err(Error::PinMismatch);
    }

    if row.require_every_use {
        conn.execute(
            "UPDATE pins SET attempt_count = 0 WHERE id = ?1",
            params![row.id],
        )?;
    } else {
        conn.execute(
            "UPDATE pins SET attempt_count = 0, unlocked_until = datetime('now', ?2) WHERE id = ?1",
            params![row.id, format!("+{} seconds", row.ttl_seconds)],
        )?;
    }

    Ok(())
}

/// Re-locks a resource early: clears any outstanding unlocked-until
/// window, so the next access needs the PIN again regardless of how much
/// of the TTL was left. A no-op if the resource has no PIN set at all.
pub fn relock(conn: &Connection, resource_type: ResourceType, resource_id: i64) -> Result<()> {
    conn.execute(
        "UPDATE pins SET unlocked_until = NULL WHERE resource_type = ?1 AND resource_id = ?2",
        params![resource_type.as_str(), resource_id],
    )?;
    Ok(())
}

#[cfg(test)]
#[path = "pin/tests.rs"]
mod tests;
