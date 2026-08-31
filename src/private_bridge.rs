//! N-member private sign bridges across independent per-person stores.
//!
//! Tree labels map to people and their storage:
//! - one segment (`M`) is a cross-department manager (CXO)
//! - two segments (`M.S`, `M.A`) are department managers
//! - three segments (`M.S.2`) are employees
//!
//! A bridge of `M.S.2`, `M.S.3`, `M.A.2` notifies five stores: the three
//! members plus each distinct direct parent (`M.S`, `M.A`). Grandparent
//! `M` is not included unless a member is itself a department manager.
//!
//! Members receive a sealed copy of the shared Ed25519 secret. Supervisors
//! receive roster metadata only (bridge pub, salt, membership) so they can
//! track the live standard without signing as the bridge. The shared secret
//! is never stored in more than one person's database in usable form: this
//! store keeps at most the local member's sealed copy; everyone else is
//! handed a per-recipient `KQPB` file.
//!
//! That file is a digital envelope: the header names the recipient's
//! X25519 public key; `crypto_box` seals the letter. A carrier can route
//! the envelope without opening it. Network delivery is enhancement #10.

use crate::crypto::{random_salt, SALT_LEN};
use crate::error::{Error, Result};
use crate::keys;
use crate::signing::{self, BridgeSignature};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rusqlite::{params, Connection, OptionalExtension};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use zeroize::Zeroizing;

const PACKAGE_MAGIC: &[u8; 4] = b"KQPB";
const NOTICE_MAGIC: &[u8; 4] = b"KQBN";
const FORMAT_VERSION: u8 = 2;
const KIND_INVITE: u8 = 1;
const KIND_ROTATE: u8 = 2;
const KIND_DESTROY: u8 = 3;
const KIND_SUPERVISOR: u8 = 4;
const ROLE_MEMBER: u8 = 1;
const ROLE_SUPERVISOR: u8 = 2;
const UPDATE_DOMAIN: &[u8] = b"KQBRIDGE-UPDATE-v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PartyRole {
    Member,
    Supervisor,
}

impl PartyRole {
    fn as_str(self) -> &'static str {
        match self {
            Self::Member => "member",
            Self::Supervisor => "supervisor",
        }
    }

    fn from_db(s: &str) -> Result<Self> {
        match s {
            "member" => Ok(Self::Member),
            "supervisor" => Ok(Self::Supervisor),
            _ => Err(Error::InvalidBridgePackage),
        }
    }

    fn to_u8(self) -> u8 {
        match self {
            Self::Member => ROLE_MEMBER,
            Self::Supervisor => ROLE_SUPERVISOR,
        }
    }

    fn from_u8(v: u8) -> Result<Self> {
        match v {
            ROLE_MEMBER => Ok(Self::Member),
            ROLE_SUPERVISOR => Ok(Self::Supervisor),
            _ => Err(Error::InvalidBridgePackage),
        }
    }
}

/// Direct parent in the dotted tree: `M.S.2` → `M.S`, `M.S` → `M`.
pub fn parent_node_label(label: &str) -> Option<&str> {
    label.rsplit_once('.').map(|(parent, _)| parent)
}

/// Members plus each distinct direct parent. For `M.S.2`, `M.S.3`, `M.A.2`
/// this is five labels: those three and `M.S`, `M.A` — not `M`.
pub fn notify_labels<'a, I>(member_labels: I) -> Vec<String>
where
    I: IntoIterator<Item = &'a str>,
{
    let mut out = BTreeSet::new();
    for label in member_labels {
        out.insert(label.to_string());
        if let Some(parent) = parent_node_label(label) {
            out.insert(parent.to_string());
        }
    }
    out.into_iter().collect()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct MemberKeys {
    encryption: [u8; 32],
    signing: [u8; 32],
}

#[derive(Clone, Debug)]
pub struct BridgePartyInput {
    pub label: String,
    pub encryption_public_key: [u8; 32],
    pub signing_public_key: Option<[u8; 32]>,
}

#[derive(Clone, Debug)]
pub struct DeliveryPackage {
    pub label: String,
    pub role: PartyRole,
    pub recipient_public_key: [u8; 32],
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct CreatedBridge {
    pub uid: String,
    pub generation: u32,
    pub public_key: [u8; 32],
    pub salt: [u8; SALT_LEN],
    pub packages: Vec<DeliveryPackage>,
}

/// Bridge material produced by [`plan_create`]. Packages are generated first
/// so callers can persist them before this store commits.
pub struct PlannedCreation {
    pub created: CreatedBridge,
    key_id: Option<i64>,
    label: Option<String>,
    members: BTreeMap<String, MemberKeys>,
    supervisors: BTreeMap<String, [u8; 32]>,
    local_label: Option<String>,
    secret: Zeroizing<[u8; 32]>,
}

#[derive(Clone, Debug)]
pub struct BridgeParty {
    pub label: String,
    pub encryption_public_key: [u8; 32],
    pub signing_public_key: Option<[u8; 32]>,
    pub role: PartyRole,
    pub is_local: bool,
    pub has_sealed_key: bool,
}

#[derive(Clone, Debug)]
pub struct BridgeSummary {
    pub uid: String,
    pub key_id: Option<i64>,
    pub label: Option<String>,
    pub generation: u32,
    pub public_key: [u8; 32],
    pub salt: [u8; SALT_LEN],
    pub destroyed: bool,
    pub parties: Vec<BridgeParty>,
}

#[derive(Clone, Debug)]
pub struct BridgeEvent {
    pub id: i64,
    pub uid: String,
    pub event_type: String,
    pub detail: String,
    pub created_at: String,
}

#[derive(Clone, Debug)]
pub struct RemoveMemberOutcome {
    pub uid: String,
    pub destroyed: bool,
    pub remaining_members: Vec<String>,
    pub packages: Vec<DeliveryPackage>,
}

/// Membership/key mutation produced by [`plan_remove_member`]. Packages are
/// generated first so callers can persist them before this store commits.
pub struct PlannedRemoval {
    pub outcome: RemoveMemberOutcome,
    kind: PlannedRemovalKind,
}

enum PlannedRemovalKind {
    Destroy {
        uid: String,
        bridge_id: i64,
        removed_label: String,
        notify: Vec<String>,
    },
    Rotate {
        uid: String,
        bridge_id: i64,
        removed_label: String,
        notify: Vec<String>,
        local_label: String,
        expected_generation: u32,
        new_generation: u32,
        new_public: [u8; 32],
        new_salt: [u8; SALT_LEN],
        members: BTreeMap<String, MemberKeys>,
        supervisors: BTreeMap<String, [u8; 32]>,
        new_secret: Zeroizing<[u8; 32]>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BridgeChangeKind {
    NeedsMemberRotate,
    Destroyed,
}

#[derive(Clone, Debug)]
pub struct BridgeChange {
    pub uid: String,
    pub removed_member: String,
    pub remaining_members: Vec<String>,
    pub notify: Vec<String>,
    pub kind: BridgeChangeKind,
    pub notice: Vec<u8>,
}

pub fn create(
    conn: &Connection,
    key_id: Option<i64>,
    label: Option<&str>,
    members: &[BridgePartyInput],
    supervisors: &[BridgePartyInput],
    local_label: Option<&str>,
) -> Result<CreatedBridge> {
    let planned = plan_create(key_id, label, members, supervisors, local_label)?;
    commit_planned_creation(conn, &planned)?;
    Ok(planned.created)
}

/// Build invite packages without writing this store. The CLI writes those
/// files, then [`commit_planned_creation`].
pub fn plan_create(
    key_id: Option<i64>,
    label: Option<&str>,
    members: &[BridgePartyInput],
    supervisors: &[BridgePartyInput],
    local_label: Option<&str>,
) -> Result<PlannedCreation> {
    let members = unique_members(members)?;
    if members.len() < 2 {
        return Err(Error::TooFewBridgeMembers);
    }
    let mut supervisors = unique_supervisors(supervisors)?;
    fill_implied_supervisors(&members, &mut supervisors)?;

    if let Some(local) = local_label {
        if !members.contains_key(local) && !supervisors.contains_key(local) {
            return Err(Error::NotBridgeMember);
        }
    }

    let uid = hex::encode(random_salt());
    let salt = random_salt();
    let (secret, public_key) = keys::generate_signing_keypair();
    let generation = 1u32;
    let secret_bytes: &[u8; 32] = &secret;
    let packages = packages_for_roster(
        KIND_INVITE,
        KIND_SUPERVISOR,
        &uid,
        generation,
        label.unwrap_or(""),
        &public_key,
        &salt,
        &members,
        &supervisors,
        "",
        Some(secret_bytes),
        None,
    )?;

    Ok(PlannedCreation {
        created: CreatedBridge {
            uid,
            generation,
            public_key,
            salt,
            packages,
        },
        key_id,
        label: label.map(str::to_string),
        members,
        supervisors,
        local_label: local_label.map(str::to_string),
        secret,
    })
}

/// Persist a previously planned creation. Callers that write delivery
/// packages should persist those files first so a later disk failure does
/// not leave a live bridge without envelopes.
pub fn commit_planned_creation(conn: &Connection, planned: &PlannedCreation) -> Result<()> {
    with_immediate_transaction(conn, |conn| {
        persist_new_bridge(
            conn,
            &planned.created.uid,
            planned.key_id,
            planned.label.as_deref(),
            planned.created.generation,
            &planned.created.public_key,
            &planned.created.salt,
            &planned.members,
            &planned.supervisors,
            planned.local_label.as_deref(),
            &planned.secret,
        )?;
        insert_event(
            conn,
            last_bridge_id(conn, &planned.created.uid)?,
            "created",
            json!({
                "uid": planned.created.uid,
                "generation": planned.created.generation,
                "members": sorted_keys(&planned.members),
                "supervisors": sorted_keys(&planned.supervisors),
                "notify": notify_labels(planned.members.keys().map(|s| s.as_str())),
                "salt": hex::encode(planned.created.salt),
            }),
        )?;
        Ok(())
    })
}

pub fn import_package(
    conn: &Connection,
    bytes: &[u8],
    recipient_secret: &[u8; 32],
) -> Result<BridgeSummary> {
    let expected_pub = keys::encryption_public_from_secret(recipient_secret);
    let decoded = decode_package(bytes, recipient_secret)?;
    if decoded.recipient_public_key != expected_pub {
        return Err(Error::InvalidBridgePackage);
    }

    match decoded.kind {
        KIND_INVITE => insert_from_invite(conn, &decoded)?,
        KIND_SUPERVISOR if decoded.generation == 1 && decoded.auth_sig.is_none() => {
            insert_from_invite(conn, &decoded)?
        }
        KIND_ROTATE | KIND_SUPERVISOR => apply_rotate(conn, &decoded)?,
        KIND_DESTROY => apply_destroy(conn, &decoded)?,
        _ => return Err(Error::InvalidBridgePackage),
    }
    get(conn, &decoded.uid)
}

pub fn list(conn: &Connection, key_id: Option<i64>) -> Result<Vec<BridgeSummary>> {
    let mut stmt = if key_id.is_some() {
        conn.prepare("SELECT uid FROM private_bridges WHERE key_id = ?1 ORDER BY id")?
    } else {
        conn.prepare("SELECT uid FROM private_bridges ORDER BY id")?
    };
    let uids: Vec<String> = if let Some(key_id) = key_id {
        stmt.query_map(params![key_id], |row| row.get(0))?
            .collect::<rusqlite::Result<_>>()?
    } else {
        stmt.query_map([], |row| row.get(0))?
            .collect::<rusqlite::Result<_>>()?
    };
    uids.iter().map(|uid| get(conn, uid)).collect()
}

pub fn get(conn: &Connection, uid: &str) -> Result<BridgeSummary> {
    let (id, key_id, label, generation, public_key, salt, destroyed_at) = conn
        .query_row(
            "SELECT id, key_id, label, generation, public_key, salt, destroyed_at
             FROM private_bridges WHERE uid = ?1",
            params![uid],
            |row| {
                let id: i64 = row.get(0)?;
                let key_id: Option<i64> = row.get(1)?;
                let label: Option<String> = row.get(2)?;
                let generation: i64 = row.get(3)?;
                let public_key: Vec<u8> = row.get(4)?;
                let salt: Vec<u8> = row.get(5)?;
                let destroyed_at: Option<String> = row.get(6)?;
                Ok((
                    id,
                    key_id,
                    label,
                    generation,
                    public_key,
                    salt,
                    destroyed_at,
                ))
            },
        )
        .optional()?
        .ok_or(Error::BridgeNotFound)?;

    let mut stmt = conn.prepare(
        "SELECT m.node_label, m.encryption_public_key, m.signing_public_key, m.role, m.is_local,
                (SELECT COUNT(*) FROM private_bridge_sealed_keys s
                 WHERE s.bridge_id = m.bridge_id AND s.node_label = m.node_label)
         FROM private_bridge_members m
         WHERE m.bridge_id = ?1
         ORDER BY m.role, m.node_label",
    )?;
    let parties = stmt
        .query_map(params![id], |row| {
            let role: String = row.get(3)?;
            let is_local: i64 = row.get(4)?;
            let sealed: i64 = row.get(5)?;
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Option<Vec<u8>>>(2)?,
                role,
                is_local != 0,
                sealed != 0,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;

    let parties = parties
        .into_iter()
        .map(|(label, pk, signing_pk, role, is_local, has_sealed_key)| {
            Ok(BridgeParty {
                label,
                encryption_public_key: vec_to_32(&pk)?,
                signing_public_key: signing_pk.as_deref().map(vec_to_32).transpose()?,
                role: PartyRole::from_db(&role)?,
                is_local,
                has_sealed_key,
            })
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(BridgeSummary {
        uid: uid.to_string(),
        key_id,
        label,
        generation: u32::try_from(generation).map_err(|_| Error::InvalidBridgePackage)?,
        public_key: vec_to_32(&public_key)?,
        salt: vec_to_salt(&salt)?,
        destroyed: destroyed_at.is_some(),
        parties,
    })
}

pub fn events(
    conn: &Connection,
    uid: Option<&str>,
    since_id: Option<i64>,
) -> Result<Vec<BridgeEvent>> {
    let mut sql = String::from(
        "SELECT e.id, b.uid, e.event_type, e.detail, e.created_at
         FROM bridge_events e
         JOIN private_bridges b ON b.id = e.bridge_id
         WHERE 1=1",
    );
    if uid.is_some() {
        sql.push_str(" AND b.uid = ?1");
    }
    if since_id.is_some() {
        sql.push_str(if uid.is_some() {
            " AND e.id > ?2"
        } else {
            " AND e.id > ?1"
        });
    }
    sql.push_str(" ORDER BY e.id");
    let mut stmt = conn.prepare(&sql)?;
    let rows = match (uid, since_id) {
        (Some(uid), Some(since)) => stmt
            .query_map(params![uid, since], event_from_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?,
        (Some(uid), None) => stmt
            .query_map(params![uid], event_from_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?,
        (None, Some(since)) => stmt
            .query_map(params![since], event_from_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?,
        (None, None) => stmt
            .query_map([], event_from_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?,
    };
    Ok(rows)
}

fn event_from_row(row: &rusqlite::Row) -> rusqlite::Result<BridgeEvent> {
    Ok(BridgeEvent {
        id: row.get(0)?,
        uid: row.get(1)?,
        event_type: row.get(2)?,
        detail: row.get(3)?,
        created_at: row.get(4)?,
    })
}

/// A remaining *member* who holds the sealed secret drops `removed_label`,
/// rotates (or destroys if fewer than two members remain), and returns
/// per-person packages for every remaining stakeholder plus the removed
/// employee (so their store can drop the old standard).
///
/// Library callers that do not write packages to disk can use this helper,
/// which commits immediately. The CLI plans, writes envelopes, then commits.
pub fn remove_member(
    conn: &Connection,
    uid: &str,
    removed_label: &str,
    local_label: &str,
    encryption_sk: &[u8; 32],
) -> Result<RemoveMemberOutcome> {
    let planned = plan_remove_member(conn, uid, removed_label, local_label, encryption_sk)?;
    commit_planned_removal(conn, &planned)?;
    Ok(planned.outcome)
}

/// Build rotation/destruction packages without mutating this store.
pub fn plan_remove_member(
    conn: &Connection,
    uid: &str,
    removed_label: &str,
    local_label: &str,
    encryption_sk: &[u8; 32],
) -> Result<PlannedRemoval> {
    let summary = get(conn, uid)?;
    if summary.destroyed {
        return Err(Error::BridgeDestroyed);
    }
    if local_label == removed_label {
        return Err(Error::InvalidBridge);
    }
    let local = summary
        .parties
        .iter()
        .find(|p| p.label == local_label && p.role == PartyRole::Member && p.has_sealed_key)
        .ok_or(Error::SealedKeyNotHeld)?;
    if keys::encryption_public_from_secret(encryption_sk) != local.encryption_public_key {
        return Err(Error::IntegrityCheckFailed);
    }
    if !summary
        .parties
        .iter()
        .any(|p| p.label == removed_label && p.role == PartyRole::Member)
    {
        return Err(Error::NotBridgeMember);
    }

    let secret = unseal_local_secret(conn, uid, local_label, encryption_sk)?;
    let members = remaining_members(&summary, removed_label)?;

    let notify = notify_labels(
        summary
            .parties
            .iter()
            .filter(|p| p.role == PartyRole::Member)
            .map(|p| p.label.as_str()),
    );
    let bridge_id = last_bridge_id(conn, uid)?;
    let old_public = summary.public_key;
    let old_signing = SigningKey::from_bytes(&secret);
    let remaining_member_list = sorted_keys(&members);

    if members.len() < 2 {
        let supervisors = supervisor_pubs_for(&members, &summary.parties);
        let mut packages = Vec::new();
        for party in &summary.parties {
            packages.push(destroy_package_for(
                uid,
                summary.generation,
                summary.label.as_deref().unwrap_or(""),
                &old_public,
                &summary.salt,
                &members,
                &supervisors,
                removed_label,
                &party.label,
                party.encryption_public_key,
                party.role,
                &old_signing,
            )?);
        }
        return Ok(PlannedRemoval {
            outcome: RemoveMemberOutcome {
                uid: uid.to_string(),
                destroyed: true,
                remaining_members: remaining_member_list,
                packages,
            },
            kind: PlannedRemovalKind::Destroy {
                uid: uid.to_string(),
                bridge_id,
                removed_label: removed_label.to_string(),
                notify,
            },
        });
    }

    let new_salt = random_salt();
    let (new_secret, new_public) = keys::generate_signing_keypair();
    let new_generation = summary.generation + 1;
    let supervisors = supervisor_pubs_for(&members, &summary.parties);

    let new_secret_bytes: &[u8; 32] = &new_secret;
    let mut packages = packages_for_roster(
        KIND_ROTATE,
        KIND_SUPERVISOR,
        uid,
        new_generation,
        summary.label.as_deref().unwrap_or(""),
        &new_public,
        &new_salt,
        &members,
        &supervisors,
        removed_label,
        Some(new_secret_bytes),
        Some(&old_signing),
    )?;
    packages.push(destroy_package_for(
        uid,
        summary.generation,
        summary.label.as_deref().unwrap_or(""),
        &old_public,
        &summary.salt,
        &members,
        &supervisors,
        removed_label,
        removed_label,
        summary
            .parties
            .iter()
            .find(|p| p.label == removed_label)
            .map(|p| p.encryption_public_key)
            .ok_or(Error::NotBridgeMember)?,
        PartyRole::Member,
        &old_signing,
    )?);

    Ok(PlannedRemoval {
        outcome: RemoveMemberOutcome {
            uid: uid.to_string(),
            destroyed: false,
            remaining_members: remaining_member_list,
            packages,
        },
        kind: PlannedRemovalKind::Rotate {
            uid: uid.to_string(),
            bridge_id,
            removed_label: removed_label.to_string(),
            notify,
            local_label: local_label.to_string(),
            expected_generation: summary.generation,
            new_generation,
            new_public,
            new_salt,
            members,
            supervisors,
            new_secret,
        },
    })
}

/// Apply a previously planned removal. Callers that write delivery packages
/// should persist those files first so a later disk failure does not strand
/// other stores on the old generation.
pub fn commit_planned_removal(conn: &Connection, planned: &PlannedRemoval) -> Result<()> {
    match &planned.kind {
        PlannedRemovalKind::Destroy {
            uid,
            bridge_id,
            removed_label,
            notify,
        } => with_immediate_transaction(conn, |conn| {
            conn.execute(
                "UPDATE private_bridges SET destroyed_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                 WHERE uid = ?1",
                params![uid],
            )?;
            conn.execute(
                "DELETE FROM private_bridge_sealed_keys WHERE bridge_id = ?1",
                params![bridge_id],
            )?;
            insert_event(
                conn,
                *bridge_id,
                "destroyed",
                json!({
                    "uid": uid,
                    "removed": removed_label,
                    "notify": notify,
                }),
            )?;
            Ok(())
        }),
        PlannedRemovalKind::Rotate {
            uid,
            bridge_id,
            removed_label,
            notify,
            local_label,
            expected_generation,
            new_generation,
            new_public,
            new_salt,
            members,
            supervisors,
            new_secret,
        } => with_immediate_transaction(conn, |conn| {
            persist_rotation(
                conn,
                uid,
                *bridge_id,
                *expected_generation,
                *new_generation,
                new_public,
                new_salt,
                members,
                supervisors,
                local_label,
                new_secret,
            )?;
            insert_event(
                conn,
                *bridge_id,
                "member_removed",
                json!({"uid": uid, "removed": removed_label, "notify": notify}),
            )?;
            insert_event(
                conn,
                *bridge_id,
                "rotated",
                json!({
                    "uid": uid,
                    "generation": new_generation,
                    "members": sorted_keys(members),
                    "supervisors": sorted_keys(supervisors),
                    "salt": hex::encode(new_salt),
                }),
            )?;
            Ok(())
        }),
    }
}

/// Coordinator-side membership drop used by tree eviction. Does not rotate
/// the shared secret (this store typically has no member private key).
/// Remaining members must run `remove_member` and deliver the packages.
pub fn on_leaf_removed(
    conn: &Connection,
    key_id: i64,
    node_label: &str,
) -> Result<Vec<BridgeChange>> {
    let mut stmt = conn.prepare(
        "SELECT b.uid FROM private_bridges b
         JOIN private_bridge_members m ON m.bridge_id = b.id
         WHERE b.destroyed_at IS NULL AND b.key_id = ?1
           AND m.node_label = ?2 AND m.role = 'member'",
    )?;
    let uids: Vec<String> = stmt
        .query_map(params![key_id, node_label], |row| row.get(0))?
        .collect::<rusqlite::Result<_>>()?;

    let mut changes = Vec::new();
    for uid in uids {
        if let Some(change) = drop_member_on_coordinator(conn, &uid, node_label)? {
            changes.push(change);
        }
    }
    Ok(changes)
}

/// Drop a revoked employee from every live private bridge they belong to,
/// including bridges not tied to a specific tree `key_id`.
pub fn on_member_revoked(conn: &Connection, node_label: &str) -> Result<Vec<BridgeChange>> {
    let mut stmt = conn.prepare(
        "SELECT b.uid FROM private_bridges b
         JOIN private_bridge_members m ON m.bridge_id = b.id
         WHERE b.destroyed_at IS NULL
           AND m.node_label = ?1 AND m.role = 'member'",
    )?;
    let uids: Vec<String> = stmt
        .query_map(params![node_label], |row| row.get(0))?
        .collect::<rusqlite::Result<_>>()?;

    let mut changes = Vec::new();
    for uid in uids {
        if let Some(change) = drop_member_on_coordinator(conn, &uid, node_label)? {
            changes.push(change);
        }
    }
    Ok(changes)
}

pub fn sign_message(
    conn: &Connection,
    uid: &str,
    local_label: &str,
    encryption_sk: &[u8; 32],
    signing_sk: &[u8; 32],
    message: &[u8],
) -> Result<BridgeSignature> {
    let summary = get(conn, uid)?;
    if summary.destroyed {
        return Err(Error::BridgeDestroyed);
    }
    let member = summary
        .parties
        .iter()
        .find(|p| p.label == local_label && p.role == PartyRole::Member)
        .ok_or(Error::NotBridgeMember)?;
    if !member.has_sealed_key {
        return Err(Error::SealedKeyNotHeld);
    }
    if keys::encryption_public_from_secret(encryption_sk) != member.encryption_public_key {
        return Err(Error::IntegrityCheckFailed);
    }
    let roster_signing = member.signing_public_key.ok_or(Error::InvalidBridge)?;
    let provided_signing = SigningKey::from_bytes(signing_sk)
        .verifying_key()
        .to_bytes();
    if provided_signing != roster_signing {
        return Err(Error::IntegrityCheckFailed);
    }
    match signing_public_for_label(conn, local_label) {
        Ok(local) if local != roster_signing => return Err(Error::IntegrityCheckFailed),
        Ok(_) | Err(Error::NodeNotFound) => {}
        Err(err) => return Err(err),
    }
    let bridge_sk = unseal_local_secret(conn, uid, local_label, encryption_sk)?;
    signing::sign_with_bridge(
        uid,
        summary.generation,
        &summary.salt,
        local_label,
        &bridge_sk,
        signing_sk,
        message,
    )
}

pub fn verify_message(
    conn: &Connection,
    uid: &str,
    verifier_label: &str,
    message: &[u8],
    artifact: &BridgeSignature,
) -> Result<()> {
    let summary = get(conn, uid)?;
    if summary.destroyed {
        return Err(Error::BridgeDestroyed);
    }
    if artifact.uid != uid || artifact.generation != summary.generation {
        return Err(Error::BridgeGenerationMismatch);
    }
    if artifact.bridge_salt != summary.salt {
        return Err(Error::BridgeGenerationMismatch);
    }
    let signer = summary
        .parties
        .iter()
        .find(|p| p.role == PartyRole::Member && p.label == artifact.signer_label)
        .ok_or(Error::NotBridgeMember)?;
    let verifier_ok = summary
        .parties
        .iter()
        .any(|p| p.role == PartyRole::Member && p.label == verifier_label);
    if !verifier_ok {
        return Err(Error::NotBridgeMember);
    }
    let roster_signing = signer.signing_public_key.ok_or(Error::InvalidBridge)?;
    match signing_public_for_label(conn, &artifact.signer_label) {
        Ok(local) if local != roster_signing => return Err(Error::IntegrityCheckFailed),
        Ok(_) | Err(Error::NodeNotFound) => {}
        Err(err) => return Err(err),
    }
    signing::verify_bridge_signature(artifact, &summary.public_key, &roster_signing, message)
}

pub fn encryption_public_for_label(
    conn: &Connection,
    key_id: Option<i64>,
    label: &str,
) -> Result<[u8; 32]> {
    if let Some(key_id) = key_id {
        let leaf: Option<Vec<u8>> = conn
            .query_row(
                "SELECT h.public_key FROM key_nodes n
                 JOIN hardware_keys h ON h.id = n.hardware_key_id
                 WHERE n.key_id = ?1 AND n.label = ?2 AND n.is_active = 1
                   AND h.revoked_at IS NULL",
                params![key_id, label],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(pk) = leaf {
            return vec_to_32(&pk);
        }
    }
    let mut stmt = conn.prepare(
        "SELECT public_key FROM hardware_keys
         WHERE label = ?1 AND key_type = 'encryption' AND revoked_at IS NULL
         ORDER BY id",
    )?;
    let keys: Vec<Vec<u8>> = stmt
        .query_map(params![label], |row| row.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    match keys.as_slice() {
        [pk] => vec_to_32(pk),
        [] => Err(Error::NodeNotFound),
        _ => Err(Error::InvalidBridge),
    }
}

pub fn signing_public_for_label(conn: &Connection, label: &str) -> Result<[u8; 32]> {
    let mut stmt = conn.prepare(
        "SELECT public_key FROM hardware_keys
         WHERE label = ?1 AND key_type = 'signing' AND revoked_at IS NULL
         ORDER BY id",
    )?;
    let keys: Vec<Vec<u8>> = stmt
        .query_map(params![label], |row| row.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    match keys.as_slice() {
        [pk] => {
            let pk = vec_to_32(pk)?;
            VerifyingKey::from_bytes(&pk).map_err(|_| Error::InvalidPublicKey)?;
            Ok(pk)
        }
        [] => Err(Error::NodeNotFound),
        _ => Err(Error::InvalidBridge),
    }
}

fn unique_members(parties: &[BridgePartyInput]) -> Result<BTreeMap<String, MemberKeys>> {
    let mut map = BTreeMap::new();
    for party in parties {
        if party.label.is_empty() {
            return Err(Error::InvalidBridge);
        }
        if is_weak_x25519_public_key(&party.encryption_public_key) {
            return Err(Error::InvalidPublicKey);
        }
        let signing = party.signing_public_key.ok_or(Error::InvalidPublicKey)?;
        VerifyingKey::from_bytes(&signing).map_err(|_| Error::InvalidPublicKey)?;
        if map
            .insert(
                party.label.clone(),
                MemberKeys {
                    encryption: party.encryption_public_key,
                    signing,
                },
            )
            .is_some()
        {
            return Err(Error::DuplicateNodeLabel);
        }
    }
    Ok(map)
}

fn unique_supervisors(parties: &[BridgePartyInput]) -> Result<BTreeMap<String, [u8; 32]>> {
    let mut map = BTreeMap::new();
    for party in parties {
        if party.label.is_empty() {
            return Err(Error::InvalidBridge);
        }
        if is_weak_x25519_public_key(&party.encryption_public_key) {
            return Err(Error::InvalidPublicKey);
        }
        if map
            .insert(party.label.clone(), party.encryption_public_key)
            .is_some()
        {
            return Err(Error::DuplicateNodeLabel);
        }
    }
    Ok(map)
}

fn fill_implied_supervisors(
    members: &BTreeMap<String, MemberKeys>,
    supervisors: &mut BTreeMap<String, [u8; 32]>,
) -> Result<()> {
    for member in members.keys() {
        if let Some(parent) = parent_node_label(member) {
            if members.contains_key(parent) {
                continue;
            }
            if !supervisors.contains_key(parent) {
                return Err(Error::NodeNotFound);
            }
        }
    }
    supervisors.retain(|label, _| !members.contains_key(label));
    Ok(())
}

fn supervisor_pubs_for(
    members: &BTreeMap<String, MemberKeys>,
    previous: &[BridgeParty],
) -> BTreeMap<String, [u8; 32]> {
    let mut needed: BTreeSet<String> = BTreeSet::new();
    for label in members.keys() {
        if let Some(parent) = parent_node_label(label) {
            if !members.contains_key(parent) {
                needed.insert(parent.to_string());
            }
        }
    }
    let mut out = BTreeMap::new();
    for party in previous {
        if needed.contains(&party.label) {
            out.insert(party.label.clone(), party.encryption_public_key);
        }
    }
    out
}

#[allow(clippy::too_many_arguments)]
fn persist_new_bridge(
    conn: &Connection,
    uid: &str,
    key_id: Option<i64>,
    label: Option<&str>,
    generation: u32,
    public_key: &[u8; 32],
    salt: &[u8; SALT_LEN],
    members: &BTreeMap<String, MemberKeys>,
    supervisors: &BTreeMap<String, [u8; 32]>,
    local_label: Option<&str>,
    secret: &[u8; 32],
) -> Result<()> {
    conn.execute(
        "INSERT INTO private_bridges (uid, key_id, label, generation, public_key, salt)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            uid,
            key_id,
            label,
            generation as i64,
            public_key.as_slice(),
            salt.as_slice()
        ],
    )?;
    let bridge_id = conn.last_insert_rowid();
    insert_member_parties(conn, bridge_id, members, local_label)?;
    insert_supervisor_parties(conn, bridge_id, supervisors, local_label)?;
    seal_local_if_member(conn, bridge_id, local_label.unwrap_or(""), members, secret)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn persist_rotation(
    conn: &Connection,
    uid: &str,
    bridge_id: i64,
    expected_generation: u32,
    generation: u32,
    public_key: &[u8; 32],
    salt: &[u8; SALT_LEN],
    members: &BTreeMap<String, MemberKeys>,
    supervisors: &BTreeMap<String, [u8; 32]>,
    local_label: &str,
    secret: &[u8; 32],
) -> Result<()> {
    let updated = conn.execute(
        "UPDATE private_bridges SET generation = ?1, public_key = ?2, salt = ?3
         WHERE uid = ?4 AND generation = ?5 AND destroyed_at IS NULL",
        params![
            generation as i64,
            public_key.as_slice(),
            salt.as_slice(),
            uid,
            expected_generation as i64
        ],
    )?;
    if updated != 1 {
        return Err(Error::BridgeGenerationMismatch);
    }
    conn.execute(
        "DELETE FROM private_bridge_members WHERE bridge_id = ?1",
        params![bridge_id],
    )?;
    insert_member_parties(conn, bridge_id, members, Some(local_label))?;
    insert_supervisor_parties(conn, bridge_id, supervisors, Some(local_label))?;
    conn.execute(
        "DELETE FROM private_bridge_sealed_keys WHERE bridge_id = ?1",
        params![bridge_id],
    )?;
    seal_local_if_member(conn, bridge_id, local_label, members, secret)?;
    Ok(())
}

fn insert_member_parties(
    conn: &Connection,
    bridge_id: i64,
    members: &BTreeMap<String, MemberKeys>,
    local_label: Option<&str>,
) -> Result<()> {
    for (label, keys) in members {
        let is_local = local_label == Some(label.as_str());
        conn.execute(
            "INSERT INTO private_bridge_members
             (bridge_id, node_label, encryption_public_key, signing_public_key, role, is_local)
             VALUES (?1, ?2, ?3, ?4, 'member', ?5)",
            params![
                bridge_id,
                label,
                keys.encryption.as_slice(),
                keys.signing.as_slice(),
                is_local as i64
            ],
        )?;
    }
    Ok(())
}

fn insert_supervisor_parties(
    conn: &Connection,
    bridge_id: i64,
    supervisors: &BTreeMap<String, [u8; 32]>,
    local_label: Option<&str>,
) -> Result<()> {
    for (label, pk) in supervisors {
        let is_local = local_label == Some(label.as_str());
        conn.execute(
            "INSERT INTO private_bridge_members
             (bridge_id, node_label, encryption_public_key, signing_public_key, role, is_local)
             VALUES (?1, ?2, ?3, NULL, 'supervisor', ?4)",
            params![bridge_id, label, pk.as_slice(), is_local as i64],
        )?;
    }
    Ok(())
}

fn seal_local_if_member(
    conn: &Connection,
    bridge_id: i64,
    local_label: &str,
    members: &BTreeMap<String, MemberKeys>,
    secret: &[u8; 32],
) -> Result<()> {
    let Some(keys) = members.get(local_label) else {
        return Ok(());
    };
    let wrap_salt = random_salt();
    let wrapped = seal_secret(&keys.encryption, &wrap_salt, secret)?;
    conn.execute(
        "INSERT INTO private_bridge_sealed_keys
         (bridge_id, node_label, wrap_salt, wrapped_secret)
         VALUES (?1, ?2, ?3, ?4)",
        params![bridge_id, local_label, wrap_salt.as_slice(), wrapped],
    )?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn packages_for_roster(
    member_kind: u8,
    supervisor_kind: u8,
    uid: &str,
    generation: u32,
    bridge_label: &str,
    public_key: &[u8; 32],
    salt: &[u8; SALT_LEN],
    members: &BTreeMap<String, MemberKeys>,
    supervisors: &BTreeMap<String, [u8; 32]>,
    removed_label: &str,
    secret: Option<&[u8; 32]>,
    old_signing: Option<&SigningKey>,
) -> Result<Vec<DeliveryPackage>> {
    let mut packages = Vec::new();
    for (label, keys) in members {
        let wrap = secret.map(|_| random_salt());
        packages.push(DeliveryPackage {
            label: label.clone(),
            role: PartyRole::Member,
            recipient_public_key: keys.encryption,
            bytes: encode_package(PackageFields {
                kind: member_kind,
                uid,
                generation,
                bridge_label,
                public_key,
                salt,
                recipient_label: label,
                recipient_public_key: &keys.encryption,
                role: PartyRole::Member,
                members,
                supervisors,
                removed_label,
                wrap_salt: wrap.as_ref(),
                secret,
                old_signing,
            })?,
        });
    }
    for (label, pk) in supervisors {
        packages.push(DeliveryPackage {
            label: label.clone(),
            role: PartyRole::Supervisor,
            recipient_public_key: *pk,
            bytes: encode_package(PackageFields {
                kind: supervisor_kind,
                uid,
                generation,
                bridge_label,
                public_key,
                salt,
                recipient_label: label,
                recipient_public_key: pk,
                role: PartyRole::Supervisor,
                members,
                supervisors,
                removed_label,
                wrap_salt: None,
                secret: None,
                old_signing,
            })?,
        });
    }
    Ok(packages)
}

#[allow(clippy::too_many_arguments)]
fn destroy_package_for(
    uid: &str,
    generation: u32,
    bridge_label: &str,
    public_key: &[u8; 32],
    salt: &[u8; SALT_LEN],
    members: &BTreeMap<String, MemberKeys>,
    supervisors: &BTreeMap<String, [u8; 32]>,
    removed_label: &str,
    recipient_label: &str,
    recipient_pk: [u8; 32],
    recipient_role: PartyRole,
    old_signing: &SigningKey,
) -> Result<DeliveryPackage> {
    Ok(DeliveryPackage {
        label: recipient_label.to_string(),
        role: recipient_role,
        recipient_public_key: recipient_pk,
        bytes: encode_package(PackageFields {
            kind: KIND_DESTROY,
            uid,
            generation,
            bridge_label,
            public_key,
            salt,
            recipient_label,
            recipient_public_key: &recipient_pk,
            role: recipient_role,
            members,
            supervisors,
            removed_label,
            wrap_salt: None,
            secret: None,
            old_signing: Some(old_signing),
        })?,
    })
}

struct PackageFields<'a> {
    kind: u8,
    uid: &'a str,
    generation: u32,
    bridge_label: &'a str,
    public_key: &'a [u8; 32],
    salt: &'a [u8; SALT_LEN],
    recipient_label: &'a str,
    recipient_public_key: &'a [u8; 32],
    role: PartyRole,
    members: &'a BTreeMap<String, MemberKeys>,
    supervisors: &'a BTreeMap<String, [u8; 32]>,
    removed_label: &'a str,
    wrap_salt: Option<&'a [u8; SALT_LEN]>,
    secret: Option<&'a [u8; 32]>,
    old_signing: Option<&'a SigningKey>,
}

struct DecodedPackage {
    kind: u8,
    uid: String,
    generation: u32,
    bridge_label: String,
    public_key: [u8; 32],
    salt: [u8; SALT_LEN],
    recipient_label: String,
    recipient_public_key: [u8; 32],
    role: PartyRole,
    members: BTreeMap<String, MemberKeys>,
    supervisors: BTreeMap<String, [u8; 32]>,
    removed_label: String,
    wrap_salt: Option<[u8; SALT_LEN]>,
    secret: Option<Zeroizing<[u8; 32]>>,
    auth_sig: Option<[u8; 64]>,
}

fn encode_package(f: PackageFields<'_>) -> Result<Vec<u8>> {
    if is_weak_x25519_public_key(f.recipient_public_key) {
        return Err(Error::InvalidPublicKey);
    }
    let mut payload = Vec::new();
    push_len_prefixed(&mut payload, f.uid.as_bytes())?;
    payload.extend_from_slice(&f.generation.to_be_bytes());
    push_len_prefixed(&mut payload, f.bridge_label.as_bytes())?;
    payload.extend_from_slice(f.public_key);
    payload.extend_from_slice(f.salt);
    push_len_prefixed(&mut payload, f.recipient_label.as_bytes())?;
    payload.push(f.role.to_u8());
    push_member_map(&mut payload, f.members)?;
    push_party_map(&mut payload, f.supervisors)?;
    push_len_prefixed(&mut payload, f.removed_label.as_bytes())?;
    let has_secret = f.secret.is_some();
    payload.push(u8::from(has_secret));
    if let (Some(wrap), Some(secret)) = (f.wrap_salt, f.secret) {
        payload.extend_from_slice(wrap);
        payload.extend_from_slice(secret);
    }
    let has_auth = f.old_signing.is_some();
    payload.push(u8::from(has_auth));
    if let Some(signing_key) = f.old_signing {
        let preimage = update_auth_preimage(
            f.uid,
            f.generation,
            f.kind,
            f.public_key,
            f.salt,
            f.recipient_label,
            f.members,
            f.supervisors,
            f.removed_label,
        )?;
        payload.extend_from_slice(&signing::sign(&signing_key.to_bytes(), &preimage));
    }

    let sealed = crypto_box::PublicKey::from_bytes(*f.recipient_public_key)
        .seal(&mut rand::rngs::OsRng, &payload)
        .expect("crypto_box sealing should not fail for an in-memory payload");
    let payload_len = u32::try_from(sealed.len()).map_err(|_| Error::BundleFieldTooLarge)?;
    let mut out = Vec::new();
    out.extend_from_slice(PACKAGE_MAGIC);
    out.push(FORMAT_VERSION);
    out.push(f.kind);
    out.extend_from_slice(f.recipient_public_key);
    out.extend_from_slice(&payload_len.to_be_bytes());
    out.extend_from_slice(&sealed);
    Ok(out)
}

fn decode_package(bytes: &[u8], recipient_sk: &[u8; 32]) -> Result<DecodedPackage> {
    let mut data = bytes;
    if take_n(&mut data, 4)? != PACKAGE_MAGIC {
        return Err(Error::InvalidBridgePackage);
    }
    if take_u8(&mut data)? != FORMAT_VERSION {
        return Err(Error::InvalidBridgePackage);
    }
    let kind = take_u8(&mut data)?;
    let recipient_public_key = take_array::<32>(&mut data)?;
    let payload_len = u32::from_be_bytes(take_array(&mut data)?) as usize;
    let sealed = take_n(&mut data, payload_len)?;
    if !data.is_empty() {
        return Err(Error::InvalidBridgePackage);
    }
    let secret_key = crypto_box::SecretKey::from(*recipient_sk);
    let payload = secret_key
        .unseal(sealed)
        .map_err(|_| Error::InvalidBridgePackage)?;
    let mut payload = payload.as_slice();
    let uid = utf8(take_len_prefixed(&mut payload)?)?;
    let generation = u32::from_be_bytes(take_array(&mut payload)?);
    let bridge_label = utf8(take_len_prefixed(&mut payload)?)?;
    let public_key = take_array::<32>(&mut payload)?;
    let salt = take_array::<SALT_LEN>(&mut payload)?;
    let recipient_label = utf8(take_len_prefixed(&mut payload)?)?;
    let role = PartyRole::from_u8(take_u8(&mut payload)?)?;
    let members = take_member_map(&mut payload)?;
    let supervisors = take_party_map(&mut payload)?;
    let removed_label = utf8(take_len_prefixed(&mut payload)?)?;
    let has_secret = take_u8(&mut payload)? != 0;
    let (wrap_salt, secret) = if has_secret {
        let wrap = take_array::<SALT_LEN>(&mut payload)?;
        let sk = take_array::<32>(&mut payload)?;
        (Some(wrap), Some(Zeroizing::new(sk)))
    } else {
        (None, None)
    };
    let has_auth = take_u8(&mut payload)? != 0;
    let auth_sig = if has_auth {
        Some(take_array::<64>(&mut payload)?)
    } else {
        None
    };
    if !payload.is_empty() {
        return Err(Error::InvalidBridgePackage);
    }
    Ok(DecodedPackage {
        kind,
        uid,
        generation,
        bridge_label,
        public_key,
        salt,
        recipient_label,
        recipient_public_key,
        role,
        members,
        supervisors,
        removed_label,
        wrap_salt,
        secret,
        auth_sig,
    })
}

fn insert_from_invite(conn: &Connection, decoded: &DecodedPackage) -> Result<()> {
    validate_decoded_recipient(decoded)?;
    if get_optional(conn, &decoded.uid)?.is_some() {
        return Err(Error::InvalidBridge);
    }
    with_immediate_transaction(conn, |conn| {
        conn.execute(
            "INSERT INTO private_bridges (uid, label, generation, public_key, salt)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                decoded.uid,
                empty_to_none(&decoded.bridge_label),
                decoded.generation as i64,
                decoded.public_key.as_slice(),
                decoded.salt.as_slice()
            ],
        )?;
        let bridge_id = conn.last_insert_rowid();
        replace_roster_and_secret(conn, bridge_id, decoded)?;
        insert_event(
            conn,
            bridge_id,
            "imported",
            json!({
                "uid": decoded.uid,
                "role": decoded.role.as_str(),
                "node": decoded.recipient_label,
                "generation": decoded.generation,
            }),
        )?;
        Ok(())
    })
}

fn apply_rotate(conn: &Connection, decoded: &DecodedPackage) -> Result<()> {
    validate_decoded_recipient(decoded)?;
    let summary = get(conn, &decoded.uid)?;
    if summary.destroyed {
        return Err(Error::BridgeDestroyed);
    }
    if decoded.generation != summary.generation + 1 {
        return Err(Error::BridgeGenerationMismatch);
    }
    verify_update_auth(decoded, &summary.public_key)?;
    let bridge_id = last_bridge_id(conn, &decoded.uid)?;
    with_immediate_transaction(conn, |conn| {
        let updated = conn.execute(
            "UPDATE private_bridges SET generation = ?1, public_key = ?2, salt = ?3, label = COALESCE(?4, label)
             WHERE uid = ?5 AND generation = ?6 AND destroyed_at IS NULL",
            params![
                decoded.generation as i64,
                decoded.public_key.as_slice(),
                decoded.salt.as_slice(),
                empty_to_none(&decoded.bridge_label),
                decoded.uid,
                summary.generation as i64
            ],
        )?;
        if updated != 1 {
            return Err(Error::BridgeGenerationMismatch);
        }
        conn.execute(
            "DELETE FROM private_bridge_members WHERE bridge_id = ?1",
            params![bridge_id],
        )?;
        conn.execute(
            "DELETE FROM private_bridge_sealed_keys WHERE bridge_id = ?1",
            params![bridge_id],
        )?;
        replace_roster_and_secret(conn, bridge_id, decoded)?;
        insert_event(
            conn,
            bridge_id,
            "rotated",
            json!({
                "uid": decoded.uid,
                "generation": decoded.generation,
                "node": decoded.recipient_label,
            }),
        )?;
        Ok(())
    })
}

fn replace_roster_and_secret(
    conn: &Connection,
    bridge_id: i64,
    decoded: &DecodedPackage,
) -> Result<()> {
    insert_member_parties(
        conn,
        bridge_id,
        &decoded.members,
        Some(&decoded.recipient_label),
    )?;
    insert_supervisor_parties(
        conn,
        bridge_id,
        &decoded.supervisors,
        Some(&decoded.recipient_label),
    )?;
    if let (Some(wrap_salt), Some(secret), PartyRole::Member) =
        (decoded.wrap_salt, decoded.secret.as_ref(), decoded.role)
    {
        let wrapped = seal_secret(&decoded.recipient_public_key, &wrap_salt, secret)?;
        conn.execute(
            "INSERT INTO private_bridge_sealed_keys
             (bridge_id, node_label, wrap_salt, wrapped_secret)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                bridge_id,
                decoded.recipient_label,
                wrap_salt.as_slice(),
                wrapped
            ],
        )?;
    }
    Ok(())
}

fn validate_decoded_recipient(decoded: &DecodedPackage) -> Result<()> {
    let in_members = decoded.members.contains_key(&decoded.recipient_label);
    let in_supervisors = decoded.supervisors.contains_key(&decoded.recipient_label);
    let role_matches = match decoded.role {
        PartyRole::Member => in_members,
        PartyRole::Supervisor => in_supervisors,
    };
    if !role_matches {
        return Err(Error::InvalidBridgePackage);
    }
    let expected_pk = match decoded.role {
        PartyRole::Member => decoded.members[&decoded.recipient_label].encryption,
        PartyRole::Supervisor => decoded.supervisors[&decoded.recipient_label],
    };
    if expected_pk != decoded.recipient_public_key {
        return Err(Error::InvalidBridgePackage);
    }
    Ok(())
}

fn apply_destroy(conn: &Connection, decoded: &DecodedPackage) -> Result<()> {
    let summary = get(conn, &decoded.uid)?;
    if summary.destroyed {
        return Ok(());
    }
    verify_update_auth(decoded, &summary.public_key)?;
    let bridge_id = last_bridge_id(conn, &decoded.uid)?;
    with_immediate_transaction(conn, |conn| {
        conn.execute(
            "UPDATE private_bridges SET destroyed_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
             WHERE uid = ?1 AND destroyed_at IS NULL",
            params![decoded.uid],
        )?;
        conn.execute(
            "DELETE FROM private_bridge_sealed_keys WHERE bridge_id = ?1",
            params![bridge_id],
        )?;
        insert_event(
            conn,
            bridge_id,
            "destroyed",
            json!({"uid": decoded.uid, "node": decoded.recipient_label}),
        )?;
        Ok(())
    })
}

fn verify_update_auth(decoded: &DecodedPackage, old_public: &[u8; 32]) -> Result<()> {
    let sig = decoded.auth_sig.ok_or(Error::InvalidBridgePackage)?;
    let preimage = update_auth_preimage(
        &decoded.uid,
        decoded.generation,
        decoded.kind,
        &decoded.public_key,
        &decoded.salt,
        &decoded.recipient_label,
        &decoded.members,
        &decoded.supervisors,
        &decoded.removed_label,
    )?;
    signing::verify_signature(old_public, &preimage, &sig)
}

fn drop_member_on_coordinator(
    conn: &Connection,
    uid: &str,
    removed_label: &str,
) -> Result<Option<BridgeChange>> {
    let summary = get(conn, uid)?;
    if summary.destroyed {
        return Ok(None);
    }
    let remaining: Vec<String> = summary
        .parties
        .iter()
        .filter(|p| p.role == PartyRole::Member && p.label != removed_label)
        .map(|p| p.label.clone())
        .collect();
    let notify = notify_labels(
        summary
            .parties
            .iter()
            .filter(|p| p.role == PartyRole::Member)
            .map(|p| p.label.as_str()),
    );
    let bridge_id = last_bridge_id(conn, uid)?;
    let kind = if remaining.len() < 2 {
        BridgeChangeKind::Destroyed
    } else {
        BridgeChangeKind::NeedsMemberRotate
    };
    with_immediate_transaction(conn, |conn| {
        conn.execute(
            "DELETE FROM private_bridge_members WHERE bridge_id = ?1 AND node_label = ?2",
            params![bridge_id, removed_label],
        )?;
        if kind == BridgeChangeKind::Destroyed {
            conn.execute(
                "UPDATE private_bridges SET destroyed_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                 WHERE uid = ?1",
                params![uid],
            )?;
            conn.execute(
                "DELETE FROM private_bridge_sealed_keys WHERE bridge_id = ?1",
                params![bridge_id],
            )?;
            insert_event(
                conn,
                bridge_id,
                "destroyed",
                json!({"uid": uid, "removed": removed_label, "notify": notify}),
            )?;
        } else {
            insert_event(
                conn,
                bridge_id,
                "member_removed",
                json!({"uid": uid, "removed": removed_label, "notify": notify}),
            )?;
        }
        Ok(())
    })?;
    let notice = encode_notice(uid, removed_label, &remaining, &notify, kind)?;
    Ok(Some(BridgeChange {
        uid: uid.to_string(),
        removed_member: removed_label.to_string(),
        remaining_members: remaining,
        notify,
        kind,
        notice,
    }))
}

fn encode_notice(
    uid: &str,
    removed: &str,
    remaining: &[String],
    notify: &[String],
    kind: BridgeChangeKind,
) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    out.extend_from_slice(NOTICE_MAGIC);
    out.push(FORMAT_VERSION);
    out.push(match kind {
        BridgeChangeKind::NeedsMemberRotate => 1,
        BridgeChangeKind::Destroyed => 2,
    });
    push_len_prefixed(&mut out, uid.as_bytes())?;
    push_len_prefixed(&mut out, removed.as_bytes())?;
    let n = u16::try_from(remaining.len()).map_err(|_| Error::BundleFieldTooLarge)?;
    out.extend_from_slice(&n.to_be_bytes());
    for label in remaining {
        push_len_prefixed(&mut out, label.as_bytes())?;
    }
    let n = u16::try_from(notify.len()).map_err(|_| Error::BundleFieldTooLarge)?;
    out.extend_from_slice(&n.to_be_bytes());
    for label in notify {
        push_len_prefixed(&mut out, label.as_bytes())?;
    }
    Ok(out)
}

fn unseal_local_secret(
    conn: &Connection,
    uid: &str,
    local_label: &str,
    encryption_sk: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>> {
    let bridge_id = last_bridge_id(conn, uid)?;
    let (wrap_salt, wrapped): (Vec<u8>, Vec<u8>) = conn.query_row(
        "SELECT wrap_salt, wrapped_secret FROM private_bridge_sealed_keys
         WHERE bridge_id = ?1 AND node_label = ?2",
        params![bridge_id, local_label],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let wrap_salt = vec_to_salt(&wrap_salt)?;
    let secret_key = crypto_box::SecretKey::from(*encryption_sk);
    let plain = secret_key
        .unseal(&wrapped)
        .map_err(|_| Error::IntegrityCheckFailed)?;
    if plain.len() != SALT_LEN + 32 || plain[..SALT_LEN] != wrap_salt {
        return Err(Error::IntegrityCheckFailed);
    }
    let mut sk = Zeroizing::new([0u8; 32]);
    sk.copy_from_slice(&plain[SALT_LEN..]);
    Ok(sk)
}

fn seal_secret(
    recipient_pub: &[u8; 32],
    wrap_salt: &[u8; SALT_LEN],
    secret: &[u8; 32],
) -> Result<Vec<u8>> {
    if is_weak_x25519_public_key(recipient_pub) {
        return Err(Error::InvalidPublicKey);
    }
    let mut plain = Vec::with_capacity(SALT_LEN + 32);
    plain.extend_from_slice(wrap_salt);
    plain.extend_from_slice(secret);
    Ok(crypto_box::PublicKey::from_bytes(*recipient_pub)
        .seal(&mut rand::rngs::OsRng, &plain)
        .expect("crypto_box sealing should not fail for an in-memory secret"))
}

#[allow(clippy::too_many_arguments)]
fn update_auth_preimage(
    uid: &str,
    generation: u32,
    kind: u8,
    public_key: &[u8; 32],
    salt: &[u8; SALT_LEN],
    recipient_label: &str,
    members: &BTreeMap<String, MemberKeys>,
    supervisors: &BTreeMap<String, [u8; 32]>,
    removed_label: &str,
) -> Result<[u8; 32]> {
    let mut hasher = Sha256::new();
    hasher.update(UPDATE_DOMAIN);
    hash_len_prefixed(&mut hasher, uid.as_bytes())?;
    hasher.update(generation.to_be_bytes());
    hasher.update([kind]);
    hasher.update(public_key);
    hasher.update(salt);
    hash_len_prefixed(&mut hasher, recipient_label.as_bytes())?;
    hash_len_prefixed(&mut hasher, removed_label.as_bytes())?;
    hash_u16_count(&mut hasher, members.len())?;
    for (label, keys) in members {
        if label.is_empty() {
            return Err(Error::InvalidBridgePackage);
        }
        hash_len_prefixed(&mut hasher, label.as_bytes())?;
        hasher.update(keys.encryption);
        hasher.update(keys.signing);
    }
    hash_u16_count(&mut hasher, supervisors.len())?;
    for (label, pk) in supervisors {
        if label.is_empty() {
            return Err(Error::InvalidBridgePackage);
        }
        hash_len_prefixed(&mut hasher, label.as_bytes())?;
        hasher.update(pk);
    }
    Ok(hasher.finalize().into())
}

fn hash_len_prefixed(hasher: &mut Sha256, bytes: &[u8]) -> Result<()> {
    let len = u16::try_from(bytes.len()).map_err(|_| Error::BundleFieldTooLarge)?;
    hasher.update(len.to_be_bytes());
    hasher.update(bytes);
    Ok(())
}

fn hash_u16_count(hasher: &mut Sha256, n: usize) -> Result<()> {
    let n = u16::try_from(n).map_err(|_| Error::BundleFieldTooLarge)?;
    hasher.update(n.to_be_bytes());
    Ok(())
}

fn last_bridge_id(conn: &Connection, uid: &str) -> Result<i64> {
    conn.query_row(
        "SELECT id FROM private_bridges WHERE uid = ?1",
        params![uid],
        |row| row.get(0),
    )
    .optional()?
    .ok_or(Error::BridgeNotFound)
}

fn get_optional(conn: &Connection, uid: &str) -> Result<Option<i64>> {
    Ok(conn
        .query_row(
            "SELECT id FROM private_bridges WHERE uid = ?1",
            params![uid],
            |row| row.get(0),
        )
        .optional()?)
}

fn insert_event(
    conn: &Connection,
    bridge_id: i64,
    event_type: &str,
    detail: serde_json::Value,
) -> Result<()> {
    conn.execute(
        "INSERT INTO bridge_events (bridge_id, event_type, detail) VALUES (?1, ?2, ?3)",
        params![bridge_id, event_type, detail.to_string()],
    )?;
    Ok(())
}

fn sorted_keys<T>(map: &BTreeMap<String, T>) -> Vec<String> {
    map.keys().cloned().collect()
}

fn remaining_members(
    summary: &BridgeSummary,
    removed_label: &str,
) -> Result<BTreeMap<String, MemberKeys>> {
    let mut members = BTreeMap::new();
    for party in &summary.parties {
        if party.role != PartyRole::Member || party.label == removed_label {
            continue;
        }
        let signing = party.signing_public_key.ok_or(Error::InvalidBridge)?;
        members.insert(
            party.label.clone(),
            MemberKeys {
                encryption: party.encryption_public_key,
                signing,
            },
        );
    }
    Ok(members)
}

fn with_immediate_transaction(
    conn: &Connection,
    f: impl FnOnce(&Connection) -> Result<()>,
) -> Result<()> {
    if !conn.is_autocommit() {
        return f(conn);
    }
    conn.execute("BEGIN IMMEDIATE", [])?;
    match f(conn) {
        Ok(()) => {
            conn.execute("COMMIT", [])?;
            Ok(())
        }
        Err(err) => {
            let _ = conn.execute("ROLLBACK", []);
            Err(err)
        }
    }
}

fn empty_to_none(s: &str) -> Option<&str> {
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

fn vec_to_32(bytes: &[u8]) -> Result<[u8; 32]> {
    bytes.try_into().map_err(|_| Error::InvalidPublicKey)
}

fn vec_to_salt(bytes: &[u8]) -> Result<[u8; SALT_LEN]> {
    bytes.try_into().map_err(|_| Error::InvalidPublicKey)
}

fn is_weak_x25519_public_key(public_key: &[u8; 32]) -> bool {
    x25519_dalek::x25519([1u8; 32], *public_key) == [0u8; 32]
}

fn push_len_prefixed(out: &mut Vec<u8>, bytes: &[u8]) -> Result<()> {
    let len = u16::try_from(bytes.len()).map_err(|_| Error::BundleFieldTooLarge)?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

fn push_party_map(out: &mut Vec<u8>, map: &BTreeMap<String, [u8; 32]>) -> Result<()> {
    let n = u16::try_from(map.len()).map_err(|_| Error::BundleFieldTooLarge)?;
    out.extend_from_slice(&n.to_be_bytes());
    for (label, pk) in map {
        push_len_prefixed(out, label.as_bytes())?;
        out.extend_from_slice(pk);
    }
    Ok(())
}

fn push_member_map(out: &mut Vec<u8>, map: &BTreeMap<String, MemberKeys>) -> Result<()> {
    let n = u16::try_from(map.len()).map_err(|_| Error::BundleFieldTooLarge)?;
    out.extend_from_slice(&n.to_be_bytes());
    for (label, keys) in map {
        push_len_prefixed(out, label.as_bytes())?;
        out.extend_from_slice(&keys.encryption);
        out.extend_from_slice(&keys.signing);
    }
    Ok(())
}

fn take_u8(data: &mut &[u8]) -> Result<u8> {
    let (b, rest) = data.split_first().ok_or(Error::InvalidBridgePackage)?;
    *data = rest;
    Ok(*b)
}

fn take_n<'a>(data: &mut &'a [u8], n: usize) -> Result<&'a [u8]> {
    if data.len() < n {
        return Err(Error::InvalidBridgePackage);
    }
    let (head, tail) = data.split_at(n);
    *data = tail;
    Ok(head)
}

fn take_array<const N: usize>(data: &mut &[u8]) -> Result<[u8; N]> {
    take_n(data, N)?
        .try_into()
        .map_err(|_| Error::InvalidBridgePackage)
}

fn take_len_prefixed<'a>(data: &mut &'a [u8]) -> Result<&'a [u8]> {
    let len = u16::from_be_bytes(take_array(data)?) as usize;
    take_n(data, len)
}

fn take_party_map(data: &mut &[u8]) -> Result<BTreeMap<String, [u8; 32]>> {
    let n = u16::from_be_bytes(take_array(data)?) as usize;
    let mut map = BTreeMap::new();
    for _ in 0..n {
        let label = utf8(take_len_prefixed(data)?)?;
        let pk = take_array::<32>(data)?;
        map.insert(label, pk);
    }
    Ok(map)
}

fn take_member_map(data: &mut &[u8]) -> Result<BTreeMap<String, MemberKeys>> {
    let n = u16::from_be_bytes(take_array(data)?) as usize;
    let mut map = BTreeMap::new();
    for _ in 0..n {
        let label = utf8(take_len_prefixed(data)?)?;
        let encryption = take_array::<32>(data)?;
        let signing = take_array::<32>(data)?;
        VerifyingKey::from_bytes(&signing).map_err(|_| Error::InvalidBridgePackage)?;
        map.insert(
            label,
            MemberKeys {
                encryption,
                signing,
            },
        );
    }
    Ok(map)
}

fn utf8(bytes: &[u8]) -> Result<String> {
    std::str::from_utf8(bytes)
        .map(|s| s.to_string())
        .map_err(|_| Error::InvalidBridgePackage)
}

#[cfg(test)]
#[path = "private_bridge/tests.rs"]
mod tests;
