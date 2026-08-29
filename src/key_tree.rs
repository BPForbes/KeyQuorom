//! Recursive key splitting: a secret is organized as a tree of nodes, each
//! either a LEAF (a Shamir share sealed to one registered encryption
//! hardware key) or a SPLIT (its own threshold, dividing its value among
//! its children, recursively). A flat "M-of-N hardware keys" quorum is
//! just a one-level tree — a single SPLIT root with N LEAF children.
//!
//! Turning a LEAF's `wrapped_share` back into raw share bytes needs a
//! hardware key's private key, which this project has no custody story
//! for yet (see README's Roadmap) — `reconstruct` below takes already
//! -unwrapped raw shares as opaque bytes; obtaining them is the caller's
//! responsibility.

use crate::error::{Error, Result};
use crate::keys;
use crate::pss;
use blahaj::{Share, Sharks};
use rusqlite::{params, Connection, OptionalExtension, Row};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged, deny_unknown_fields)]
pub enum NodeSpec {
    Leaf {
        label: String,
        hardware_key_id: i64,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        allowed_bridges: Vec<String>,
    },
    Split {
        label: String,
        threshold: u8,
        children: Vec<NodeSpec>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        allowed_bridges: Vec<String>,
    },
}

impl NodeSpec {
    fn label(&self) -> &str {
        match self {
            Self::Leaf { label, .. } | Self::Split { label, .. } => label,
        }
    }

    fn allowed_bridges(&self) -> &[String] {
        match self {
            Self::Leaf {
                allowed_bridges, ..
            }
            | Self::Split {
                allowed_bridges, ..
            } => allowed_bridges,
        }
    }

    /// One-level split used by `split --leaf`. Nested trees still go
    /// through a JSON snapshot (`--tree-spec` / `tree --output`).
    pub fn flat_split(root: impl Into<String>, threshold: u8, leaves: Vec<(String, i64)>) -> Self {
        Self::Split {
            label: root.into(),
            threshold,
            allowed_bridges: Vec::new(),
            children: leaves
                .into_iter()
                .map(|(label, hardware_key_id)| Self::Leaf {
                    label,
                    hardware_key_id,
                    allowed_bridges: Vec::new(),
                })
                .collect(),
        }
    }
}

/// One node in the in-memory arena loaded from SQLite. Share payloads stay
/// sealed in `key_nodes.wrapped_share`; this struct is topology and policy.
pub struct KeyNode {
    pub db_id: i64,
    pub id: String,
    pub parent_idx: Option<usize>,
    pub children_indices: Vec<usize>,
    pub threshold: Option<usize>,
    pub is_active: bool,
    pub hardware_key_id: Option<i64>,
    pub allowed_bridges: HashSet<String>,
}

pub struct KeyQuorumTree {
    pub nodes: Vec<KeyNode>,
    pub root_index: usize,
    pub id_to_index: HashMap<String, usize>,
    db_id_to_index: HashMap<i64, usize>,
}

pub struct TreeNodeSummary {
    pub id: i64,
    pub label: String,
    pub threshold: Option<i64>,
    pub hardware_key_id: Option<i64>,
    pub hardware_key_label: Option<String>,
    pub is_active: bool,
    pub allowed_bridges: Vec<String>,
    pub children: Vec<TreeNodeSummary>,
}

pub struct EstablishedBridge {
    pub from: String,
    pub to: String,
}

pub struct BridgeListing {
    pub allowed: Vec<(String, String)>,
    pub established: Vec<EstablishedBridge>,
}

pub struct TreeSummary {
    pub key_id: i64,
    pub label: String,
    pub root: TreeNodeSummary,
}

pub struct TreeListing {
    pub key_id: i64,
    pub label: String,
}

pub struct HardwareLeafRef {
    pub key_id: i64,
    pub node_id: i64,
    pub label: String,
}

/// Every `Split`'s threshold must be in `1..=children.len()`, every `Leaf`
/// must reference an active encryption-purpose hardware key, labels must be
/// unique within the tree, `allowed_bridges` must name other nodes in the
/// same spec, and the tree must contain at least one leaf overall.
pub fn validate(conn: &Connection, spec: &NodeSpec) -> Result<()> {
    let mut leaf_count = 0usize;
    validate_node(conn, spec, &mut leaf_count)?;
    if leaf_count == 0 {
        return Err(Error::InvalidQuorumThreshold);
    }
    let mut labels = HashSet::new();
    collect_labels(spec, &mut labels)?;
    validate_bridges(spec, &labels)?;
    Ok(())
}

fn collect_labels(spec: &NodeSpec, seen: &mut HashSet<String>) -> Result<()> {
    if spec.label().is_empty() || !seen.insert(spec.label().to_string()) {
        return Err(Error::DuplicateNodeLabel);
    }
    if let NodeSpec::Split { children, .. } = spec {
        for child in children {
            collect_labels(child, seen)?;
        }
    }
    Ok(())
}

fn validate_bridges(spec: &NodeSpec, labels: &HashSet<String>) -> Result<()> {
    for peer in spec.allowed_bridges() {
        if peer == spec.label() || !labels.contains(peer) {
            return Err(Error::InvalidBridge);
        }
    }
    if let NodeSpec::Split { children, .. } = spec {
        for child in children {
            validate_bridges(child, labels)?;
        }
    }
    Ok(())
}

fn validate_node(conn: &Connection, spec: &NodeSpec, leaf_count: &mut usize) -> Result<()> {
    match spec {
        NodeSpec::Leaf {
            hardware_key_id, ..
        } => {
            keys::get_active_encryption_key(conn, *hardware_key_id)?;
            *leaf_count += 1;
            Ok(())
        }
        NodeSpec::Split {
            threshold,
            children,
            ..
        } => {
            // Sharks/blahaj operate over GF(256): a Split with more than
            // 255 children would exhaust the available non-zero
            // x-coordinates, which downstream would silently produce
            // fewer shares than children (see the shares.len() check in
            // split_node) rather than erroring here where the problem is
            // obvious.
            if children.is_empty()
                || *threshold == 0
                || (*threshold as usize) > children.len()
                || children.len() > 255
            {
                return Err(Error::InvalidQuorumThreshold);
            }
            for child in children {
                validate_node(conn, child, leaf_count)?;
            }
            Ok(())
        }
    }
}

/// Creates a `keys` row and the whole `key_nodes` tree in one transaction:
/// recursively Shamir-splits `secret` at each `Split` node, and for each
/// child either seals-and-inserts a leaf or recurses with that child's
/// own share as the next level's secret. Rolls back entirely on any
/// failure — a half-built tree would be silently unrecoverable, not just
/// incomplete.
pub fn split(conn: &mut Connection, label: &str, secret: &[u8], spec: &NodeSpec) -> Result<i64> {
    let tx = conn.transaction()?;
    let key_id = build_tree(&tx, label, secret, spec)?;
    tx.commit()?;
    Ok(key_id)
}

/// Builds a key's tree using the given connection, which may already be
/// inside a transaction the caller manages (e.g. `quorum::lock_file`
/// combining this with its own `files` row insert into one atomic write).
/// Does not open or commit any transaction of its own.
pub(crate) fn build_tree(
    conn: &Connection,
    label: &str,
    secret: &[u8],
    spec: &NodeSpec,
) -> Result<i64> {
    validate(conn, spec)?;
    conn.execute("INSERT INTO keys (label) VALUES (?1)", params![label])?;
    let key_id = conn.last_insert_rowid();
    split_node(conn, key_id, None, secret, spec)?;
    Ok(key_id)
}

fn split_node(
    conn: &Connection,
    key_id: i64,
    parent_id: Option<i64>,
    secret: &[u8],
    spec: &NodeSpec,
) -> Result<()> {
    match spec {
        NodeSpec::Leaf {
            label,
            hardware_key_id,
            ..
        } => {
            let hardware_key = keys::get_active_encryption_key(conn, *hardware_key_id)?;
            let wrapped_share = seal_share(&hardware_key, secret)?;
            conn.execute(
                "INSERT INTO key_nodes (key_id, parent_id, label, hardware_key_id, wrapped_share)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![key_id, parent_id, label, hardware_key_id, wrapped_share],
            )?;
            let node_id = conn.last_insert_rowid();
            insert_allowed_bridges(conn, node_id, spec.allowed_bridges())?;
            Ok(())
        }
        NodeSpec::Split {
            label,
            threshold,
            children,
            ..
        } => {
            conn.execute(
                "INSERT INTO key_nodes (key_id, parent_id, label, threshold)
                 VALUES (?1, ?2, ?3, ?4)",
                params![key_id, parent_id, label, *threshold as i64],
            )?;
            let node_id = conn.last_insert_rowid();
            insert_allowed_bridges(conn, node_id, spec.allowed_bridges())?;

            let sharks = Sharks(*threshold);
            let shares: Vec<Share> = sharks
                .dealer_rng(secret, &mut rand::rngs::OsRng)
                .take(children.len())
                .collect();

            // zip() would otherwise silently stop at the shorter side,
            // dropping trailing children without any error if the dealer
            // ever produced fewer shares than requested.
            if shares.len() != children.len() {
                return Err(Error::InvalidQuorumThreshold);
            }

            for (child_spec, share) in children.iter().zip(shares.iter()) {
                let raw_share: Vec<u8> = Vec::from(share);
                split_node(conn, key_id, Some(node_id), &raw_share, child_spec)?;
            }
            Ok(())
        }
    }
}

fn seal_share(hardware_key: &keys::HardwareKey, share: &[u8]) -> Result<Vec<u8>> {
    let public_key_bytes: [u8; 32] = hardware_key.public_key[..]
        .try_into()
        .map_err(|_| Error::InvalidPublicKey)?;
    let public_key = crypto_box::PublicKey::from_bytes(public_key_bytes);
    Ok(public_key
        .seal(&mut rand::rngs::OsRng, share)
        .expect("crypto_box sealing should not fail for an in-memory share"))
}

fn insert_allowed_bridges(conn: &Connection, node_id: i64, peers: &[String]) -> Result<()> {
    for peer in peers {
        conn.execute(
            "INSERT INTO key_node_bridges (node_id, peer_label) VALUES (?1, ?2)",
            params![node_id, peer],
        )?;
    }
    Ok(())
}

/// `raw_shares` maps a leaf `key_nodes.id` to its already-unwrapped raw
/// share bytes (obtaining them is the deferred unwrap step — see the
/// module doc comment). Walks the loaded arena: a leaf resolves iff its
/// id is present in `raw_shares`; a split node resolves once at least
/// `threshold` of its *active* children resolve (recursively), via
/// `Sharks::recover`. Returns `QuorumNotMet` if the root can't be
/// resolved.
pub fn reconstruct(
    conn: &Connection,
    key_id: i64,
    raw_shares: &HashMap<i64, Vec<u8>>,
) -> Result<Vec<u8>> {
    let tree = KeyQuorumTree::load(conn, key_id)?;
    tree.reconstruct(raw_shares)
}

/// Reconstruct only the subtree rooted at `lca_idx` (e.g. a department
/// node), then walk parent shares upward until the key root.
pub fn reconstruct_from_lca(
    conn: &Connection,
    key_id: i64,
    lca_idx: usize,
    raw_shares: &HashMap<i64, Vec<u8>>,
) -> Result<Vec<u8>> {
    let tree = KeyQuorumTree::load(conn, key_id)?;
    tree.reconstruct_up_to_root(lca_idx, raw_shares)
}

fn root_node_id(conn: &Connection, key_id: i64) -> Result<i64> {
    let root_id = conn.query_row(
        "SELECT id FROM key_nodes WHERE key_id = ?1 AND parent_id IS NULL",
        params![key_id],
        |row| row.get(0),
    )?;
    Ok(root_id)
}

impl KeyQuorumTree {
    pub fn load(conn: &Connection, key_id: i64) -> Result<Self> {
        let mut stmt = conn.prepare(
            "SELECT id, parent_id, label, threshold, hardware_key_id, is_active
             FROM key_nodes WHERE key_id = ?1 ORDER BY id",
        )?;
        type NodeRow = (i64, Option<i64>, String, Option<i64>, Option<i64>, i64);
        let rows: Vec<NodeRow> = stmt
            .query_map(params![key_id], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        drop(stmt);

        if rows.is_empty() {
            return Err(Error::NodeNotFound);
        }

        let mut db_id_to_index = HashMap::with_capacity(rows.len());
        let mut id_to_index = HashMap::with_capacity(rows.len());
        let mut nodes = Vec::with_capacity(rows.len());

        for (i, (db_id, _, label, threshold, hardware_key_id, is_active)) in rows.iter().enumerate()
        {
            if id_to_index.insert(label.clone(), i).is_some() {
                return Err(Error::DuplicateNodeLabel);
            }
            db_id_to_index.insert(*db_id, i);
            nodes.push(KeyNode {
                db_id: *db_id,
                id: label.clone(),
                parent_idx: None,
                children_indices: Vec::new(),
                threshold: threshold.map(|t| t as usize),
                is_active: *is_active != 0,
                hardware_key_id: *hardware_key_id,
                allowed_bridges: HashSet::new(),
            });
        }

        for (i, (db_id, parent_id, _, _, _, _)) in rows.iter().enumerate() {
            if let Some(parent_id) = parent_id {
                let parent_idx = *db_id_to_index.get(parent_id).ok_or(Error::NodeNotFound)?;
                nodes[i].parent_idx = Some(parent_idx);
                nodes[parent_idx].children_indices.push(i);
            }
            let _ = db_id;
        }

        let mut bridge_stmt = conn.prepare(
            "SELECT n.id, b.peer_label
             FROM key_node_bridges b
             JOIN key_nodes n ON n.id = b.node_id
             WHERE n.key_id = ?1",
        )?;
        let bridges: Vec<(i64, String)> = bridge_stmt
            .query_map(params![key_id], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        drop(bridge_stmt);

        for (db_id, peer) in bridges {
            let idx = *db_id_to_index.get(&db_id).ok_or(Error::NodeNotFound)?;
            nodes[idx].allowed_bridges.insert(peer);
        }

        let root_index = nodes
            .iter()
            .position(|n| n.parent_idx.is_none())
            .ok_or(Error::NodeNotFound)?;

        Ok(Self {
            nodes,
            root_index,
            id_to_index,
            db_id_to_index,
        })
    }

    pub fn index_by_label(&self, label: &str) -> Result<usize> {
        self.id_to_index
            .get(label)
            .copied()
            .ok_or(Error::NodeNotFound)
    }

    pub fn index_by_db_id(&self, db_id: i64) -> Result<usize> {
        self.db_id_to_index
            .get(&db_id)
            .copied()
            .ok_or(Error::NodeNotFound)
    }

    pub fn find_lowest_common_ancestor(&self, index_a: usize, index_b: usize) -> Result<usize> {
        if index_a >= self.nodes.len() || index_b >= self.nodes.len() {
            return Err(Error::NodeNotFound);
        }

        let mut path_a = Vec::new();
        let mut curr = Some(index_a);
        while let Some(idx) = curr {
            path_a.push(idx);
            curr = self.nodes[idx].parent_idx;
        }

        let mut path_b = Vec::new();
        let mut curr = Some(index_b);
        while let Some(idx) = curr {
            path_b.push(idx);
            curr = self.nodes[idx].parent_idx;
        }

        let mut lca_idx = self.root_index;
        for (node_a, node_b) in path_a.iter().rev().zip(path_b.iter().rev()) {
            if node_a == node_b {
                lca_idx = *node_a;
            } else {
                break;
            }
        }
        Ok(lca_idx)
    }

    pub fn find_lowest_common_ancestor_of(&self, indices: &[usize]) -> Result<usize> {
        let mut iter = indices.iter().copied();
        let first = iter.next().ok_or(Error::NodeNotFound)?;
        iter.try_fold(first, |acc, idx| self.find_lowest_common_ancestor(acc, idx))
    }

    pub fn reconstruct(&self, raw_shares: &HashMap<i64, Vec<u8>>) -> Result<Vec<u8>> {
        self.reconstruct_node(self.root_index, raw_shares)
    }

    pub fn reconstruct_from(
        &self,
        idx: usize,
        raw_shares: &HashMap<i64, Vec<u8>>,
    ) -> Result<Vec<u8>> {
        self.reconstruct_node(idx, raw_shares)
    }

    pub fn reconstruct_up_to_root(
        &self,
        from_idx: usize,
        raw_shares: &HashMap<i64, Vec<u8>>,
    ) -> Result<Vec<u8>> {
        let mut value = self.reconstruct_node(from_idx, raw_shares)?;
        let mut idx = from_idx;
        while let Some(parent_idx) = self.nodes[idx].parent_idx {
            let parent = &self.nodes[parent_idx];
            let threshold = parent.threshold.ok_or(Error::QuorumNotMet)?;
            let mut resolved = Vec::new();
            if let Ok(share) = Share::try_from(value.as_slice()) {
                resolved.push(share);
            }
            for &sib in &parent.children_indices {
                if resolved.len() >= threshold {
                    break;
                }
                if sib == idx || !self.nodes[sib].is_active {
                    continue;
                }
                if let Ok(sibling_value) = self.reconstruct_node(sib, raw_shares) {
                    if let Ok(share) = Share::try_from(sibling_value.as_slice()) {
                        resolved.push(share);
                    }
                }
            }
            if resolved.len() < threshold {
                return Err(Error::QuorumNotMet);
            }
            value = Sharks(threshold as u8)
                .recover(resolved.iter())
                .map_err(|_| Error::QuorumNotMet)?;
            idx = parent_idx;
        }
        Ok(value)
    }

    fn reconstruct_node(&self, idx: usize, raw_shares: &HashMap<i64, Vec<u8>>) -> Result<Vec<u8>> {
        let node = self.nodes.get(idx).ok_or(Error::NodeNotFound)?;
        if !node.is_active {
            return Err(Error::QuorumNotMet);
        }
        if node.hardware_key_id.is_some() {
            return raw_shares
                .get(&node.db_id)
                .cloned()
                .ok_or(Error::QuorumNotMet);
        }

        let threshold = node.threshold.ok_or(Error::QuorumNotMet)?;
        let mut resolved: Vec<Share> = Vec::new();
        for &child_idx in &node.children_indices {
            if resolved.len() >= threshold {
                break;
            }
            if !self.nodes[child_idx].is_active {
                continue;
            }
            if let Ok(value) = self.reconstruct_node(child_idx, raw_shares) {
                // A malformed share is treated the same as an unresolved
                // child rather than aborting — other valid children may
                // still meet this node's threshold.
                if let Ok(share) = Share::try_from(value.as_slice()) {
                    resolved.push(share);
                }
            }
        }

        if resolved.len() < threshold {
            return Err(Error::QuorumNotMet);
        }

        Sharks(threshold as u8)
            .recover(resolved.iter())
            .map_err(|_| Error::QuorumNotMet)
    }
}

fn node_id_for_label(conn: &Connection, key_id: i64, label: &str) -> Result<i64> {
    conn.query_row(
        "SELECT id FROM key_nodes WHERE key_id = ?1 AND label = ?2",
        params![key_id, label],
        |row| row.get(0),
    )
    .optional()?
    .ok_or(Error::NodeNotFound)
}

fn ordered_pair(a: i64, b: i64) -> Result<(i64, i64)> {
    if a == b {
        return Err(Error::InvalidBridge);
    }
    if a < b {
        Ok((a, b))
    } else {
        Ok((b, a))
    }
}

/// Grant `--node` permission to form a cross-branch pairing with `--peer`.
pub fn allow_bridge(
    conn: &Connection,
    key_id: i64,
    node_label: &str,
    peer_label: &str,
) -> Result<()> {
    if node_label == peer_label {
        return Err(Error::InvalidBridge);
    }
    let node_id = node_id_for_label(conn, key_id, node_label)?;
    let _peer_id = node_id_for_label(conn, key_id, peer_label)?;
    conn.execute(
        "INSERT OR IGNORE INTO key_node_bridges (node_id, peer_label) VALUES (?1, ?2)",
        params![node_id, peer_label],
    )?;
    Ok(())
}

/// Revoke that permission and drop any established pairing between the two.
pub fn deny_bridge(
    conn: &Connection,
    key_id: i64,
    node_label: &str,
    peer_label: &str,
) -> Result<()> {
    let node_id = node_id_for_label(conn, key_id, node_label)?;
    let peer_id = node_id_for_label(conn, key_id, peer_label)?;
    conn.execute(
        "DELETE FROM key_node_bridges
         WHERE (node_id = ?1 AND peer_label = ?2)
            OR (node_id = ?3 AND peer_label = ?4)",
        params![node_id, peer_label, peer_id, node_label],
    )?;
    if let Ok((lo, hi)) = ordered_pair(node_id, peer_id) {
        conn.execute(
            "DELETE FROM key_node_links WHERE node_a_id = ?1 AND node_b_id = ?2",
            params![lo, hi],
        )?;
    }
    Ok(())
}

/// Establish an undirected pairing if either node's whitelist allows it.
pub fn add_bridge(conn: &Connection, key_id: i64, from_label: &str, to_label: &str) -> Result<()> {
    let tree = KeyQuorumTree::load(conn, key_id)?;
    let idx_a = tree.index_by_label(from_label)?;
    let idx_b = tree.index_by_label(to_label)?;
    if idx_a == idx_b {
        return Err(Error::InvalidBridge);
    }

    let authorized = tree.nodes[idx_a].allowed_bridges.contains(to_label)
        || tree.nodes[idx_b].allowed_bridges.contains(from_label);
    if !authorized {
        return Err(Error::BridgeNotWhitelisted);
    }

    let (lo, hi) = ordered_pair(tree.nodes[idx_a].db_id, tree.nodes[idx_b].db_id)?;
    conn.execute(
        "INSERT OR IGNORE INTO key_node_links (node_a_id, node_b_id) VALUES (?1, ?2)",
        params![lo, hi],
    )?;
    Ok(())
}

/// Tear down an established pairing; the whitelist is left intact.
pub fn remove_bridge(
    conn: &Connection,
    key_id: i64,
    from_label: &str,
    to_label: &str,
) -> Result<()> {
    let a = node_id_for_label(conn, key_id, from_label)?;
    let b = node_id_for_label(conn, key_id, to_label)?;
    let (lo, hi) = ordered_pair(a, b)?;
    let deleted = conn.execute(
        "DELETE FROM key_node_links WHERE node_a_id = ?1 AND node_b_id = ?2",
        params![lo, hi],
    )?;
    if deleted == 0 {
        return Err(Error::BridgeNotFound);
    }
    Ok(())
}

pub fn list_bridges(conn: &Connection, key_id: i64) -> Result<BridgeListing> {
    let mut allowed_stmt = conn.prepare(
        "SELECT n.label, b.peer_label
         FROM key_node_bridges b
         JOIN key_nodes n ON n.id = b.node_id
         WHERE n.key_id = ?1
         ORDER BY n.label, b.peer_label",
    )?;
    let allowed = allowed_stmt
        .query_map(params![key_id], |row| Ok((row.get(0)?, row.get(1)?)))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    drop(allowed_stmt);

    let mut link_stmt = conn.prepare(
        "SELECT a.label, b.label
         FROM key_node_links l
         JOIN key_nodes a ON a.id = l.node_a_id
         JOIN key_nodes b ON b.id = l.node_b_id
         WHERE a.key_id = ?1 AND b.key_id = ?1
         ORDER BY a.label, b.label",
    )?;
    let established = link_stmt
        .query_map(params![key_id], |row| {
            Ok(EstablishedBridge {
                from: row.get(0)?,
                to: row.get(1)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;

    Ok(BridgeListing {
        allowed,
        established,
    })
}

/// Whitelist both directions and establish the pairing. Node ids stay
/// put across later secret refreshes, so this bind survives PSS / add /
/// rebind as long as those operations UPDATE the same rows.
pub fn bind_pair(conn: &Connection, key_id: i64, a_label: &str, b_label: &str) -> Result<()> {
    allow_bridge(conn, key_id, a_label, b_label)?;
    allow_bridge(conn, key_id, b_label, a_label)?;
    add_bridge(conn, key_id, a_label, b_label)?;
    Ok(())
}

/// Bind `leaf_label` to every other active leaf sibling of its parent.
pub fn bind_leaf_to_active_siblings(
    conn: &Connection,
    key_id: i64,
    leaf_label: &str,
) -> Result<()> {
    let tree = KeyQuorumTree::load(conn, key_id)?;
    let idx = tree.index_by_label(leaf_label)?;
    let parent_idx = tree.nodes[idx].parent_idx.ok_or(Error::InvalidBridge)?;
    let siblings: Vec<String> = tree.nodes[parent_idx]
        .children_indices
        .iter()
        .copied()
        .filter(|&c| c != idx && tree.nodes[c].is_active && tree.nodes[c].hardware_key_id.is_some())
        .map(|c| tree.nodes[c].id.clone())
        .collect();
    for peer in siblings {
        bind_pair(conn, key_id, leaf_label, &peer)?;
    }
    Ok(())
}

/// Establish a pairing between every pair of active leaf siblings under
/// each split. Used after `split --leaf` so the live spec records
/// those binds without a JSON file.
pub fn bind_all_sibling_leaf_pairs(conn: &Connection, key_id: i64) -> Result<()> {
    let tree = KeyQuorumTree::load(conn, key_id)?;
    let mut pairs = Vec::new();
    for node in &tree.nodes {
        if node.threshold.is_none() {
            continue;
        }
        let leaves: Vec<String> = node
            .children_indices
            .iter()
            .copied()
            .filter(|&c| tree.nodes[c].is_active && tree.nodes[c].hardware_key_id.is_some())
            .map(|c| tree.nodes[c].id.clone())
            .collect();
        for i in 0..leaves.len() {
            for j in (i + 1)..leaves.len() {
                pairs.push((leaves[i].clone(), leaves[j].clone()));
            }
        }
    }
    for (a, b) in pairs {
        bind_pair(conn, key_id, &a, &b)?;
    }
    Ok(())
}

/// Reseal an active leaf to a new hardware key. The share bytes and the
/// `key_nodes.id` stay the same, so existing pairings survive.
pub fn rebind_leaf(
    conn: &Connection,
    key_id: i64,
    node_label: &str,
    new_hardware_id: i64,
    old_secret: &[u8],
) -> Result<()> {
    let tree = KeyQuorumTree::load(conn, key_id)?;
    let idx = tree.index_by_label(node_label)?;
    let node = &tree.nodes[idx];
    if !node.is_active || node.hardware_key_id.is_none() {
        return Err(Error::NodeNotFound);
    }
    let share = unwrap_leaf_share(conn, node.db_id, old_secret)?;
    let new_hw = keys::get_active_encryption_key(conn, new_hardware_id)?;
    let wrapped = seal_share(&new_hw, &share)?;
    let updated = conn.execute(
        "UPDATE key_nodes SET hardware_key_id = ?1, wrapped_share = ?2
         WHERE id = ?3 AND key_id = ?4",
        params![new_hardware_id, wrapped, node.db_id, key_id],
    )?;
    if updated != 1 {
        return Err(Error::NodeNotFound);
    }
    Ok(())
}

/// Recover a parent split, dealer `n+1` shares at the same threshold,
/// reseal existing active leaf children in place, and insert the new
/// leaf. Survivor node ids are unchanged so their binds survive.
/// A complete old quorum still reconstructs the same secret; mixed
/// old-and-new sibling shares do not.
pub fn add_leaf_and_reshare(
    conn: &mut Connection,
    key_id: i64,
    parent_label: &str,
    new_label: &str,
    new_hardware_id: i64,
    presented: &HashMap<i64, Vec<u8>>,
) -> Result<i64> {
    if new_label.is_empty() {
        return Err(Error::DuplicateNodeLabel);
    }
    let tx = conn.transaction()?;
    let tree = KeyQuorumTree::load(&tx, key_id)?;
    if tree.id_to_index.contains_key(new_label) {
        return Err(Error::DuplicateNodeLabel);
    }
    let parent_idx = tree.index_by_label(parent_label)?;
    let parent = &tree.nodes[parent_idx];
    let threshold = parent.threshold.ok_or(Error::CannotAddLeaf)?;

    let mut active_leaves = Vec::new();
    for &child in &parent.children_indices {
        let node = &tree.nodes[child];
        if !node.is_active {
            continue;
        }
        if node.hardware_key_id.is_none() {
            return Err(Error::CannotAddLeaf);
        }
        active_leaves.push(child);
    }

    let n = active_leaves.len() + 1;
    if n > 255 || threshold > n {
        return Err(Error::CannotAddLeaf);
    }

    let mut raw_for_recover = Vec::new();
    for &idx in &active_leaves {
        if let Some(raw) = presented.get(&tree.nodes[idx].db_id) {
            raw_for_recover.push(raw.clone());
        }
    }
    if raw_for_recover.len() < threshold {
        return Err(Error::QuorumNotMet);
    }
    require_recoverable_share_coordinates(&raw_for_recover)?;

    let parent_secret = recover_secret(threshold as u8, &raw_for_recover)?;
    keys::get_active_encryption_key(&tx, new_hardware_id)?;

    let new_shares: Vec<Share> = Sharks(threshold as u8)
        .dealer_rng(&parent_secret, &mut rand::rngs::OsRng)
        .take(n)
        .collect();
    if new_shares.len() != n {
        return Err(Error::InvalidQuorumThreshold);
    }

    for (idx, share) in active_leaves.iter().zip(new_shares.iter()) {
        let node = &tree.nodes[*idx];
        let hw_id = node.hardware_key_id.ok_or(Error::CannotAddLeaf)?;
        let hardware_key = keys::get_active_encryption_key(&tx, hw_id)?;
        let raw: Vec<u8> = Vec::from(share);
        let wrapped = seal_share(&hardware_key, &raw)?;
        tx.execute(
            "UPDATE key_nodes SET wrapped_share = ?1 WHERE id = ?2",
            params![wrapped, node.db_id],
        )?;
    }

    let new_share: Vec<u8> = Vec::from(&new_shares[n - 1]);
    let new_hw = keys::get_active_encryption_key(&tx, new_hardware_id)?;
    let wrapped = seal_share(&new_hw, &new_share)?;
    tx.execute(
        "INSERT INTO key_nodes (key_id, parent_id, label, hardware_key_id, wrapped_share)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![key_id, parent.db_id, new_label, new_hardware_id, wrapped],
    )?;
    let new_id = tx.last_insert_rowid();
    tx.commit()?;
    Ok(new_id)
}

fn require_recoverable_share_coordinates(raw_shares: &[Vec<u8>]) -> Result<()> {
    let mut xs = Vec::with_capacity(raw_shares.len());
    for raw in raw_shares {
        if raw.is_empty() {
            return Err(Error::ShareShapeMismatch);
        }
        xs.push(raw[0]);
    }
    pss::require_distinct_nonzero_xs(&xs)
}

fn recover_secret(threshold: u8, raw_shares: &[Vec<u8>]) -> Result<Vec<u8>> {
    require_recoverable_share_coordinates(raw_shares)?;
    let mut shares = Vec::with_capacity(raw_shares.len());
    for raw in raw_shares {
        let share = Share::try_from(raw.as_slice()).map_err(|_| Error::QuorumNotMet)?;
        shares.push(share);
    }
    Sharks(threshold)
        .recover(shares.iter())
        .map_err(|_| Error::QuorumNotMet)
}

/// Snapshot of the live tree: active nodes, current hardware bindings,
/// and whitelist entries. This is an export, not something callers edit
/// and feed back in as the source of truth.
pub fn export_spec(conn: &Connection, key_id: i64) -> Result<NodeSpec> {
    let tree = KeyQuorumTree::load(conn, key_id)?;
    Ok(export_node(&tree, tree.root_index))
}

fn export_node(tree: &KeyQuorumTree, idx: usize) -> NodeSpec {
    let node = &tree.nodes[idx];
    let mut allowed: Vec<String> = node.allowed_bridges.iter().cloned().collect();
    allowed.sort();
    if let Some(hardware_key_id) = node.hardware_key_id {
        NodeSpec::Leaf {
            label: node.id.clone(),
            hardware_key_id,
            allowed_bridges: allowed,
        }
    } else {
        let children = node
            .children_indices
            .iter()
            .copied()
            .filter(|&c| tree.nodes[c].is_active)
            .map(|c| export_node(tree, c))
            .collect();
        NodeSpec::Split {
            label: node.id.clone(),
            threshold: node.threshold.unwrap_or(1) as u8,
            children,
            allowed_bridges: allowed,
        }
    }
}

fn delete_node_bindings(conn: &rusqlite::Connection, key_id: i64, node_id: i64) -> Result<()> {
    let label: String = conn.query_row(
        "SELECT label FROM key_nodes WHERE id = ?1 AND key_id = ?2",
        params![node_id, key_id],
        |row| row.get(0),
    )?;
    conn.execute(
        "DELETE FROM key_node_links WHERE node_a_id = ?1 OR node_b_id = ?1",
        params![node_id],
    )?;
    conn.execute(
        "DELETE FROM key_node_bridges
         WHERE node_id = ?1
            OR (peer_label = ?2 AND node_id IN (
                    SELECT id FROM key_nodes WHERE key_id = ?3
                ))",
        params![node_id, label, key_id],
    )?;
    Ok(())
}

/// Evict an active leaf and PSS-refresh every remaining active leaf sibling
/// of its parent. Threshold is unchanged. All remaining siblings must be
/// leaves and must present their current raw shares.
pub fn evict_and_refresh(
    conn: &mut Connection,
    key_id: i64,
    evicted_node_id: i64,
    survivor_raw_shares: &HashMap<i64, Vec<u8>>,
) -> Result<()> {
    let tx = conn.transaction()?;
    let tree = KeyQuorumTree::load(&tx, key_id)?;
    let evicted_idx = tree.index_by_db_id(evicted_node_id)?;
    let evicted = &tree.nodes[evicted_idx];
    if !evicted.is_active || evicted.hardware_key_id.is_none() {
        return Err(Error::CannotEvict);
    }
    let parent_idx = evicted.parent_idx.ok_or(Error::CannotEvict)?;
    let parent = &tree.nodes[parent_idx];
    let threshold = parent.threshold.ok_or(Error::CannotEvict)?;
    // t = 1 makes the PSS blinding polynomial identically zero, so the
    // evicted share would still reconstruct the parent by itself.
    if threshold < 2 {
        return Err(Error::CannotEvict);
    }

    let mut survivor_idxs = Vec::new();
    for &child in &parent.children_indices {
        if child == evicted_idx {
            continue;
        }
        let sibling = &tree.nodes[child];
        if !sibling.is_active {
            continue;
        }
        if sibling.hardware_key_id.is_none() {
            return Err(Error::CannotEvict);
        }
        survivor_idxs.push(child);
    }

    if survivor_idxs.len() < threshold {
        return Err(Error::CannotEvict);
    }

    let mut shares = Vec::with_capacity(survivor_idxs.len());
    let mut share_meta = Vec::with_capacity(survivor_idxs.len());
    for &idx in &survivor_idxs {
        let node = &tree.nodes[idx];
        let raw = survivor_raw_shares
            .get(&node.db_id)
            .ok_or(Error::QuorumNotMet)?;
        let hardware_key_id = node.hardware_key_id.ok_or(Error::CannotEvict)?;
        let hardware_key = keys::get_active_encryption_key(&tx, hardware_key_id)?;
        shares.push(raw.clone());
        share_meta.push((node.db_id, hardware_key));
    }

    pss::refresh_among(&mut shares, threshold as u8)?;

    tx.execute(
        "UPDATE key_nodes SET is_active = 0 WHERE id = ?1",
        params![evicted_node_id],
    )?;
    delete_node_bindings(&tx, key_id, evicted_node_id)?;

    for ((db_id, hardware_key), new_share) in share_meta.iter().zip(shares.iter()) {
        let wrapped_share = seal_share(hardware_key, new_share)?;
        tx.execute(
            "UPDATE key_nodes SET wrapped_share = ?1 WHERE id = ?2",
            params![wrapped_share, db_id],
        )?;
    }

    tx.commit()?;
    Ok(())
}

/// Unseal one leaf's `wrapped_share` with that leaf's encryption secret.
pub fn unwrap_leaf_share(
    conn: &Connection,
    node_id: i64,
    secret_key_bytes: &[u8],
) -> Result<Vec<u8>> {
    let secret_bytes: [u8; 32] = secret_key_bytes
        .try_into()
        .map_err(|_| Error::InvalidPublicKey)?;
    let secret_key = crypto_box::SecretKey::from(secret_bytes);
    let expected_public = *secret_key.public_key().as_bytes();

    let (hardware_key_id, wrapped): (Option<i64>, Option<Vec<u8>>) = conn.query_row(
        "SELECT hardware_key_id, wrapped_share FROM key_nodes WHERE id = ?1",
        params![node_id],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let hardware_key_id = hardware_key_id.ok_or(Error::NodeNotFound)?;
    let wrapped = wrapped.ok_or(Error::NodeNotFound)?;
    let hardware_key = keys::get_key(conn, hardware_key_id)?;
    if hardware_key.public_key != expected_public {
        return Err(Error::IntegrityCheckFailed);
    }
    secret_key
        .unseal(&wrapped)
        .map_err(|_| Error::IntegrityCheckFailed)
}

/// Read-only tree summary — labels, thresholds, and which hardware key
/// backs each leaf — for `tree <id>` / audit review.
pub fn describe(conn: &Connection, key_id: i64) -> Result<TreeSummary> {
    let label: String = conn.query_row(
        "SELECT label FROM keys WHERE id = ?1",
        params![key_id],
        |row| row.get(0),
    )?;
    let root_id = root_node_id(conn, key_id)?;
    let root = describe_node(conn, root_id)?;
    Ok(TreeSummary {
        key_id,
        label,
        root,
    })
}

/// Every stored split tree (`keys` rows), newest last.
pub fn list_trees(conn: &Connection) -> Result<Vec<TreeListing>> {
    let mut stmt = conn.prepare("SELECT id, label FROM keys ORDER BY id")?;
    let trees = stmt
        .query_map([], |row| {
            Ok(TreeListing {
                key_id: row.get(0)?,
                label: row.get(1)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(trees)
}

/// Active leaves sealed to this hardware key, across every tree.
pub fn active_leaves_for_hardware(
    conn: &Connection,
    hardware_key_id: i64,
) -> Result<Vec<HardwareLeafRef>> {
    let mut stmt = conn.prepare(
        "SELECT key_id, id, label FROM key_nodes
         WHERE hardware_key_id = ?1 AND is_active = 1
         ORDER BY key_id, id",
    )?;
    let leaves = stmt
        .query_map(params![hardware_key_id], |row| {
            Ok(HardwareLeafRef {
                key_id: row.get(0)?,
                node_id: row.get(1)?,
                label: row.get(2)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(leaves)
}

/// Drop pairings and whitelist rows for every active leaf sealed to
/// this hardware key. Node rows stay; only the live spec's binds change.
pub fn drop_bindings_for_hardware(
    conn: &Connection,
    hardware_key_id: i64,
) -> Result<Vec<HardwareLeafRef>> {
    let leaves = active_leaves_for_hardware(conn, hardware_key_id)?;
    for leaf in &leaves {
        delete_node_bindings(conn, leaf.key_id, leaf.node_id)?;
    }
    Ok(leaves)
}

fn describe_node(conn: &Connection, node_id: i64) -> Result<TreeNodeSummary> {
    let (label, threshold, hardware_key_id, is_active) = describe_row(conn, node_id)?;

    let hardware_key_label = match hardware_key_id {
        Some(id) => Some(keys::get_key(conn, id)?.label),
        None => None,
    };

    let mut bridge_stmt = conn.prepare(
        "SELECT peer_label FROM key_node_bridges WHERE node_id = ?1 ORDER BY peer_label",
    )?;
    let allowed_bridges: Vec<String> = bridge_stmt
        .query_map(params![node_id], |row| row.get(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    drop(bridge_stmt);

    let mut stmt = conn.prepare("SELECT id FROM key_nodes WHERE parent_id = ?1 ORDER BY id")?;
    let child_ids: Vec<i64> = stmt
        .query_map(params![node_id], |row| row.get(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    drop(stmt);

    let mut children = Vec::with_capacity(child_ids.len());
    for child_id in child_ids {
        children.push(describe_node(conn, child_id)?);
    }

    Ok(TreeNodeSummary {
        id: node_id,
        label,
        threshold,
        hardware_key_id,
        hardware_key_label,
        is_active,
        allowed_bridges,
        children,
    })
}

fn describe_row(
    conn: &Connection,
    node_id: i64,
) -> Result<(String, Option<i64>, Option<i64>, bool)> {
    let row = conn.query_row(
        "SELECT label, threshold, hardware_key_id, is_active FROM key_nodes WHERE id = ?1",
        params![node_id],
        |row: &Row| {
            let is_active: i64 = row.get(3)?;
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, is_active != 0))
        },
    )?;
    Ok(row)
}

#[cfg(test)]
#[path = "key_tree/tests.rs"]
mod tests;
