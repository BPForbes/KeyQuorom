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
use serde::Deserialize;
use std::collections::{HashMap, HashSet};

#[derive(Debug, Deserialize)]
#[serde(untagged, deny_unknown_fields)]
pub enum NodeSpec {
    Leaf {
        label: String,
        hardware_key_id: i64,
        #[serde(default)]
        allowed_bridges: Vec<String>,
    },
    Split {
        label: String,
        threshold: u8,
        children: Vec<NodeSpec>,
        #[serde(default)]
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
            let public_key_bytes: [u8; 32] = hardware_key.public_key[..]
                .try_into()
                .map_err(|_| Error::InvalidPublicKey)?;
            let public_key = crypto_box::PublicKey::from_bytes(public_key_bytes);
            let wrapped_share = public_key
                .seal(&mut rand::rngs::OsRng, secret)
                .expect("crypto_box sealing should not fail for an in-memory share");
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

    for ((db_id, hardware_key), new_share) in share_meta.iter().zip(shares.iter()) {
        let public_key_bytes: [u8; 32] = hardware_key.public_key[..]
            .try_into()
            .map_err(|_| Error::InvalidPublicKey)?;
        let public_key = crypto_box::PublicKey::from_bytes(public_key_bytes);
        let wrapped_share = public_key
            .seal(&mut rand::rngs::OsRng, new_share)
            .expect("crypto_box sealing should not fail for an in-memory share");
        tx.execute(
            "UPDATE key_nodes SET wrapped_share = ?1 WHERE id = ?2",
            params![wrapped_share, db_id],
        )?;
    }

    tx.commit()?;
    Ok(())
}

/// Read-only tree summary — labels, thresholds, and which hardware key
/// backs each leaf — for `key tree <id>` / audit review.
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
mod tests {
    use super::*;
    use crate::db;
    use crate::keys::KeyType;

    fn register_encryption_key(conn: &Connection, label: &str) -> (i64, crypto_box::SecretKey) {
        let secret_key = crypto_box::SecretKey::generate(&mut rand::rngs::OsRng);
        let public_key = *secret_key.public_key().as_bytes();
        let id = keys::register_key(conn, label, KeyType::Encryption, &public_key)
            .expect("register_key should succeed");
        (id, secret_key)
    }

    fn unwrap_leaf_share(
        conn: &Connection,
        node_id: i64,
        secret_key: &crypto_box::SecretKey,
    ) -> Vec<u8> {
        let wrapped: Vec<u8> = conn
            .query_row(
                "SELECT wrapped_share FROM key_nodes WHERE id = ?1",
                params![node_id],
                |row| row.get(0),
            )
            .expect("leaf node should exist");
        secret_key
            .unseal(&wrapped)
            .expect("unseal should succeed with the matching secret key")
    }

    fn leaf_ids_by_label(conn: &Connection, key_id: i64) -> HashMap<String, i64> {
        let mut stmt = conn
            .prepare(
                "SELECT id, label FROM key_nodes WHERE key_id = ?1 AND hardware_key_id IS NOT NULL",
            )
            .unwrap();
        stmt.query_map(params![key_id], |row| {
            Ok((row.get::<_, String>(1)?, row.get::<_, i64>(0)?))
        })
        .unwrap()
        .collect::<rusqlite::Result<HashMap<_, _>>>()
        .unwrap()
    }

    #[test]
    fn flat_tree_round_trips_split_and_reconstruct() {
        let mut conn = db::open_in_memory().expect("schema should apply");
        let (id_a, sk_a) = register_encryption_key(&conn, "a");
        let (id_b, sk_b) = register_encryption_key(&conn, "b");
        let (id_c, _sk_c) = register_encryption_key(&conn, "c");

        let spec = NodeSpec::Split {
            label: "root".into(),
            threshold: 2,
            allowed_bridges: vec![],
            children: vec![
                NodeSpec::Leaf {
                    label: "a".into(),
                    hardware_key_id: id_a,
                    allowed_bridges: vec![],
                },
                NodeSpec::Leaf {
                    label: "b".into(),
                    hardware_key_id: id_b,
                    allowed_bridges: vec![],
                },
                NodeSpec::Leaf {
                    label: "c".into(),
                    hardware_key_id: id_c,
                    allowed_bridges: vec![],
                },
            ],
        };

        let secret = b"the quorum has been reached!!!!".to_vec();
        let key_id = split(&mut conn, "flat", &secret, &spec).expect("split should succeed");

        let leaves = leaf_ids_by_label(&conn, key_id);
        let raw_a = unwrap_leaf_share(&conn, leaves[&"a".to_string()], &sk_a);
        let raw_b = unwrap_leaf_share(&conn, leaves[&"b".to_string()], &sk_b);

        let mut shares = HashMap::new();
        shares.insert(leaves[&"a".to_string()], raw_a);
        shares.insert(leaves[&"b".to_string()], raw_b);

        let recovered = reconstruct(&conn, key_id, &shares).expect("reconstruct should succeed");
        assert_eq!(recovered, secret);
    }

    #[test]
    fn reconstruct_skips_a_malformed_share_instead_of_aborting() {
        let mut conn = db::open_in_memory().expect("schema should apply");
        let (id_a, _sk_a) = register_encryption_key(&conn, "a");
        let (id_b, sk_b) = register_encryption_key(&conn, "b");
        let (id_c, sk_c) = register_encryption_key(&conn, "c");

        let spec = NodeSpec::Split {
            label: "root".into(),
            threshold: 2,
            allowed_bridges: vec![],
            children: vec![
                NodeSpec::Leaf {
                    label: "a".into(),
                    hardware_key_id: id_a,
                    allowed_bridges: vec![],
                },
                NodeSpec::Leaf {
                    label: "b".into(),
                    hardware_key_id: id_b,
                    allowed_bridges: vec![],
                },
                NodeSpec::Leaf {
                    label: "c".into(),
                    hardware_key_id: id_c,
                    allowed_bridges: vec![],
                },
            ],
        };

        let secret = b"the quorum has been reached!!!!".to_vec();
        let key_id = split(&mut conn, "flat", &secret, &spec).expect("split should succeed");

        let leaves = leaf_ids_by_label(&conn, key_id);
        let raw_b = unwrap_leaf_share(&conn, leaves[&"b".to_string()], &sk_b);
        let raw_c = unwrap_leaf_share(&conn, leaves[&"c".to_string()], &sk_c);

        // A genuinely malformed "share" (not valid Share-encoded bytes)
        // for `a` — the first leaf tried, in id order, since children are
        // inserted in spec order — alongside two real, correctly-unwrapped
        // shares for b and c. Before the fix, hitting the malformed entry
        // while still under threshold aborted the *entire* reconstruction
        // via `?`, never even trying b or c.
        let mut shares = HashMap::new();
        shares.insert(leaves[&"a".to_string()], vec![0xFF]);
        shares.insert(leaves[&"b".to_string()], raw_b);
        shares.insert(leaves[&"c".to_string()], raw_c);

        let recovered = reconstruct(&conn, key_id, &shares)
            .expect("reconstruct should succeed despite one malformed share");
        assert_eq!(recovered, secret);
    }

    #[test]
    fn flat_tree_reconstruct_fails_with_too_few_shares() {
        let mut conn = db::open_in_memory().expect("schema should apply");
        let (id_a, sk_a) = register_encryption_key(&conn, "a");
        let (id_b, _sk_b) = register_encryption_key(&conn, "b");

        let spec = NodeSpec::Split {
            label: "root".into(),
            threshold: 2,
            allowed_bridges: vec![],
            children: vec![
                NodeSpec::Leaf {
                    label: "a".into(),
                    hardware_key_id: id_a,
                    allowed_bridges: vec![],
                },
                NodeSpec::Leaf {
                    label: "b".into(),
                    hardware_key_id: id_b,
                    allowed_bridges: vec![],
                },
            ],
        };

        let secret = b"top secret data key value here!".to_vec();
        let key_id = split(&mut conn, "flat", &secret, &spec).expect("split should succeed");

        let leaves = leaf_ids_by_label(&conn, key_id);
        let raw_a = unwrap_leaf_share(&conn, leaves[&"a".to_string()], &sk_a);
        let mut shares = HashMap::new();
        shares.insert(leaves[&"a".to_string()], raw_a);

        let result = reconstruct(&conn, key_id, &shares);
        assert!(matches!(result, Err(Error::QuorumNotMet)));
    }

    #[test]
    fn nested_tree_round_trips_across_branches() {
        // "CEO alone" OR a 2-of-2 department quorum, where one department
        // (cxo) is itself split 2-of-2.
        let mut conn = db::open_in_memory().expect("schema should apply");
        let (ceo_id, _ceo_sk) = register_encryption_key(&conn, "ceo");
        let (cfo_id, cfo_sk) = register_encryption_key(&conn, "cfo");
        let (coo_id, coo_sk) = register_encryption_key(&conn, "coo");
        let (it_id, it_sk) = register_encryption_key(&conn, "it");

        let spec = NodeSpec::Split {
            label: "root".into(),
            threshold: 1,
            allowed_bridges: vec![],
            children: vec![
                NodeSpec::Leaf {
                    label: "ceo".into(),
                    hardware_key_id: ceo_id,
                    allowed_bridges: vec![],
                },
                NodeSpec::Split {
                    label: "departments".into(),
                    threshold: 2,
                    allowed_bridges: vec![],
                    children: vec![
                        NodeSpec::Split {
                            label: "cxo".into(),
                            threshold: 2,
                            allowed_bridges: vec![],
                            children: vec![
                                NodeSpec::Leaf {
                                    label: "cfo".into(),
                                    hardware_key_id: cfo_id,
                                    allowed_bridges: vec![],
                                },
                                NodeSpec::Leaf {
                                    label: "coo".into(),
                                    hardware_key_id: coo_id,
                                    allowed_bridges: vec![],
                                },
                            ],
                        },
                        NodeSpec::Leaf {
                            label: "it".into(),
                            hardware_key_id: it_id,
                            allowed_bridges: vec![],
                        },
                    ],
                },
            ],
        };

        let secret = b"company master secret 32 bytes!".to_vec();
        let key_id = split(&mut conn, "nested", &secret, &spec).expect("split should succeed");
        let leaves = leaf_ids_by_label(&conn, key_id);

        let raw_cfo = unwrap_leaf_share(&conn, leaves[&"cfo".to_string()], &cfo_sk);
        let raw_coo = unwrap_leaf_share(&conn, leaves[&"coo".to_string()], &coo_sk);
        let raw_it = unwrap_leaf_share(&conn, leaves[&"it".to_string()], &it_sk);

        let mut shares = HashMap::new();
        shares.insert(leaves[&"cfo".to_string()], raw_cfo);
        shares.insert(leaves[&"coo".to_string()], raw_coo);
        shares.insert(leaves[&"it".to_string()], raw_it);

        let recovered = reconstruct(&conn, key_id, &shares)
            .expect("reconstruct should succeed via department branch");
        assert_eq!(recovered, secret);
    }

    #[test]
    fn nested_tree_fails_when_a_branch_is_short_even_if_others_are_oversupplied() {
        let mut conn = db::open_in_memory().expect("schema should apply");
        let (ceo_id, _ceo_sk) = register_encryption_key(&conn, "ceo");
        let (cfo_id, cfo_sk) = register_encryption_key(&conn, "cfo");
        let (coo_id, _coo_sk) = register_encryption_key(&conn, "coo");
        let (it_id, it_sk) = register_encryption_key(&conn, "it");

        let spec = NodeSpec::Split {
            label: "root".into(),
            threshold: 2, // needs 2 of {ceo, departments} — ceo alone is no longer enough
            allowed_bridges: vec![],
            children: vec![
                NodeSpec::Leaf {
                    label: "ceo".into(),
                    hardware_key_id: ceo_id,
                    allowed_bridges: vec![],
                },
                NodeSpec::Split {
                    label: "departments".into(),
                    threshold: 2,
                    allowed_bridges: vec![],
                    children: vec![
                        NodeSpec::Split {
                            label: "cxo".into(),
                            threshold: 2,
                            allowed_bridges: vec![],
                            children: vec![
                                NodeSpec::Leaf {
                                    label: "cfo".into(),
                                    hardware_key_id: cfo_id,
                                    allowed_bridges: vec![],
                                },
                                NodeSpec::Leaf {
                                    label: "coo".into(),
                                    hardware_key_id: coo_id,
                                    allowed_bridges: vec![],
                                },
                            ],
                        },
                        NodeSpec::Leaf {
                            label: "it".into(),
                            hardware_key_id: it_id,
                            allowed_bridges: vec![],
                        },
                    ],
                },
            ],
        };

        let secret = b"another 32-byte company secret!".to_vec();
        let key_id = split(&mut conn, "nested", &secret, &spec).expect("split should succeed");
        let leaves = leaf_ids_by_label(&conn, key_id);

        // Only cfo (not coo) from the cxo branch, plus it: cxo's own 2-of-2
        // is short by one, so "departments" can't resolve, and ceo wasn't
        // supplied either, so root's 2-of-2 has nothing to work with.
        let raw_cfo = unwrap_leaf_share(&conn, leaves[&"cfo".to_string()], &cfo_sk);
        let raw_it = unwrap_leaf_share(&conn, leaves[&"it".to_string()], &it_sk);

        let mut shares = HashMap::new();
        shares.insert(leaves[&"cfo".to_string()], raw_cfo);
        shares.insert(leaves[&"it".to_string()], raw_it);

        let result = reconstruct(&conn, key_id, &shares);
        assert!(matches!(result, Err(Error::QuorumNotMet)));
    }

    #[test]
    fn validate_rejects_threshold_above_children_count() {
        let conn = db::open_in_memory().expect("schema should apply");
        let (id_a, _) = register_encryption_key(&conn, "a");

        let spec = NodeSpec::Split {
            label: "root".into(),
            threshold: 2,
            allowed_bridges: vec![],
            children: vec![NodeSpec::Leaf {
                label: "a".into(),
                hardware_key_id: id_a,
                allowed_bridges: vec![],
            }],
        };

        assert!(matches!(
            validate(&conn, &spec),
            Err(Error::InvalidQuorumThreshold)
        ));
    }

    #[test]
    fn validate_rejects_more_than_255_children() {
        let conn = db::open_in_memory().expect("schema should apply");
        let (id_a, _) = register_encryption_key(&conn, "a");

        let spec = NodeSpec::Split {
            label: "root".into(),
            threshold: 1,
            allowed_bridges: vec![],
            children: (0..256)
                .map(|i| NodeSpec::Leaf {
                    label: format!("leaf-{i}"),
                    hardware_key_id: id_a,
                    allowed_bridges: vec![],
                })
                .collect(),
        };

        assert!(matches!(
            validate(&conn, &spec),
            Err(Error::InvalidQuorumThreshold)
        ));
    }

    #[test]
    fn validate_rejects_zero_threshold() {
        let conn = db::open_in_memory().expect("schema should apply");
        let (id_a, _) = register_encryption_key(&conn, "a");
        let (id_b, _) = register_encryption_key(&conn, "b");

        let spec = NodeSpec::Split {
            label: "root".into(),
            threshold: 0,
            allowed_bridges: vec![],
            children: vec![
                NodeSpec::Leaf {
                    label: "a".into(),
                    hardware_key_id: id_a,
                    allowed_bridges: vec![],
                },
                NodeSpec::Leaf {
                    label: "b".into(),
                    hardware_key_id: id_b,
                    allowed_bridges: vec![],
                },
            ],
        };

        assert!(matches!(
            validate(&conn, &spec),
            Err(Error::InvalidQuorumThreshold)
        ));
    }

    #[test]
    fn validate_rejects_signing_key_as_leaf() {
        let conn = db::open_in_memory().expect("schema should apply");
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let public_key = signing_key.verifying_key().to_bytes();
        let id = keys::register_key(&conn, "signer", KeyType::Signing, &public_key)
            .expect("register_key should succeed");

        let spec = NodeSpec::Leaf {
            label: "leaf".into(),
            hardware_key_id: id,
            allowed_bridges: vec![],
        };
        assert!(matches!(validate(&conn, &spec), Err(Error::WrongKeyType)));
    }

    #[test]
    fn validate_rejects_revoked_key_as_leaf() {
        let conn = db::open_in_memory().expect("schema should apply");
        let (id, _) = register_encryption_key(&conn, "a");
        keys::revoke_key(&conn, id).expect("revoke_key should succeed");

        let spec = NodeSpec::Leaf {
            label: "leaf".into(),
            hardware_key_id: id,
            allowed_bridges: vec![],
        };
        assert!(matches!(validate(&conn, &spec), Err(Error::KeyRevoked)));
    }

    #[test]
    fn describe_reports_labels_thresholds_and_leaf_key_labels() {
        let mut conn = db::open_in_memory().expect("schema should apply");
        let (id_a, _) = register_encryption_key(&conn, "alice");
        let (id_b, _) = register_encryption_key(&conn, "bob");

        let spec = NodeSpec::Split {
            label: "root".into(),
            threshold: 1,
            allowed_bridges: vec![],
            children: vec![
                NodeSpec::Leaf {
                    label: "a".into(),
                    hardware_key_id: id_a,
                    allowed_bridges: vec![],
                },
                NodeSpec::Leaf {
                    label: "b".into(),
                    hardware_key_id: id_b,
                    allowed_bridges: vec![],
                },
            ],
        };
        let secret = b"describe-me-describe-me-32bytes".to_vec();
        let key_id = split(&mut conn, "described", &secret, &spec).expect("split should succeed");

        let summary = describe(&conn, key_id).expect("describe should succeed");
        assert_eq!(summary.label, "described");
        assert_eq!(summary.root.threshold, Some(1));
        assert_eq!(summary.root.children.len(), 2);
        let labels: Vec<_> = summary
            .root
            .children
            .iter()
            .map(|c| c.hardware_key_label.clone().unwrap())
            .collect();
        assert!(labels.contains(&"alice".to_string()));
        assert!(labels.contains(&"bob".to_string()));
    }

    #[test]
    fn node_spec_rejects_an_object_mixing_leaf_and_split_fields() {
        let json = r#"{"label": "confused", "hardware_key_id": 1, "threshold": 2, "children": []}"#;
        let result: std::result::Result<NodeSpec, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn node_spec_rejects_an_unexpected_field() {
        let json = r#"{"label": "leaf", "hardware_key_id": 1, "extra": true}"#;
        let result: std::result::Result<NodeSpec, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn node_spec_accepts_allowed_bridges_on_a_leaf() {
        let json = r#"{"label": "alice", "hardware_key_id": 1, "allowed_bridges": ["bob"]}"#;
        let spec: NodeSpec = serde_json::from_str(json).expect("spec should parse");
        assert_eq!(spec.allowed_bridges(), &["bob".to_string()]);
    }

    #[test]
    fn validate_rejects_duplicate_labels() {
        let conn = db::open_in_memory().expect("schema should apply");
        let (id_a, _) = register_encryption_key(&conn, "a");
        let spec = NodeSpec::Split {
            label: "root".into(),
            threshold: 1,
            allowed_bridges: vec![],
            children: vec![
                NodeSpec::Leaf {
                    label: "dup".into(),
                    hardware_key_id: id_a,
                    allowed_bridges: vec![],
                },
                NodeSpec::Leaf {
                    label: "dup".into(),
                    hardware_key_id: id_a,
                    allowed_bridges: vec![],
                },
            ],
        };
        assert!(matches!(
            validate(&conn, &spec),
            Err(Error::DuplicateNodeLabel)
        ));
    }

    fn department_tree_spec(ma1: i64, ma2: i64, ma3: i64, mb: i64) -> NodeSpec {
        NodeSpec::Split {
            label: "M".into(),
            threshold: 1,
            allowed_bridges: vec![],
            children: vec![
                NodeSpec::Split {
                    label: "M.A".into(),
                    threshold: 2,
                    allowed_bridges: vec![],
                    children: vec![
                        NodeSpec::Leaf {
                            label: "M.A.1".into(),
                            hardware_key_id: ma1,
                            allowed_bridges: vec!["M.B".into()],
                        },
                        NodeSpec::Leaf {
                            label: "M.A.2".into(),
                            hardware_key_id: ma2,
                            allowed_bridges: vec![],
                        },
                        NodeSpec::Leaf {
                            label: "M.A.3".into(),
                            hardware_key_id: ma3,
                            allowed_bridges: vec![],
                        },
                    ],
                },
                NodeSpec::Leaf {
                    label: "M.B".into(),
                    hardware_key_id: mb,
                    allowed_bridges: vec![],
                },
            ],
        }
    }

    #[test]
    fn lca_of_department_siblings_is_the_department_node() {
        let mut conn = db::open_in_memory().expect("schema should apply");
        let (ma1, _) = register_encryption_key(&conn, "ma1");
        let (ma2, _) = register_encryption_key(&conn, "ma2");
        let (ma3, _) = register_encryption_key(&conn, "ma3");
        let (mb, _) = register_encryption_key(&conn, "mb");
        let spec = department_tree_spec(ma1, ma2, ma3, mb);
        let secret = b"company master secret 32 bytes!";
        let key_id = split(&mut conn, "org", secret, &spec).expect("split should succeed");

        let tree = KeyQuorumTree::load(&conn, key_id).expect("load should succeed");
        let a1 = tree.index_by_label("M.A.1").unwrap();
        let a2 = tree.index_by_label("M.A.2").unwrap();
        let mb_idx = tree.index_by_label("M.B").unwrap();
        let ma = tree.index_by_label("M.A").unwrap();

        assert_eq!(tree.find_lowest_common_ancestor(a1, a2).unwrap(), ma);
        assert_eq!(
            tree.find_lowest_common_ancestor(a1, mb_idx).unwrap(),
            tree.root_index
        );
        assert_eq!(tree.find_lowest_common_ancestor(a1, a1).unwrap(), a1);
        assert_eq!(
            tree.find_lowest_common_ancestor_of(&[a1, a2, ma]).unwrap(),
            ma
        );
    }

    #[test]
    fn bridge_allow_add_remove_and_deny() {
        let mut conn = db::open_in_memory().expect("schema should apply");
        let (ma1, _) = register_encryption_key(&conn, "ma1");
        let (ma2, _) = register_encryption_key(&conn, "ma2");
        let (ma3, _) = register_encryption_key(&conn, "ma3");
        let (mb, _) = register_encryption_key(&conn, "mb");
        let spec = department_tree_spec(ma1, ma2, ma3, mb);
        let secret = b"company master secret 32 bytes!";
        let key_id = split(&mut conn, "org", secret, &spec).expect("split should succeed");

        add_bridge(&conn, key_id, "M.A.1", "M.B").expect("spec whitelist should allow");
        let listing = list_bridges(&conn, key_id).expect("list should succeed");
        assert!(listing
            .established
            .iter()
            .any(|l| (l.from == "M.A.1" && l.to == "M.B") || (l.from == "M.B" && l.to == "M.A.1")));

        remove_bridge(&conn, key_id, "M.B", "M.A.1").expect("remove should succeed");
        assert!(list_bridges(&conn, key_id).unwrap().established.is_empty());
        assert!(matches!(
            remove_bridge(&conn, key_id, "M.A.1", "M.B"),
            Err(Error::BridgeNotFound)
        ));

        assert!(matches!(
            add_bridge(&conn, key_id, "M.A.2", "M.B"),
            Err(Error::BridgeNotWhitelisted)
        ));
        allow_bridge(&conn, key_id, "M.A.2", "M.B").expect("allow should succeed");
        add_bridge(&conn, key_id, "M.A.2", "M.B").expect("now whitelisted");
        deny_bridge(&conn, key_id, "M.A.2", "M.B").expect("deny should succeed");
        assert!(list_bridges(&conn, key_id).unwrap().established.is_empty());
        assert!(matches!(
            add_bridge(&conn, key_id, "M.A.2", "M.B"),
            Err(Error::BridgeNotWhitelisted)
        ));
        assert!(matches!(
            add_bridge(&conn, key_id, "missing", "M.B"),
            Err(Error::NodeNotFound)
        ));
    }

    #[test]
    fn deny_bridge_removes_the_reverse_whitelist_entry() {
        let mut conn = db::open_in_memory().expect("schema should apply");
        let (ma1, _) = register_encryption_key(&conn, "ma1");
        let (ma2, _) = register_encryption_key(&conn, "ma2");
        let (ma3, _) = register_encryption_key(&conn, "ma3");
        let (mb, _) = register_encryption_key(&conn, "mb");
        let spec = department_tree_spec(ma1, ma2, ma3, mb);
        let secret = b"company master secret 32 bytes!";
        let key_id = split(&mut conn, "org", secret, &spec).expect("split should succeed");

        // Spec already whitelists M.A.1 -> M.B; add the reverse so either
        // side would authorize a pairing after a one-way deny.
        allow_bridge(&conn, key_id, "M.B", "M.A.1").expect("reverse allow should succeed");
        add_bridge(&conn, key_id, "M.A.1", "M.B").expect("either whitelist should allow");
        deny_bridge(&conn, key_id, "M.A.1", "M.B").expect("deny should succeed");
        assert!(list_bridges(&conn, key_id).unwrap().established.is_empty());
        assert!(matches!(
            add_bridge(&conn, key_id, "M.B", "M.A.1"),
            Err(Error::BridgeNotWhitelisted)
        ));
    }

    #[test]
    fn evicting_ma3_lets_survivors_reach_root_without_the_parent_or_old_share() {
        let mut conn = db::open_in_memory().expect("schema should apply");
        let (id1, sk1) = register_encryption_key(&conn, "ma1");
        let (id2, sk2) = register_encryption_key(&conn, "ma2");
        let (id3, sk3) = register_encryption_key(&conn, "ma3");
        let (idb, _skb) = register_encryption_key(&conn, "mb");
        let spec = department_tree_spec(id1, id2, id3, idb);
        let secret = b"company master secret 32 bytes!";
        let key_id = split(&mut conn, "org", secret, &spec).expect("split should succeed");

        let leaves = leaf_ids_by_label(&conn, key_id);
        let raw1 = unwrap_leaf_share(&conn, leaves["M.A.1"], &sk1);
        let raw2 = unwrap_leaf_share(&conn, leaves["M.A.2"], &sk2);
        let raw3 = unwrap_leaf_share(&conn, leaves["M.A.3"], &sk3);

        let mut before = HashMap::new();
        before.insert(leaves["M.A.1"], raw1.clone());
        before.insert(leaves["M.A.2"], raw2.clone());
        assert_eq!(reconstruct(&conn, key_id, &before).unwrap(), secret);

        let mut survivors = HashMap::new();
        survivors.insert(leaves["M.A.1"], raw1.clone());
        survivors.insert(leaves["M.A.2"], raw2.clone());
        evict_and_refresh(&mut conn, key_id, leaves["M.A.3"], &survivors)
            .expect("evict should succeed");

        let tree = KeyQuorumTree::load(&conn, key_id).expect("load should succeed");
        let ma = tree.index_by_label("M.A").unwrap();
        assert_eq!(tree.nodes[ma].threshold, Some(2));
        assert!(!tree.nodes[tree.index_by_label("M.A.3").unwrap()].is_active);

        let new1 = unwrap_leaf_share(&conn, leaves["M.A.1"], &sk1);
        let new2 = unwrap_leaf_share(&conn, leaves["M.A.2"], &sk2);
        let mut after = HashMap::new();
        after.insert(leaves["M.A.1"], new1.clone());
        after.insert(leaves["M.A.2"], new2.clone());
        assert_eq!(reconstruct(&conn, key_id, &after).unwrap(), secret);

        let lca = tree
            .find_lowest_common_ancestor(
                tree.index_by_label("M.A.1").unwrap(),
                tree.index_by_label("M.A.2").unwrap(),
            )
            .unwrap();
        assert_eq!(
            reconstruct_from_lca(&conn, key_id, lca, &after).unwrap(),
            secret
        );

        let mut stale = HashMap::new();
        stale.insert(leaves["M.A.1"], new1);
        stale.insert(leaves["M.A.3"], raw3);
        assert!(matches!(
            reconstruct(&conn, key_id, &stale),
            Err(Error::QuorumNotMet)
        ));
    }

    #[test]
    fn evict_rejects_the_same_raw_share_for_two_survivors() {
        let mut conn = db::open_in_memory().expect("schema should apply");
        let (id1, sk1) = register_encryption_key(&conn, "ma1");
        let (id2, _) = register_encryption_key(&conn, "ma2");
        let (id3, _) = register_encryption_key(&conn, "ma3");
        let (idb, _) = register_encryption_key(&conn, "mb");
        let spec = department_tree_spec(id1, id2, id3, idb);
        let secret = b"company master secret 32 bytes!";
        let key_id = split(&mut conn, "org", secret, &spec).expect("split should succeed");

        let leaves = leaf_ids_by_label(&conn, key_id);
        let raw1 = unwrap_leaf_share(&conn, leaves["M.A.1"], &sk1);
        let mut survivors = HashMap::new();
        survivors.insert(leaves["M.A.1"], raw1.clone());
        survivors.insert(leaves["M.A.2"], raw1);
        assert!(matches!(
            evict_and_refresh(&mut conn, key_id, leaves["M.A.3"], &survivors),
            Err(Error::ShareShapeMismatch)
        ));
        let tree = KeyQuorumTree::load(&conn, key_id).expect("load should succeed");
        assert!(tree.nodes[tree.index_by_label("M.A.3").unwrap()].is_active);
    }

    #[test]
    fn evict_rejects_a_parent_threshold_of_one() {
        let mut conn = db::open_in_memory().expect("schema should apply");
        let (id_a, sk_a) = register_encryption_key(&conn, "a");
        let (id_b, _sk_b) = register_encryption_key(&conn, "b");
        let spec = NodeSpec::Split {
            label: "root".into(),
            threshold: 1,
            allowed_bridges: vec![],
            children: vec![
                NodeSpec::Leaf {
                    label: "a".into(),
                    hardware_key_id: id_a,
                    allowed_bridges: vec![],
                },
                NodeSpec::Leaf {
                    label: "b".into(),
                    hardware_key_id: id_b,
                    allowed_bridges: vec![],
                },
            ],
        };
        let secret = b"company master secret 32 bytes!";
        let key_id = split(&mut conn, "flat", secret, &spec).expect("split should succeed");
        let leaves = leaf_ids_by_label(&conn, key_id);
        let raw_a = unwrap_leaf_share(&conn, leaves["a"], &sk_a);
        let mut survivors = HashMap::new();
        survivors.insert(leaves["a"], raw_a);
        assert!(matches!(
            evict_and_refresh(&mut conn, key_id, leaves["b"], &survivors),
            Err(Error::CannotEvict)
        ));
    }
}
