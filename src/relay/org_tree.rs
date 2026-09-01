//! Canonical public split-tree topology stored on the relay.
//!
//! This is labels, thresholds, encryption fingerprints/public keys,
//! whitelist, and established links only. Sealed shares and private keys
//! never belong here. Each personal store later fetches a slice of this
//! tree: own lineage, siblings, descendants, and the fixpoint of
//! established bridge peers.

use crate::error::{Error, Result};
use crate::key_tree::{
    filter_public_tree, visible_labels_in_public_tree, PublicEdge, PublicNode, PublicTree,
};
use rusqlite::{params, Connection, OptionalExtension};
use std::collections::HashSet;

pub fn put_public_tree(conn: &Connection, snapshot: &PublicTree) -> Result<PublicTree> {
    validate_public_tree(snapshot)?;
    let existing: Option<(i64, i64)> = conn
        .query_row(
            "SELECT id, generation FROM org_trees WHERE label = ?1",
            params![snapshot.label],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let (tree_id, generation) = match existing {
        Some((id, gen)) => {
            conn.execute("DELETE FROM org_nodes WHERE tree_id = ?1", params![id])?;
            conn.execute("DELETE FROM org_whitelist WHERE tree_id = ?1", params![id])?;
            conn.execute("DELETE FROM org_links WHERE tree_id = ?1", params![id])?;
            let generation = gen.saturating_add(1);
            conn.execute(
                "UPDATE org_trees SET generation = ?1,
                    updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                 WHERE id = ?2",
                params![generation, id],
            )?;
            (id, generation)
        }
        None => {
            conn.execute(
                "INSERT INTO org_trees (label, generation) VALUES (?1, 1)",
                params![snapshot.label],
            )?;
            (conn.last_insert_rowid(), 1)
        }
    };
    for node in &snapshot.nodes {
        conn.execute(
            "INSERT INTO org_nodes (
                tree_id, label, parent_label, threshold, is_active,
                encryption_fingerprint, encryption_public_key
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                tree_id,
                node.label,
                node.parent_label,
                node.threshold,
                i64::from(u8::from(node.is_active)),
                node.encryption_fingerprint,
                node.encryption_public_key,
            ],
        )?;
    }
    for edge in &snapshot.whitelist {
        conn.execute(
            "INSERT INTO org_whitelist (tree_id, from_label, to_label) VALUES (?1, ?2, ?3)",
            params![tree_id, edge.from, edge.to],
        )?;
    }
    for edge in &snapshot.links {
        conn.execute(
            "INSERT INTO org_links (tree_id, from_label, to_label) VALUES (?1, ?2, ?3)",
            params![tree_id, edge.from, edge.to],
        )?;
    }
    let mut stored = snapshot.clone();
    stored.generation = u32::try_from(generation).unwrap_or(u32::MAX);
    Ok(stored)
}

pub fn get_public_tree(conn: &Connection, label: &str) -> Result<PublicTree> {
    let (tree_id, generation): (i64, i64) = conn
        .query_row(
            "SELECT id, generation FROM org_trees WHERE label = ?1",
            params![label],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?
        .ok_or(Error::TreeNotFound)?;
    load_public_tree(conn, tree_id, label, generation)
}

/// Slice the published tree for every leaf bound to this encryption
/// fingerprint. Unknown fingerprints are a not-found, not an empty tree.
pub fn context_for_fingerprint(
    conn: &Connection,
    label: &str,
    fingerprint: &str,
) -> Result<PublicTree> {
    let full = get_public_tree(conn, label)?;
    let seeds: Vec<String> = full
        .nodes
        .iter()
        .filter(|node| node.encryption_fingerprint.as_deref() == Some(fingerprint))
        .map(|node| node.label.clone())
        .collect();
    if seeds.is_empty() {
        return Err(Error::NodeNotFound);
    }
    let visible = visible_labels_in_public_tree(&full, &seeds);
    Ok(filter_public_tree(&full, &visible))
}

fn load_public_tree(
    conn: &Connection,
    tree_id: i64,
    label: &str,
    generation: i64,
) -> Result<PublicTree> {
    let mut node_stmt = conn.prepare(
        "SELECT label, parent_label, threshold, is_active,
                encryption_fingerprint, encryption_public_key
         FROM org_nodes WHERE tree_id = ?1 ORDER BY id",
    )?;
    let nodes = node_stmt
        .query_map(params![tree_id], |row| {
            let is_active: i64 = row.get(3)?;
            Ok(PublicNode {
                label: row.get(0)?,
                parent_label: row.get(1)?,
                threshold: row.get(2)?,
                is_active: is_active != 0,
                encryption_fingerprint: row.get(4)?,
                encryption_public_key: row.get(5)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    drop(node_stmt);

    Ok(PublicTree {
        label: label.to_string(),
        generation: u32::try_from(generation).unwrap_or(u32::MAX),
        nodes,
        whitelist: load_edges(conn, tree_id, EdgeKind::Whitelist)?,
        links: load_edges(conn, tree_id, EdgeKind::Link)?,
    })
}

fn load_edges(conn: &Connection, tree_id: i64, kind: EdgeKind) -> Result<Vec<PublicEdge>> {
    let sql = match kind {
        EdgeKind::Whitelist => {
            "SELECT from_label, to_label FROM org_whitelist WHERE tree_id = ?1 ORDER BY from_label, to_label"
        }
        EdgeKind::Link => {
            "SELECT from_label, to_label FROM org_links WHERE tree_id = ?1 ORDER BY from_label, to_label"
        }
    };
    let mut stmt = conn.prepare(sql)?;
    let edges = stmt
        .query_map(params![tree_id], |row| {
            Ok(PublicEdge {
                from: row.get(0)?,
                to: row.get(1)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(edges)
}

enum EdgeKind {
    Whitelist,
    Link,
}

pub(crate) fn validate_public_tree(tree: &PublicTree) -> Result<()> {
    if tree.label.is_empty() || tree.nodes.is_empty() {
        return Err(Error::InvalidTreeSpec);
    }
    let mut labels = HashSet::new();
    let mut roots = 0usize;
    for node in &tree.nodes {
        if node.label.is_empty() || !labels.insert(node.label.as_str()) {
            return Err(Error::DuplicateNodeLabel);
        }
        if node.parent_label.is_none() {
            roots += 1;
        }
        match (
            node.threshold,
            node.encryption_fingerprint.as_ref(),
            node.encryption_public_key.as_ref(),
        ) {
            (Some(threshold), None, None) if threshold > 0 => {}
            (None, Some(_), Some(pk)) => {
                let raw = hex::decode(pk).map_err(|_| Error::InvalidPublicKey)?;
                if raw.len() != 32 {
                    return Err(Error::InvalidPublicKey);
                }
            }
            _ => return Err(Error::InvalidTreeSpec),
        }
    }
    if roots != 1 {
        return Err(Error::InvalidTreeSpec);
    }
    for node in &tree.nodes {
        if let Some(parent) = &node.parent_label {
            if !labels.contains(parent.as_str()) {
                return Err(Error::InvalidTreeSpec);
            }
        }
    }
    for edge in tree.whitelist.iter().chain(&tree.links) {
        if edge.from == edge.to
            || !labels.contains(edge.from.as_str())
            || !labels.contains(edge.to.as_str())
        {
            return Err(Error::InvalidBridge);
        }
    }
    Ok(())
}
