//! Canonical public split-tree stored as a JSON document per `keys.label`.
//!
//! The relay keeps the **full** public topology here (labels, thresholds,
//! encryption fingerprints/public keys, whitelist, established links). That
//! document is the server's own context store — not a personal SQLite tree
//! and never wrapped shares or private keys. Pushing envelopes updates these
//! documents. Pull slices the document for the recipient fingerprint and the
//! personal store translates that slice into SQLite.

use crate::error::{Error, Result};
use crate::key_tree::{filter_public_tree, visible_labels_in_public_tree, PublicTree};
use rusqlite::{params, Connection, OptionalExtension};
use std::collections::{HashMap, HashSet};

pub fn put_public_tree(conn: &Connection, snapshot: &PublicTree) -> Result<PublicTree> {
    validate_public_tree(snapshot)?;
    crate::db::with_immediate_transaction(conn, || persist_public_tree(conn, snapshot))
}

/// Upsert the incoming nodes and edges into an existing document.
///
/// Labels present in `snapshot` are authoritative. Nodes and edges the
/// sender does not mention stay in place, so a personal subgraph cannot
/// erase unrelated topology. Use [`put_public_tree`] to replace a document.
pub fn merge_public_tree(conn: &Connection, snapshot: &PublicTree) -> Result<PublicTree> {
    validate_public_tree(snapshot)?;
    crate::db::with_immediate_transaction(conn, || {
        let merged = match get_public_tree(conn, &snapshot.label) {
            Ok(existing) => merge_into_existing(&existing, snapshot)?,
            Err(Error::TreeNotFound) => snapshot.clone(),
            Err(err) => return Err(err),
        };
        persist_public_tree(conn, &merged)
    })
}

fn merge_into_existing(existing: &PublicTree, incoming: &PublicTree) -> Result<PublicTree> {
    let incoming_labels: HashSet<&str> = incoming.nodes.iter().map(|n| n.label.as_str()).collect();
    let mut nodes = incoming.nodes.clone();
    for node in &existing.nodes {
        if !incoming_labels.contains(node.label.as_str()) {
            nodes.push(node.clone());
        }
    }
    let mut whitelist = incoming.whitelist.clone();
    for edge in &existing.whitelist {
        if incoming_labels.contains(edge.from.as_str())
            && incoming_labels.contains(edge.to.as_str())
        {
            continue;
        }
        if !whitelist
            .iter()
            .any(|kept| kept.from == edge.from && kept.to == edge.to)
        {
            whitelist.push(edge.clone());
        }
    }
    let mut links = incoming.links.clone();
    for edge in &existing.links {
        if incoming_labels.contains(edge.from.as_str())
            && incoming_labels.contains(edge.to.as_str())
        {
            continue;
        }
        if !links
            .iter()
            .any(|kept| kept.from == edge.from && kept.to == edge.to)
        {
            links.push(edge.clone());
        }
    }
    let merged = PublicTree {
        label: incoming.label.clone(),
        generation: existing.generation,
        nodes,
        whitelist,
        links,
    };
    validate_public_tree(&merged)?;
    Ok(merged)
}

fn persist_public_tree(conn: &Connection, snapshot: &PublicTree) -> Result<PublicTree> {
    let existing: Option<i64> = conn
        .query_row(
            "SELECT generation FROM org_tree_docs WHERE label = ?1",
            params![snapshot.label],
            |row| row.get(0),
        )
        .optional()?;
    let generation = existing.map(|gen| gen.saturating_add(1)).unwrap_or(1);
    let mut stored = snapshot.clone();
    stored.generation = u32::try_from(generation).unwrap_or(u32::MAX);
    let document = serde_json::to_string(&stored).map_err(|_| Error::InvalidTreeSpec)?;
    conn.execute(
        "INSERT INTO org_tree_docs (label, generation, document) VALUES (?1, ?2, ?3)
         ON CONFLICT(label) DO UPDATE SET
            generation = excluded.generation,
            document = excluded.document,
            updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')",
        params![stored.label, generation, document],
    )?;
    Ok(stored)
}

pub fn get_public_tree(conn: &Connection, label: &str) -> Result<PublicTree> {
    let document: String = conn
        .query_row(
            "SELECT document FROM org_tree_docs WHERE label = ?1",
            params![label],
            |row| row.get(0),
        )
        .optional()?
        .ok_or(Error::TreeNotFound)?;
    parse_document(&document)
}

pub fn list_public_trees(conn: &Connection) -> Result<Vec<PublicTree>> {
    let mut stmt = conn.prepare("SELECT document FROM org_tree_docs ORDER BY label")?;
    let trees = stmt
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    trees
        .iter()
        .map(|document| parse_document(document))
        .collect()
}

/// Slice every stored tree that contains this encryption fingerprint.
/// Trees that do not mention the fingerprint are omitted, not an error.
pub fn slices_for_fingerprint(conn: &Connection, fingerprint: &str) -> Result<Vec<PublicTree>> {
    let mut slices = Vec::new();
    for full in list_public_trees(conn)? {
        if let Some(slice) = slice_for_fingerprint(&full, fingerprint) {
            slices.push(slice);
        }
    }
    Ok(slices)
}

/// Slice one published tree for every leaf bound to this fingerprint.
pub fn context_for_fingerprint(
    conn: &Connection,
    label: &str,
    fingerprint: &str,
) -> Result<PublicTree> {
    let full = get_public_tree(conn, label)?;
    slice_for_fingerprint(&full, fingerprint).ok_or(Error::NodeNotFound)
}

fn slice_for_fingerprint(full: &PublicTree, fingerprint: &str) -> Option<PublicTree> {
    let seeds: Vec<String> = full
        .nodes
        .iter()
        .filter(|node| node.encryption_fingerprint.as_deref() == Some(fingerprint))
        .map(|node| node.label.clone())
        .collect();
    if seeds.is_empty() {
        return None;
    }
    let visible = visible_labels_in_public_tree(full, &seeds);
    Some(filter_public_tree(full, &visible))
}

/// Every published tree this fingerprint appears in, already sliced.
/// Unknown fingerprints yield an empty list so inbox pull still succeeds.
pub fn contexts_for_fingerprint(conn: &Connection, fingerprint: &str) -> Result<Vec<PublicTree>> {
    slices_for_fingerprint(conn, fingerprint)
}

fn parse_document(document: &str) -> Result<PublicTree> {
    serde_json::from_str(document).map_err(|_| Error::InvalidTreeSpec)
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
    let mut seen_whitelist = HashSet::new();
    for edge in &tree.whitelist {
        if !seen_whitelist.insert((edge.from.as_str(), edge.to.as_str())) {
            return Err(Error::InvalidBridge);
        }
    }
    let mut seen_links = HashSet::new();
    for edge in &tree.links {
        if !seen_links.insert((edge.from.as_str(), edge.to.as_str())) {
            return Err(Error::InvalidBridge);
        }
        let listed = tree.whitelist.iter().any(|allowed| {
            (allowed.from == edge.from && allowed.to == edge.to)
                || (allowed.from == edge.to && allowed.to == edge.from)
        });
        if !listed {
            return Err(Error::InvalidBridge);
        }
    }
    let mut parent_of = HashMap::new();
    let mut root = None;
    for node in &tree.nodes {
        parent_of.insert(node.label.as_str(), node.parent_label.as_deref());
        if node.parent_label.is_none() {
            root = Some(node.label.as_str());
        }
    }
    let root = root.ok_or(Error::InvalidTreeSpec)?;
    for node in &tree.nodes {
        if !reaches_root(&parent_of, node.label.as_str(), root) {
            return Err(Error::InvalidTreeSpec);
        }
    }
    Ok(())
}

fn reaches_root(parent_of: &HashMap<&str, Option<&str>>, start: &str, root: &str) -> bool {
    let mut cur = Some(start);
    let mut seen = HashSet::new();
    while let Some(label) = cur {
        if !seen.insert(label) {
            return false;
        }
        if label == root {
            return true;
        }
        cur = parent_of.get(label).copied().flatten();
    }
    false
}

#[cfg(test)]
mod persist_tests {
    use super::*;
    use crate::key_tree::{PublicEdge, PublicNode, PublicTree};

    fn split(label: &str, parent: Option<&str>) -> PublicNode {
        PublicNode {
            label: label.into(),
            parent_label: parent.map(str::to_string),
            threshold: Some(2),
            is_active: true,
            encryption_fingerprint: None,
            encryption_public_key: None,
        }
    }

    fn tiny_tree() -> PublicTree {
        PublicTree {
            label: "org".into(),
            generation: 1,
            nodes: vec![
                split("M", None),
                split("M.A", Some("M")),
                split("M.S", Some("M")),
            ],
            whitelist: vec![PublicEdge {
                from: "M.A".into(),
                to: "M.S".into(),
            }],
            links: vec![],
        }
    }

    #[test]
    fn persist_rejects_duplicate_whitelist_without_replacing_the_document() {
        let conn = crate::relay::open_in_memory().expect("schema");
        let tree = tiny_tree();
        put_public_tree(&conn, &tree).expect("first put");
        let mut bad = tree.clone();
        bad.whitelist.push(bad.whitelist[0].clone());
        assert!(put_public_tree(&conn, &bad).is_err());
        let stored = get_public_tree(&conn, "org").expect("still there");
        assert_eq!(stored.generation, 1);
        assert_eq!(stored.nodes.len(), 3);
        assert_eq!(stored.whitelist.len(), 1);
    }

    #[test]
    fn persist_rejects_a_disconnected_parent_cycle() {
        let conn = crate::relay::open_in_memory().expect("schema");
        let tree = PublicTree {
            label: "org".into(),
            generation: 1,
            nodes: vec![
                split("M", None),
                split("A", Some("B")),
                split("B", Some("A")),
            ],
            whitelist: vec![],
            links: vec![],
        };
        assert!(matches!(
            put_public_tree(&conn, &tree),
            Err(Error::InvalidTreeSpec)
        ));
        assert!(matches!(
            get_public_tree(&conn, "org"),
            Err(Error::TreeNotFound)
        ));
    }
}
