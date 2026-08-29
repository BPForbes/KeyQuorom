//! Herzberg-style proactive secret sharing over the same GF(256) Shamir
//! shares `blahaj` produces.
//!
//! Each surviving holder generates a random degree-`(t-1)` polynomial with
//! `Z(0) = 0`. Evaluations at the survivors' existing x-coordinates are
//! added (XOR) into their current shares. The secret is unchanged; any
//! share that did not receive the update becomes interpolating noise.

use crate::error::{Error, Result};
use blahaj::{Share, Sharks};
use rand::rngs::OsRng;
use std::collections::{HashMap, HashSet};

/// Builds one zero-constant polynomial of degree `threshold - 1` and
/// evaluates it at each requested Shamir x-coordinate.
///
/// x-coordinates must be in `1..=255` (blahaj never emits `x = 0`). The
/// dealer is asked for every field element so a hole in the middle of the
/// original split (e.g. evicting `x = 2` while `x = 1` and `x = 3` remain)
/// still receives the matching evaluation.
pub fn generate_zero_deltas(
    threshold: u8,
    secret_len: usize,
    xs: &[u8],
) -> Result<HashMap<u8, Vec<u8>>> {
    if threshold < 2 || secret_len == 0 || xs.is_empty() {
        return Err(Error::ShareShapeMismatch);
    }
    require_distinct_nonzero_xs(xs)?;

    let zero = vec![0u8; secret_len];
    let sharks = Sharks(threshold);
    let all: Vec<Share> = sharks.dealer_rng(&zero, &mut OsRng).take(255).collect();

    let wanted: HashMap<u8, ()> = xs.iter().copied().map(|x| (x, ())).collect();
    let mut by_x = HashMap::with_capacity(xs.len());
    for share in &all {
        let bytes = Vec::from(share);
        let x = bytes[0];
        if wanted.contains_key(&x) {
            by_x.insert(x, bytes);
        }
    }

    if by_x.len() != wanted.len() {
        return Err(Error::ShareShapeMismatch);
    }
    Ok(by_x)
}

/// XOR of two share encodings that must already share `x` and y-length.
pub fn apply_deltas(share: &[u8], delta: &[u8]) -> Result<Vec<u8>> {
    add_shares(share, delta)
}

/// XOR of two share encodings that must already share `x` and y-length.
pub fn add_shares(a: &[u8], b: &[u8]) -> Result<Vec<u8>> {
    if a.len() < 2 || a.len() != b.len() || a[0] != b[0] {
        return Err(Error::ShareShapeMismatch);
    }
    let mut out = Vec::with_capacity(a.len());
    out.push(a[0]);
    out.extend(a[1..].iter().zip(&b[1..]).map(|(l, r)| l ^ r));
    Ok(out)
}

/// In-process mutual refresh: each survivor generates a blinding
/// polynomial and every local share absorbs every generated delta.
pub fn refresh_among(shares: &mut [Vec<u8>], threshold: u8) -> Result<()> {
    if shares.is_empty() || shares.len() < threshold as usize {
        return Err(Error::ShareShapeMismatch);
    }
    let secret_len = shares[0].len().saturating_sub(1);
    if secret_len == 0 {
        return Err(Error::ShareShapeMismatch);
    }

    let mut xs = Vec::with_capacity(shares.len());
    for share in shares.iter() {
        if share.len() != secret_len + 1 {
            return Err(Error::ShareShapeMismatch);
        }
        xs.push(share[0]);
    }
    require_distinct_nonzero_xs(&xs)?;
    if threshold < 2 {
        return Err(Error::ShareShapeMismatch);
    }

    let mut combined: HashMap<u8, Vec<u8>> = HashMap::with_capacity(xs.len());
    for &x in &xs {
        let mut zero_share = vec![x];
        zero_share.resize(secret_len + 1, 0);
        combined.insert(x, zero_share);
    }

    for _ in 0..shares.len() {
        let deltas = generate_zero_deltas(threshold, secret_len, &xs)?;
        for (&x, delta) in &deltas {
            let acc = combined.get_mut(&x).ok_or(Error::ShareShapeMismatch)?;
            *acc = apply_deltas(acc, delta)?;
        }
    }

    for share in shares.iter_mut() {
        let x = share[0];
        let delta = combined.get(&x).ok_or(Error::ShareShapeMismatch)?;
        *share = apply_deltas(share, delta)?;
    }
    Ok(())
}

fn require_distinct_nonzero_xs(xs: &[u8]) -> Result<()> {
    let mut seen = HashSet::with_capacity(xs.len());
    for &x in xs {
        if x == 0 || !seen.insert(x) {
            return Err(Error::ShareShapeMismatch);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn split_secret(secret: &[u8], threshold: u8, n: usize) -> Vec<Vec<u8>> {
        let sharks = Sharks(threshold);
        sharks
            .dealer_rng(secret, &mut OsRng)
            .take(n)
            .map(|s| Vec::from(&s))
            .collect()
    }

    fn recover(threshold: u8, shares: &[Vec<u8>]) -> Vec<u8> {
        let parsed: Vec<Share> = shares
            .iter()
            .map(|s| Share::try_from(s.as_slice()).expect("share should parse"))
            .collect();
        Sharks(threshold)
            .recover(parsed.iter())
            .expect("recover should succeed")
    }

    #[test]
    fn refresh_preserves_the_secret_and_invalidates_a_stale_share() {
        let secret = b"the quorum has been reached!!!!";
        let mut shares = split_secret(secret, 2, 3);
        let stale = shares[2].clone();

        refresh_among(&mut shares[..2], 2).expect("refresh should succeed");

        assert_eq!(recover(2, &shares[..2]), secret);

        let mixed = [shares[0].clone(), stale];
        let recovered = recover(2, &mixed);
        assert_ne!(
            recovered, secret,
            "a pre-refresh share must not reconstruct with a refreshed sibling"
        );
    }

    #[test]
    fn add_shares_rejects_mismatched_x() {
        let a = vec![1, 10, 20];
        let b = vec![2, 10, 20];
        assert!(matches!(add_shares(&a, &b), Err(Error::ShareShapeMismatch)));
    }

    #[test]
    fn refresh_rejects_duplicate_share_coordinates() {
        let secret = b"the quorum has been reached!!!!";
        let shares = split_secret(secret, 2, 2);
        let mut duplicated = [shares[0].clone(), shares[0].clone()];
        assert!(matches!(
            refresh_among(&mut duplicated, 2),
            Err(Error::ShareShapeMismatch)
        ));
    }

    #[test]
    fn refresh_rejects_a_threshold_of_one() {
        let secret = b"the quorum has been reached!!!!";
        let mut shares = split_secret(secret, 1, 2);
        assert!(matches!(
            refresh_among(&mut shares, 1),
            Err(Error::ShareShapeMismatch)
        ));
    }

    #[test]
    fn refresh_rejects_fewer_shares_than_the_threshold() {
        let secret = b"the quorum has been reached!!!!";
        let mut shares = split_secret(secret, 2, 2);
        assert!(matches!(
            refresh_among(&mut shares[..1], 2),
            Err(Error::ShareShapeMismatch)
        ));
    }
}
