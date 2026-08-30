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
