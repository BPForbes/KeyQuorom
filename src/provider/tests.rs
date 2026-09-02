use super::*;
use crate::error::Error;
use crate::provider::test_helpers::{empty_revoked, issued_identity, issued_identity_with_caps};
use std::collections::HashSet;

fn verify_ok(issued: &super::test_helpers::IssuedIdentity, now: &str) -> Certificate {
    verify_certificate(
        &issued.root_public,
        &issued.certificate,
        now,
        &empty_revoked(),
    )
    .expect("valid certificate")
}

#[test]
fn issue_and_verify_round_trip() {
    let issued = issued_identity("2027-09-02 00:00:00");
    let cert = verify_ok(&issued, "2026-09-02 12:00:00");
    assert_eq!(cert.provider_id, "Acme Security Services");
    assert_eq!(cert.serial, "KQP-000184");
    assert_eq!(cert.relay_public_key, issued.relay_public);
    assert_eq!(cert.capabilities, CAP_PROVIDER);
    assert_eq!(cert.issuer_id, "KeyQuorumRoot");
}

#[test]
fn expired_certificate_is_rejected() {
    let issued = issued_identity("2026-01-01 00:00:00");
    let err = verify_certificate(
        &issued.root_public,
        &issued.certificate,
        "2026-01-01 00:00:00",
        &empty_revoked(),
    )
    .unwrap_err();
    assert!(matches!(err, Error::ProviderCertificateExpired));
}

#[test]
fn revoked_serial_is_rejected() {
    let issued = issued_identity("2027-09-02 00:00:00");
    let mut revoked = HashSet::new();
    revoked.insert("KQP-000184".into());
    let err = verify_certificate(
        &issued.root_public,
        &issued.certificate,
        "2026-09-02 12:00:00",
        &revoked,
    )
    .unwrap_err();
    assert!(matches!(err, Error::ProviderCertificateRevoked));
}

#[test]
fn wrong_root_is_rejected() {
    let issued = issued_identity("2027-09-02 00:00:00");
    let (_, other_root) = crate::keys::generate_signing_keypair();
    let err = verify_certificate(
        &other_root,
        &issued.certificate,
        "2026-09-02 12:00:00",
        &empty_revoked(),
    )
    .unwrap_err();
    assert!(matches!(err, Error::InvalidProviderCertificate));
}

#[test]
fn incomplete_capabilities_are_rejected() {
    let issued = issued_identity_with_caps("2027-09-02 00:00:00", CAP_RELAY | CAP_MAILBOX);
    let err = verify_certificate(
        &issued.root_public,
        &issued.certificate,
        "2026-09-02 12:00:00",
        &empty_revoked(),
    )
    .unwrap_err();
    assert!(matches!(err, Error::ProviderCapabilityDenied));
}

#[test]
fn self_check_requires_matching_private_key() {
    let issued = issued_identity("2027-09-02 00:00:00");
    self_check(
        &issued.root_public,
        &issued.certificate,
        &issued.relay_private,
        "2026-09-02 12:00:00",
        &empty_revoked(),
    )
    .expect("matching key");
    let (other, _) = generate_relay_identity();
    let err = self_check(
        &issued.root_public,
        &issued.certificate,
        &other,
        "2026-09-02 12:00:00",
        &empty_revoked(),
    )
    .unwrap_err();
    assert!(matches!(err, Error::RelayIdentityMismatch));
}

#[test]
fn challenge_round_trip() {
    let issued = issued_identity("2027-09-02 00:00:00");
    let cert = verify_ok(&issued, "2026-09-02 12:00:00");
    let challenge = random_challenge();
    let signature = sign_challenge(&issued.relay_private, &challenge).expect("sign");
    verify_challenge(&cert, &challenge, &signature).expect("verify");
    let other = random_challenge();
    assert!(verify_challenge(&cert, &other, &signature).is_err());
    let (wrong_sk, _) = generate_relay_identity();
    let wrong_sig = sign_challenge(&wrong_sk, &challenge).expect("sign");
    assert!(verify_challenge(&cert, &challenge, &wrong_sig).is_err());
}

#[test]
fn challenge_rejects_wrong_length() {
    let issued = issued_identity("2027-09-02 00:00:00");
    assert!(matches!(
        sign_challenge(&issued.relay_private, &[0u8; 16]),
        Err(Error::InvalidProviderChallenge)
    ));
}

#[test]
fn signed_revocation_list_round_trip() {
    let (root_sk, root_pk) = crate::keys::generate_signing_keypair();
    let bytes = issue_revocation_list(
        &root_sk,
        "2026-09-02 12:00:00",
        &["KQP-000184".into(), "KQP-000271".into()],
    )
    .expect("krl");
    let serials = verify_revocation_list(&root_pk, &bytes).expect("verify krl");
    assert!(serials.contains("KQP-000184"));
    assert!(serials.contains("KQP-000271"));
    let (_, other) = crate::keys::generate_signing_keypair();
    assert!(verify_revocation_list(&other, &bytes).is_err());
}

#[test]
fn empty_revocation_list_is_valid() {
    let (root_sk, root_pk) = crate::keys::generate_signing_keypair();
    let bytes = issue_revocation_list(&root_sk, "2026-09-02 12:00:00", &[]).expect("empty krl");
    let serials = verify_revocation_list(&root_pk, &bytes).expect("verify");
    assert!(serials.is_empty());
}

#[test]
fn malformed_certificate_is_rejected() {
    assert!(matches!(
        parse_certificate(b""),
        Err(Error::InvalidProviderCertificate)
    ));
    assert!(matches!(
        parse_certificate(b"XXXX"),
        Err(Error::InvalidProviderCertificate)
    ));
    let issued = issued_identity("2027-09-02 00:00:00");
    let mut truncated = issued.certificate.clone();
    truncated.truncate(truncated.len() - 8);
    assert!(parse_certificate(&truncated).is_err());
    let mut extra = issued.certificate.clone();
    extra.push(0);
    assert!(parse_certificate(&extra).is_err());
}

#[test]
fn parse_capabilities_accepts_provider_and_parts() {
    assert_eq!(parse_capabilities("provider").unwrap(), CAP_PROVIDER);
    assert_eq!(
        parse_capabilities("relay,mailbox,api-key-administration").unwrap(),
        CAP_PROVIDER
    );
    assert!(parse_capabilities("relay").unwrap() & CAP_RELAY != 0);
    assert!(parse_capabilities("nope").is_err());
    assert!(parse_capabilities("").is_err());
}

#[test]
fn unix_epoch_formats_as_utc_minute() {
    assert_eq!(unix_to_utc_minute(0), "1970-01-01 00:00:00");
    assert_eq!(unix_to_utc_minute(60), "1970-01-01 00:01:00");
}

#[test]
fn load_revocation_list_is_fail_closed() {
    let (root_sk, root_pk) = crate::keys::generate_signing_keypair();
    let bytes = issue_revocation_list(&root_sk, "2026-09-02 12:00:00", &["KQP-1".into()]).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("rev.kqrl");
    std::fs::write(&path, &bytes).unwrap();
    let loaded = load_revocation_list(&root_pk, Some(&path)).unwrap();
    assert!(loaded.contains("KQP-1"));
    assert!(load_revocation_list(&root_pk, None).unwrap().is_empty());
    assert!(load_revocation_list(&root_pk, Some(&dir.path().join("missing.kqrl"))).is_err());
}

#[test]
fn issue_rejects_empty_fields() {
    let (root_sk, _) = crate::keys::generate_signing_keypair();
    let (_, relay_pk) = generate_relay_identity();
    let err = issue_certificate(
        &root_sk,
        &NewCertificate {
            provider_id: "",
            serial: "KQP-1",
            relay_public_key: &relay_pk,
            issued_at: "2026-01-01 00:00:00",
            expires_at: "2027-01-01 00:00:00",
            capabilities: CAP_PROVIDER,
            issuer_id: "KeyQuorumRoot",
        },
    )
    .unwrap_err();
    assert!(matches!(err, Error::InvalidProviderCertificate));
}
