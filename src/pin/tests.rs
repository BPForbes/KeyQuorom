use super::*;
use crate::db;

#[test]
fn correct_pin_succeeds_and_resets_attempt_count() {
    let conn = db::open_in_memory().expect("schema should apply");
    set_pin(&conn, ResourceType::Credential, 1, "1234", true, 300).expect("set_pin should succeed");

    verify_pin(&conn, ResourceType::Credential, 1, "0000").unwrap_err();
    let result = verify_pin(&conn, ResourceType::Credential, 1, "1234");
    assert!(result.is_ok());

    let attempt_count: i64 = conn
        .query_row(
            "SELECT attempt_count FROM pins WHERE resource_id = 1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(attempt_count, 0);
}

#[test]
fn successful_one_time_verification_suppresses_prompts_until_relocked() {
    let conn = db::open_in_memory().expect("schema should apply");
    set_pin(&conn, ResourceType::Credential, 1, "1234", false, 300)
        .expect("set_pin should succeed");

    assert!(verification_required(&conn, ResourceType::Credential, 1).unwrap());
    verify_pin(&conn, ResourceType::Credential, 1, "1234").unwrap();
    assert!(!verification_required(&conn, ResourceType::Credential, 1).unwrap());

    relock(&conn, ResourceType::Credential, 1).unwrap();
    assert!(verification_required(&conn, ResourceType::Credential, 1).unwrap());
}

#[test]
fn wrong_pin_increments_attempt_count() {
    let conn = db::open_in_memory().expect("schema should apply");
    set_pin(&conn, ResourceType::Credential, 1, "1234", true, 300).expect("set_pin should succeed");

    let result = verify_pin(&conn, ResourceType::Credential, 1, "0000");
    assert!(matches!(result, Err(Error::PinMismatch)));

    let attempt_count: i64 = conn
        .query_row(
            "SELECT attempt_count FROM pins WHERE resource_id = 1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(attempt_count, 1);
}

#[test]
fn hitting_the_attempt_cap_locks_the_pin_even_for_the_correct_value() {
    let conn = db::open_in_memory().expect("schema should apply");
    set_pin(&conn, ResourceType::Credential, 1, "1234", true, 300).expect("set_pin should succeed");

    for _ in 0..MAX_ATTEMPTS {
        let _ = verify_pin(&conn, ResourceType::Credential, 1, "0000");
    }

    let result = verify_pin(&conn, ResourceType::Credential, 1, "1234");
    assert!(matches!(result, Err(Error::PinLocked)));
}

#[test]
fn one_time_mode_sets_and_honors_unlocked_until() {
    let conn = db::open_in_memory().expect("schema should apply");
    set_pin(&conn, ResourceType::FileShare, 1, "4242", false, 300).expect("set_pin should succeed");

    verify_pin(&conn, ResourceType::FileShare, 1, "4242").expect("correct PIN should succeed");

    // A second access within the TTL window shouldn't need the PIN
    // again — even a wrong PIN value short-circuits to success.
    let result = verify_pin(&conn, ResourceType::FileShare, 1, "0000");
    assert!(result.is_ok());
}

#[test]
fn require_every_use_never_short_circuits() {
    let conn = db::open_in_memory().expect("schema should apply");
    set_pin(&conn, ResourceType::FileShare, 1, "4242", true, 300).expect("set_pin should succeed");

    verify_pin(&conn, ResourceType::FileShare, 1, "4242").expect("correct PIN should succeed");

    let result = verify_pin(&conn, ResourceType::FileShare, 1, "0000");
    assert!(matches!(result, Err(Error::PinMismatch)));
}

#[test]
fn relock_clears_the_one_time_unlock_window() {
    let conn = db::open_in_memory().expect("schema should apply");
    set_pin(&conn, ResourceType::FileShare, 1, "4242", false, 300).expect("set_pin should succeed");
    verify_pin(&conn, ResourceType::FileShare, 1, "4242").expect("correct PIN should succeed");

    relock(&conn, ResourceType::FileShare, 1).expect("relock should succeed");

    let result = verify_pin(&conn, ResourceType::FileShare, 1, "0000");
    assert!(matches!(result, Err(Error::PinMismatch)));
}

#[test]
fn set_pin_rejects_non_four_digit_values() {
    let conn = db::open_in_memory().expect("schema should apply");
    assert!(matches!(
        set_pin(&conn, ResourceType::Credential, 1, "123", true, 300),
        Err(Error::InvalidPin)
    ));
    assert!(matches!(
        set_pin(&conn, ResourceType::Credential, 1, "abcd", true, 300),
        Err(Error::InvalidPin)
    ));
}

#[test]
fn has_pin_reflects_whether_one_is_configured() {
    let conn = db::open_in_memory().expect("schema should apply");
    assert!(!has_pin(&conn, ResourceType::Credential, 1).unwrap());

    set_pin(&conn, ResourceType::Credential, 1, "1234", true, 300).expect("set_pin should succeed");
    assert!(has_pin(&conn, ResourceType::Credential, 1).unwrap());
}
