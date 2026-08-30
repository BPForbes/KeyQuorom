use super::*;
use crate::db;

#[test]
fn add_and_get_credential_roundtrip() {
    let conn = db::open_in_memory().expect("schema should apply");
    let id = add_credential(&conn, "Email", Some("bailey"), "s3cr3t", "master-pw")
        .expect("add_credential should succeed");

    let credential = get_credential(&conn, id, "master-pw").expect("get_credential should succeed");

    assert_eq!(credential.label, "Email");
    assert_eq!(credential.username.as_deref(), Some("bailey"));
    assert_eq!(credential.password, "s3cr3t");
}

#[test]
fn get_credential_fails_with_wrong_master_password() {
    let conn = db::open_in_memory().expect("schema should apply");
    let id = add_credential(&conn, "Email", None, "s3cr3t", "master-pw")
        .expect("add_credential should succeed");

    let result = get_credential(&conn, id, "wrong-master-pw");
    assert!(matches!(result, Err(Error::InvalidPassword)));
}
