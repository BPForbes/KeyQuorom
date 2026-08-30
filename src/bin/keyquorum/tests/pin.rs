use super::super::*;

#[test]
fn default_cli_pins_cache_successful_verification() {
    let conn = db::open_in_memory().expect("schema should apply");
    set_default_pin(&conn, ResourceType::Credential, 1, "1234")
        .expect("setting a default CLI PIN should succeed");

    pin::verify_pin(&conn, ResourceType::Credential, 1, "1234").expect("PIN should verify");
    assert!(
        !pin::verification_required(&conn, ResourceType::Credential, 1)
            .expect("verification state should be readable")
    );
}
