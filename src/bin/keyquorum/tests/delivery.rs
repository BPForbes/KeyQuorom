use super::super::*;

fn party(label: &str) -> private_bridge::BridgePartyInput {
    let (_, encryption_public_key) = keys::generate_encryption_keypair();
    let (_, signing_public_key) = keys::generate_signing_keypair();
    private_bridge::BridgePartyInput {
        label: label.to_string(),
        encryption_public_key,
        signing_public_key: Some(signing_public_key),
    }
}

/// Two employees under one department manager: three stores, three envelopes.
fn roster() -> (
    Vec<private_bridge::BridgePartyInput>,
    Vec<private_bridge::BridgePartyInput>,
) {
    let members = vec![party("M.S.2"), party("M.S.3")];
    let mut manager = party("M.S");
    manager.signing_public_key = None;
    (members, vec![manager])
}

fn plan() -> private_bridge::PlannedCreation {
    let (members, supervisors) = roster();
    private_bridge::plan_create(None, None, &members, &supervisors, Some("M.S.2"))
        .expect("roster should plan")
}

fn package(label: &str, bytes: &[u8]) -> private_bridge::DeliveryPackage {
    private_bridge::DeliveryPackage {
        label: label.to_string(),
        role: private_bridge::PartyRole::Member,
        recipient_public_key: [1u8; 32],
        bytes: bytes.to_vec(),
    }
}

fn entries(dir: &Path) -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = fs::read_dir(dir)
        .expect("output dir should be readable")
        .map(|entry| entry.expect("dir entry").path())
        .collect();
    paths.sort();
    paths
}

#[test]
fn a_failed_commit_takes_its_delivery_files_with_it() {
    let dir = tempfile::tempdir().expect("tempdir");

    // The command's order: plan, write the envelopes, then commit. This
    // store has no schema, so the commit fails the way a locked database
    // or a rejected insert would.
    let planned = plan();
    let pending = write_delivery_packages(dir.path(), &planned.created.packages).expect("write");
    assert_eq!(entries(dir.path()).len(), 3);
    let unusable = Connection::open_in_memory().expect("connection");
    private_bridge::commit_planned_creation(&unusable, &planned).expect_err("no such table");
    drop(pending); // what `?` does on the commit line
    assert!(
        entries(dir.path()).is_empty(),
        "envelopes for a bridge that was never recorded must not survive"
    );

    // So the same command can simply be run again into the same directory.
    let conn = db::open_in_memory().expect("schema should apply");
    let planned = plan();
    let pending =
        write_delivery_packages(dir.path(), &planned.created.packages).expect("retry should write");
    private_bridge::commit_planned_creation(&conn, &planned).expect("commit");
    let written = pending.keep();
    assert_eq!(private_bridge::list(&conn, None).expect("list").len(), 1);
    assert_eq!(entries(dir.path()), written);
    for (pkg, path) in planned.created.packages.iter().zip(&written) {
        assert_eq!(path, &dir.path().join(format!("{}.kqpb", pkg.label)));
        assert_eq!(
            fs::read(path).expect("envelope should be readable"),
            pkg.bytes
        );
    }
}

#[test]
fn labels_that_collapse_to_one_file_name_write_nothing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let packages = vec![package("M.S 2", b"first"), package("M.S_2", b"second")];

    let err = write_delivery_packages(dir.path(), &packages).expect_err("names collide");
    assert!(
        matches!(&err, Error::AmbiguousDeliveryName(file) if file == "M.S_2.kqpb"),
        "unexpected error: {err}"
    );
    assert!(entries(dir.path()).is_empty());
}

#[test]
fn an_envelope_already_on_disk_rolls_back_the_ones_before_it() {
    let dir = tempfile::tempdir().expect("tempdir");
    let taken = dir.path().join("M.S.3.kqpb");
    fs::write(&taken, b"someone else's file").expect("seed the output dir");
    let packages = vec![package("M.S.2", b"first"), package("M.S.3", b"second")];

    write_delivery_packages(dir.path(), &packages).expect_err("refuses to overwrite");
    assert_eq!(entries(dir.path()), vec![taken.clone()]);
    assert_eq!(
        fs::read(&taken).expect("read"),
        b"someone else's file",
        "only files we created ourselves are cleaned up"
    );
}
