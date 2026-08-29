//! Command-line interface over the KeyQuorum library: hardware-key
//! registration, recursive key splitting, the password vault,
//! password-locked and hardware-key-quorum-protected files (unified under
//! `access`), signature verification, share links, and export bundles.
//!
//! Producing signatures, importing an export bundle, and turning a stored
//! quorum share back into raw bytes all need a private key this project
//! has no custody story for yet — see README's Roadmap. Nothing here
//! stubs those out; they simply aren't commands.

use clap::{Args, Parser, Subcommand, ValueEnum};
use keyquorum::error::{Error, Result};
use keyquorum::key_tree::{NodeSpec, TreeNodeSummary};
use keyquorum::keys::KeyType;
use keyquorum::pin::ResourceType;
use keyquorum::{db, export, key_tree, keys, locked_files, pin, quorum, sharing, signing, vault};
use rusqlite::Connection;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

/// How long a "one-time" PIN unlock stays valid before the PIN is needed
/// again (see `pin.rs`); not configurable via the CLI in this pass.
const PIN_TTL_SECONDS: i64 = 3600;

#[derive(Parser)]
#[command(
    name = "keyquorum",
    about = "KeyQuorum command-line interface",
    version
)]
struct Cli {
    /// Path to the KeyQuorum SQLite database
    #[arg(long, global = true, default_value = "keyquorum.sqlite")]
    db: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Manage password-vault credentials
    Vault {
        #[command(subcommand)]
        command: VaultCommand,
    },
    /// Register and manage hardware keys, and split/reconstruct keys
    Key {
        #[command(subcommand)]
        command: KeyCommand,
    },
    /// Lock (encrypt) or unlock (decrypt) a password- or quorum-protected file
    Access {
        #[command(subcommand)]
        command: AccessCommand,
    },
    /// Verify an Ed25519 signature
    Verify {
        #[arg(long)]
        public_key_file: PathBuf,
        #[arg(long)]
        message_file: PathBuf,
        #[arg(long)]
        signature_file: PathBuf,
    },
    /// Export a credential or file as a portable bundle for someone outside this database
    Export {
        #[command(subcommand)]
        command: ExportCommand,
    },
    /// Manage time-limited share links
    Share {
        #[command(subcommand)]
        command: ShareCommand,
    },
    /// Manage PIN unlock windows
    Pin {
        #[command(subcommand)]
        command: PinCommand,
    },
}

#[derive(Subcommand)]
enum VaultCommand {
    /// Store a new credential
    Add {
        label: String,
        #[arg(long)]
        username: Option<String>,
        /// Also protect this credential with a 4-digit PIN
        #[arg(long)]
        pin: bool,
    },
    /// Retrieve a stored credential
    Get { id: i64 },
}

#[derive(Clone, Copy, ValueEnum)]
enum CliKeyType {
    Encryption,
    Signing,
}

impl From<CliKeyType> for KeyType {
    fn from(value: CliKeyType) -> Self {
        match value {
            CliKeyType::Encryption => KeyType::Encryption,
            CliKeyType::Signing => KeyType::Signing,
        }
    }
}

#[derive(Subcommand)]
enum KeyCommand {
    /// Generate a keypair. The private key is printed to stdout ONCE and
    /// never written to disk by this tool; the public key is written to
    /// --public-key-out.
    Generate {
        #[arg(long = "type")]
        key_type: CliKeyType,
        #[arg(long)]
        public_key_out: PathBuf,
    },
    /// Register a public key
    Register {
        #[arg(long = "type")]
        key_type: CliKeyType,
        #[arg(long)]
        label: String,
        #[arg(long)]
        public_key_file: PathBuf,
    },
    /// List registered keys
    List,
    /// Revoke a registered key
    Revoke { id: i64 },
    /// Remove a registered key
    Remove { id: i64 },
    /// Split a fresh random secret per a tree-spec file (standalone escrow, no file involved)
    Split {
        #[arg(long)]
        tree_spec: PathBuf,
        #[arg(long)]
        label: String,
    },
    /// Print a key's split tree
    Tree { key_id: i64 },
    /// Reconstruct a key's secret from raw shares
    Reconstruct {
        key_id: i64,
        /// node_id=path-to-hex-encoded-raw-share (repeatable; node_id is a
        /// leaf's id as shown by `key tree`). Any leaf not covered here is
        /// prompted for interactively instead
        #[arg(long = "share-file")]
        share_files: Vec<String>,
    },
}

#[derive(Subcommand)]
enum AccessCommand {
    Password(AccessPasswordArgs),
    Quorum(AccessQuorumArgs),
}

#[derive(Args)]
struct AccessPasswordArgs {
    /// 0 = lock (encrypt), 1 = unlock (decrypt)
    #[arg(long, value_parser = clap::value_parser!(u8).range(0..=1))]
    state: u8,
    /// state 0 only: file to encrypt
    #[arg(long, required_if_eq("state", "0"), conflicts_with_all = ["id", "output"])]
    source: Option<PathBuf>,
    /// state 0 only: where to write the ciphertext
    #[arg(long, required_if_eq("state", "0"), conflicts_with_all = ["id", "output"])]
    encrypted_path: Option<PathBuf>,
    /// state 1 only: which locked file
    #[arg(long, required_if_eq("state", "1"), conflicts_with_all = ["source", "encrypted_path", "pin"])]
    id: Option<i64>,
    /// state 1 only: write plaintext here instead of stdout
    #[arg(long, conflicts_with_all = ["source", "encrypted_path", "pin"])]
    output: Option<PathBuf>,
    /// state 0: also protect with a 4-digit PIN. state 1: this file has a
    /// PIN and it's prompted for automatically — this flag is unused there.
    #[arg(long, conflicts_with_all = ["id", "output"])]
    pin: bool,
}

#[derive(Args)]
struct AccessQuorumArgs {
    /// 0 = lock (encrypt + split), 1 = unlock (reconstruct + decrypt)
    #[arg(long, value_parser = clap::value_parser!(u8).range(0..=1), conflicts_with = "status")]
    state: Option<u8>,
    /// Print the file's row and key-tree summary instead of locking/unlocking
    #[arg(long, conflicts_with_all = ["source", "encrypted_path", "tree_spec", "name", "share_files", "output"])]
    status: bool,
    /// state 0 only: file to encrypt
    #[arg(long, required_if_eq("state", "0"), conflicts_with_all = ["id", "share_files", "output"])]
    source: Option<PathBuf>,
    /// state 0 only: where to write the ciphertext
    #[arg(long, required_if_eq("state", "0"), conflicts_with_all = ["id", "share_files", "output"])]
    encrypted_path: Option<PathBuf>,
    /// state 0 only: tree-spec JSON describing how to split the data key
    #[arg(long, required_if_eq("state", "0"), conflicts_with_all = ["id", "share_files", "output"])]
    tree_spec: Option<PathBuf>,
    /// state 0 only: override the stored file name (defaults to source's file name)
    #[arg(long, conflicts_with_all = ["id", "share_files", "output"])]
    name: Option<String>,
    /// state 1 / --status: which quorum-protected file
    #[arg(long, required_if_eq("state", "1"), conflicts_with_all = ["source", "encrypted_path", "tree_spec", "name"])]
    id: Option<i64>,
    /// state 1 only: node_id=path-to-hex-encoded-raw-share (repeatable;
    /// node_id is a leaf's id as shown by `--status`)
    #[arg(long = "share-file", conflicts_with_all = ["source", "encrypted_path", "tree_spec", "name"])]
    share_files: Vec<String>,
    /// state 1 only: write plaintext here instead of stdout
    #[arg(long, conflicts_with_all = ["source", "encrypted_path", "tree_spec", "name"])]
    output: Option<PathBuf>,
}

#[derive(Subcommand)]
enum ExportCommand {
    /// Export a credential, sealed to a recipient's public key
    Credential {
        id: i64,
        #[arg(long)]
        recipient_key_file: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Export a password-locked file, sealed to a recipient's public key
    File {
        id: i64,
        #[arg(long)]
        recipient_key_file: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
}

#[derive(Subcommand)]
enum ShareCommand {
    /// Create a share link for a vault credential
    CreateCredential {
        credential_id: i64,
        #[arg(long, default_value_t = 3600, value_parser = parse_positive_i64)]
        ttl_seconds: i64,
        #[arg(long, value_parser = parse_positive_i64)]
        max_uses: Option<i64>,
        /// Also require a 4-digit PIN to redeem this share
        #[arg(long)]
        pin: bool,
        /// Require the PIN on every redemption rather than once per TTL window
        #[arg(long, requires = "pin")]
        pin_required_every_use: bool,
    },
    /// Create a share link for a password-locked file
    CreateFile {
        file_id: i64,
        #[arg(long, default_value_t = 3600, value_parser = parse_positive_i64)]
        ttl_seconds: i64,
        #[arg(long, value_parser = parse_positive_i64)]
        max_uses: Option<i64>,
        #[arg(long)]
        pin: bool,
        #[arg(long, requires = "pin")]
        pin_required_every_use: bool,
    },
    /// Redeem a credential share token (prompted interactively, never as an argument)
    RedeemCredential,
    /// Redeem a file share token (prompted interactively, never as an argument)
    RedeemFile,
    /// Revoke a credential share
    RevokeCredential { share_id: i64 },
    /// Revoke a file share
    RevokeFile { share_id: i64 },
}

#[derive(Clone, Copy, ValueEnum)]
enum CliResourceType {
    Credential,
    LockedFile,
    QuorumFile,
    CredentialShare,
    FileShare,
}

impl From<CliResourceType> for ResourceType {
    fn from(value: CliResourceType) -> Self {
        match value {
            CliResourceType::Credential => ResourceType::Credential,
            CliResourceType::LockedFile => ResourceType::LockedFile,
            CliResourceType::QuorumFile => ResourceType::QuorumFile,
            CliResourceType::CredentialShare => ResourceType::CredentialShare,
            CliResourceType::FileShare => ResourceType::FileShare,
        }
    }
}

#[derive(Subcommand)]
enum PinCommand {
    /// End a cached one-time PIN unlock window immediately
    Relock {
        #[arg(long, value_enum)]
        resource: CliResourceType,
        #[arg(long)]
        id: i64,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    match run(&cli.db, cli.command) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}

fn run(db_path: &Path, command: Command) -> Result<()> {
    let db_path_str = db_path.to_str().ok_or(Error::InvalidPath)?;
    let mut conn = db::open(db_path_str)?;

    match command {
        Command::Vault { command } => run_vault(&conn, command)?,
        Command::Key { command } => run_key(&mut conn, command)?,
        Command::Access { command } => run_access(&mut conn, command)?,
        Command::Verify {
            public_key_file,
            message_file,
            signature_file,
        } => {
            let public_key = read_hex_array_32(&public_key_file)?;
            let message = fs::read(&message_file)?;
            let signature = read_hex_array_64(&signature_file)?;
            signing::verify_signature(&public_key, &message, &signature)?;
            println!("Signature is valid");
        }
        Command::Export { command } => run_export(&conn, command)?,
        Command::Share { command } => run_share(&conn, command)?,
        Command::Pin { command } => run_pin(&conn, command)?,
    }

    Ok(())
}

fn run_vault(conn: &Connection, command: VaultCommand) -> Result<()> {
    match command {
        VaultCommand::Add {
            label,
            username,
            pin: set_pin_flag,
        } => {
            let password = prompt_secret("Credential password: ")?;
            let master_password = prompt_secret("Master password: ")?;
            let id = vault::add_credential(
                conn,
                &label,
                username.as_deref(),
                &password,
                &master_password,
            )?;
            if set_pin_flag {
                let pin_value = prompt_secret("Set a 4-digit PIN: ")?;
                set_default_pin(conn, ResourceType::Credential, id, &pin_value)?;
            }
            println!("Stored credential {id}");
        }
        VaultCommand::Get { id } => {
            if pin::verification_required(conn, ResourceType::Credential, id)? {
                let pin_value = prompt_secret("PIN: ")?;
                pin::verify_pin(conn, ResourceType::Credential, id, &pin_value)?;
            }
            let master_password = prompt_secret("Master password: ")?;
            let credential = vault::get_credential(conn, id, &master_password)?;
            println!("Label:    {}", credential.label);
            println!(
                "Username: {}",
                credential.username.as_deref().unwrap_or("-")
            );
            println!("Password: {}", credential.password);
        }
    }
    Ok(())
}

fn run_key(conn: &mut Connection, command: KeyCommand) -> Result<()> {
    match command {
        KeyCommand::Generate {
            key_type,
            public_key_out,
        } => {
            let (secret_key, public_key) = match key_type {
                CliKeyType::Encryption => keys::generate_encryption_keypair(),
                CliKeyType::Signing => keys::generate_signing_keypair(),
            };
            write_hex_file(&public_key_out, &public_key)?;
            println!("{}", hex::encode(*secret_key));
            eprintln!("Public key written to {}", public_key_out.display());
            eprintln!("Private key printed to stdout above — this tool keeps no copy of it.");
            eprintln!(
                "Register the public key with: keyquorum key register --type <encryption|signing> --label <text> --public-key-file {}",
                public_key_out.display()
            );
        }
        KeyCommand::Register {
            key_type,
            label,
            public_key_file,
        } => {
            let public_key = read_hex_bytes(&public_key_file)?;
            let id = keys::register_key(conn, &label, key_type.into(), &public_key)?;
            println!("Registered key {id}");
        }
        KeyCommand::List => {
            for key in keys::list_keys(conn)? {
                println!(
                    "{}\t{}\t{:?}\t{}\t{}",
                    key.id,
                    key.label,
                    key.key_type,
                    key.fingerprint,
                    key.revoked_at.as_deref().unwrap_or("-"),
                );
            }
        }
        KeyCommand::Revoke { id } => {
            keys::revoke_key(conn, id)?;
            println!("Revoked key {id}");
        }
        KeyCommand::Remove { id } => {
            keys::remove_key(conn, id)?;
            println!("Removed key {id}");
        }
        KeyCommand::Split { tree_spec, label } => {
            let spec = parse_tree_spec(&tree_spec)?;
            let secret = keyquorum::crypto::random_key();
            let key_id = key_tree::split(conn, &label, &secret[..], &spec)?;
            println!("{}", hex::encode(&secret[..]));
            eprintln!("Split key {key_id}; secret printed to stdout above — this tool keeps no copy of it.");
        }
        KeyCommand::Tree { key_id } => {
            let summary = key_tree::describe(conn, key_id)?;
            println!("{} (key {})", summary.label, summary.key_id);
            print_tree_node(&summary.root, 0);
        }
        KeyCommand::Reconstruct {
            key_id,
            share_files,
        } => {
            let summary = key_tree::describe(conn, key_id)?;
            let shares = collect_shares(&summary.root, &share_files)?;
            let secret = key_tree::reconstruct(conn, key_id, &shares)?;
            println!("{}", hex::encode(secret));
        }
    }
    Ok(())
}

fn run_access(conn: &mut Connection, command: AccessCommand) -> Result<()> {
    match command {
        AccessCommand::Password(args) => run_access_password(conn, args),
        AccessCommand::Quorum(args) => run_access_quorum(conn, args),
    }
}

fn run_access_password(conn: &Connection, args: AccessPasswordArgs) -> Result<()> {
    match args.state {
        0 => {
            let source = require(args.source, "source");
            let encrypted_path = require(args.encrypted_path, "encrypted-path");
            let password = prompt_secret("Lock password: ")?;
            let id = locked_files::lock_file(conn, &source, &encrypted_path, &password)?;
            if args.pin {
                let pin_value = prompt_secret("Set a 4-digit PIN: ")?;
                set_default_pin(conn, ResourceType::LockedFile, id, &pin_value)?;
            }
            println!("Locked file {id}");
        }
        1 => {
            let id = require(args.id, "id");
            if pin::verification_required(conn, ResourceType::LockedFile, id)? {
                let pin_value = prompt_secret("PIN: ")?;
                pin::verify_pin(conn, ResourceType::LockedFile, id, &pin_value)?;
            }
            let password = prompt_secret("Unlock password: ")?;
            let plaintext = locked_files::unlock_file(conn, id, &password)?;
            match args.output {
                Some(path) => locked_files::write_owner_only(&path, &plaintext)?,
                None => io::stdout().write_all(&plaintext)?,
            }
        }
        _ => fatal_usage_error("--state must be 0 (lock) or 1 (unlock)"),
    }
    Ok(())
}

fn run_access_quorum(conn: &mut Connection, args: AccessQuorumArgs) -> Result<()> {
    if args.status {
        let id = require(args.id, "id");
        let file_status = quorum::status(conn, id)?;
        println!("{} (file {})", file_status.name, file_status.id);
        println!("Encrypted path: {}", file_status.encrypted_path);
        println!("Created at:     {}", file_status.created_at);
        print_tree_node(&file_status.tree.root, 0);
        return Ok(());
    }

    match args.state {
        Some(0) => {
            let source = require(args.source, "source");
            let encrypted_path = require(args.encrypted_path, "encrypted-path");
            let tree_spec_path = require(args.tree_spec, "tree-spec");
            let spec = parse_tree_spec(&tree_spec_path)?;
            let id =
                quorum::lock_file(conn, &source, &encrypted_path, args.name.as_deref(), &spec)?;
            println!("Locked file {id}");
        }
        Some(1) => {
            let id = require(args.id, "id");
            let file_status = quorum::status(conn, id)?;
            let shares = collect_shares(&file_status.tree.root, &args.share_files)?;
            let plaintext = quorum::unlock_file(conn, id, &shares)?;
            match args.output {
                Some(path) => locked_files::write_owner_only(&path, &plaintext)?,
                None => io::stdout().write_all(&plaintext)?,
            }
        }
        _ => fatal_usage_error("--state must be 0 (lock) or 1 (unlock), or pass --status"),
    }
    Ok(())
}

fn run_export(conn: &Connection, command: ExportCommand) -> Result<()> {
    match command {
        ExportCommand::Credential {
            id,
            recipient_key_file,
            output,
        } => {
            let recipient_public_key = read_hex_array_32(&recipient_key_file)?;
            let master_password = prompt_secret("Master password: ")?;
            let bundle =
                export::export_credential(conn, id, &master_password, &recipient_public_key)?;
            locked_files::write_owner_only(&output, &bundle)?;
            println!("Exported credential {id} to {}", output.display());
        }
        ExportCommand::File {
            id,
            recipient_key_file,
            output,
        } => {
            let recipient_public_key = read_hex_array_32(&recipient_key_file)?;
            let password = prompt_secret("Unlock password: ")?;
            let bundle = export::export_file(conn, id, &password, &recipient_public_key)?;
            locked_files::write_owner_only(&output, &bundle)?;
            println!("Exported file {id} to {}", output.display());
        }
    }
    Ok(())
}

fn run_share(conn: &Connection, command: ShareCommand) -> Result<()> {
    match command {
        ShareCommand::CreateCredential {
            credential_id,
            ttl_seconds,
            max_uses,
            pin: set_pin_flag,
            pin_required_every_use,
        } => {
            let share =
                sharing::create_credential_share(conn, credential_id, ttl_seconds, max_uses)?;
            if set_pin_flag {
                let pin_value = prompt_secret("Set a 4-digit PIN for this share: ")?;
                pin::set_pin(
                    conn,
                    ResourceType::CredentialShare,
                    share.id,
                    &pin_value,
                    pin_required_every_use,
                    PIN_TTL_SECONDS,
                )?;
            }
            print_share(&share);
        }
        ShareCommand::CreateFile {
            file_id,
            ttl_seconds,
            max_uses,
            pin: set_pin_flag,
            pin_required_every_use,
        } => {
            let share = sharing::create_file_share(conn, file_id, ttl_seconds, max_uses)?;
            if set_pin_flag {
                let pin_value = prompt_secret("Set a 4-digit PIN for this share: ")?;
                pin::set_pin(
                    conn,
                    ResourceType::FileShare,
                    share.id,
                    &pin_value,
                    pin_required_every_use,
                    PIN_TTL_SECONDS,
                )?;
            }
            print_share(&share);
        }
        ShareCommand::RedeemCredential => {
            let token = prompt_secret("Credential share token: ")?;
            let share_id = sharing::credential_share_id_for_token(conn, &token)?;
            if pin::verification_required(conn, ResourceType::CredentialShare, share_id)? {
                let pin_value = prompt_secret("PIN: ")?;
                pin::verify_pin(conn, ResourceType::CredentialShare, share_id, &pin_value)?;
            }
            let credential_id = sharing::redeem_credential_share(conn, &token)?;
            println!("Redeemed credential {credential_id}");
        }
        ShareCommand::RedeemFile => {
            let token = prompt_secret("File share token: ")?;
            let share_id = sharing::file_share_id_for_token(conn, &token)?;
            if pin::verification_required(conn, ResourceType::FileShare, share_id)? {
                let pin_value = prompt_secret("PIN: ")?;
                pin::verify_pin(conn, ResourceType::FileShare, share_id, &pin_value)?;
            }
            let file_id = sharing::redeem_file_share(conn, &token)?;
            println!("Redeemed file {file_id}");
        }
        ShareCommand::RevokeCredential { share_id } => {
            sharing::revoke_credential_share(conn, share_id)?;
            println!("Revoked credential share {share_id}");
        }
        ShareCommand::RevokeFile { share_id } => {
            sharing::revoke_file_share(conn, share_id)?;
            println!("Revoked file share {share_id}");
        }
    }
    Ok(())
}

fn run_pin(conn: &Connection, command: PinCommand) -> Result<()> {
    match command {
        PinCommand::Relock { resource, id } => {
            pin::relock(conn, resource.into(), id)?;
            println!("Relocked PIN for resource {id}");
        }
    }
    Ok(())
}

fn print_share(share: &sharing::Share) {
    println!("Share id:   {}", share.id);
    println!("Token:      {}", share.token);
    println!("Expires at: {}", share.expires_at);
}

fn print_tree_node(node: &TreeNodeSummary, depth: usize) {
    let indent = "  ".repeat(depth);
    match &node.hardware_key_label {
        Some(label) => println!(
            "{indent}{} (node {}) -> hardware key {} ({label})",
            node.label,
            node.id,
            node.hardware_key_id.unwrap_or(-1)
        ),
        None => println!(
            "{indent}{} (node {}) [{} of {}]",
            node.label,
            node.id,
            node.threshold.unwrap_or(0),
            node.children.len()
        ),
    }
    for child in &node.children {
        print_tree_node(child, depth + 1);
    }
}

/// Gathers raw shares for every leaf in `root`: from `--share-file
/// node_id=path` entries first, falling back to a hidden prompt per
/// remaining leaf (blank entry = skip that leaf). Keyed by each leaf's own
/// `node_id` rather than its `hardware_key_id`, since the same hardware
/// key can legitimately back more than one leaf (e.g. present in two
/// different branches) — hardware_key_id alone can't tell those apart.
/// Never accepts a raw share as a literal argv value — individually a
/// share leaks nothing, but threshold-many together reconstruct the real
/// secret and would sit exposed in `ps` while the command runs.
fn collect_shares(root: &TreeNodeSummary, share_files: &[String]) -> Result<HashMap<i64, Vec<u8>>> {
    let mut leaves = Vec::new();
    collect_leaves(root, &mut leaves);
    let leaf_ids: HashSet<i64> = leaves.iter().map(|(node_id, _, _)| *node_id).collect();

    let mut by_node_id: HashMap<i64, Vec<u8>> = HashMap::new();
    for entry in share_files {
        let (node_id_str, path) = entry
            .split_once('=')
            .unwrap_or_else(|| fatal_usage_error("--share-file must be in the form node_id=path"));
        let node_id: i64 = node_id_str
            .parse()
            .unwrap_or_else(|_| fatal_usage_error("--share-file's node_id must be an integer"));
        if !leaf_ids.contains(&node_id) {
            fatal_usage_error(&format!(
                "--share-file references node {node_id}, which isn't a leaf in this tree \
                 (see `key tree`/`--status` for valid leaf node ids)"
            ));
        }
        if by_node_id.contains_key(&node_id) {
            fatal_usage_error(&format!(
                "--share-file for node {node_id} was given more than once"
            ));
        }
        let bytes = read_hex_bytes(Path::new(path))?;
        by_node_id.insert(node_id, bytes);
    }

    let mut shares = HashMap::new();
    for (node_id, hardware_key_id, label) in &leaves {
        if let Some(bytes) = by_node_id.remove(node_id) {
            shares.insert(*node_id, bytes);
            continue;
        }
        let prompt = format!(
            "Share for '{label}' (node {node_id}, hardware key {hardware_key_id}, hex, blank to skip): "
        );
        let entered = prompt_secret(&prompt)?;
        let trimmed = entered.trim();
        if !trimmed.is_empty() {
            let bytes = hex::decode(trimmed)
                .unwrap_or_else(|_| fatal_usage_error("share must be hex-encoded"));
            shares.insert(*node_id, bytes);
        }
    }

    Ok(shares)
}

fn collect_leaves(node: &TreeNodeSummary, out: &mut Vec<(i64, i64, String)>) {
    if let Some(hardware_key_id) = node.hardware_key_id {
        out.push((node.id, hardware_key_id, node.label.clone()));
    }
    for child in &node.children {
        collect_leaves(child, out);
    }
}

fn parse_tree_spec(path: &Path) -> Result<NodeSpec> {
    let contents = fs::read_to_string(path)?;
    serde_json::from_str(&contents).map_err(|_| Error::InvalidTreeSpec)
}

fn read_hex_bytes(path: &Path) -> Result<Vec<u8>> {
    let contents = fs::read_to_string(path)?;
    hex::decode(contents.trim()).map_err(|_| Error::InvalidPublicKey)
}

fn read_hex_array_32(path: &Path) -> Result<[u8; 32]> {
    read_hex_bytes(path)?
        .try_into()
        .map_err(|_| Error::InvalidPublicKey)
}

fn read_hex_array_64(path: &Path) -> Result<[u8; 64]> {
    read_hex_bytes(path)?
        .try_into()
        .map_err(|_| Error::InvalidPublicKey)
}

fn write_hex_file(path: &Path, bytes: &[u8]) -> Result<()> {
    locked_files::write_owner_only(path, hex::encode(bytes).as_bytes())
}

/// Prints `message` and exits immediately (clap's own convention: exit
/// code 2 for a usage error). Used for CLI-argument-shape problems — a
/// missing conditionally-required flag, a malformed `--share-file` value —
/// which are usage mistakes, not library/crypto/DB errors, so they don't
/// belong funneled through `keyquorum::error::Error`.
fn fatal_usage_error(message: &str) -> ! {
    eprintln!("error: {message}");
    std::process::exit(2);
}

fn require<T>(value: Option<T>, flag: &str) -> T {
    value.unwrap_or_else(|| {
        fatal_usage_error(&format!("--{flag} is required for this --state value"))
    })
}

fn prompt_secret(prompt: &str) -> Result<String> {
    rpassword::prompt_password(prompt).map_err(Error::from)
}

fn set_default_pin(
    conn: &Connection,
    resource_type: ResourceType,
    resource_id: i64,
    pin_value: &str,
) -> Result<()> {
    pin::set_pin(
        conn,
        resource_type,
        resource_id,
        pin_value,
        false,
        PIN_TTL_SECONDS,
    )
}

fn parse_positive_i64(value: &str) -> std::result::Result<i64, String> {
    let value = value
        .parse::<i64>()
        .map_err(|_| "must be a positive integer".to_owned())?;
    if value > 0 {
        Ok(value)
    } else {
        Err("must be greater than zero".to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn share_options_reject_unusable_limits() {
        for args in [
            [
                "keyquorum",
                "share",
                "create-file",
                "1",
                "--ttl-seconds",
                "0",
            ],
            ["keyquorum", "share", "create-file", "1", "--max-uses", "-1"],
        ] {
            assert!(Cli::try_parse_from(args).is_err());
        }
    }

    #[test]
    fn pin_every_use_requires_enabling_a_pin() {
        assert!(Cli::try_parse_from([
            "keyquorum",
            "share",
            "create-credential",
            "1",
            "--pin-required-every-use",
        ])
        .is_err());
    }

    #[test]
    fn quorum_status_rejects_mutating_options() {
        assert!(Cli::try_parse_from([
            "keyquorum",
            "access",
            "quorum",
            "--status",
            "--id",
            "1",
            "--output",
            "plaintext",
        ])
        .is_err());
    }

    #[test]
    fn access_modes_require_and_reject_mode_specific_options() {
        for args in [
            vec!["keyquorum", "access", "password", "--state", "0"],
            vec![
                "keyquorum",
                "access",
                "password",
                "--state",
                "1",
                "--id",
                "1",
                "--source",
                "plaintext",
            ],
            vec![
                "keyquorum",
                "access",
                "quorum",
                "--state",
                "0",
                "--source",
                "plaintext",
                "--encrypted-path",
                "ciphertext",
            ],
        ] {
            assert!(Cli::try_parse_from(args).is_err());
        }

        assert!(Cli::try_parse_from([
            "keyquorum",
            "access",
            "password",
            "--state",
            "1",
            "--id",
            "1",
            "--output",
            "plaintext",
        ])
        .is_ok());
    }

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
}
