//! Command-line interface over the KeyQuorum library: hardware-key
//! registration, recursive key splitting, the password vault,
//! password-locked and hardware-key-quorum-protected files (unified under
//! `access`), signature verification and private-bridge signing, share
//! links, and export bundles.
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
use keyquorum::{
    db, export, key_tree, keys, locked_files, pin, private_bridge, quorum, relay, sharing, signing,
    vault,
};
use rusqlite::Connection;
use std::collections::{BTreeSet, HashMap};
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
    /// Generate a keypair. The private key is printed to stdout ONCE and
    /// never written to disk by this tool; the public key is written to
    /// --public-key-out.
    Generate {
        #[arg(long = "type")]
        key_type: CliKeyType,
        #[arg(long)]
        public_key_out: PathBuf,
        /// Registry label. Required with --register.
        #[arg(long)]
        label: Option<String>,
        /// Register the new public key in the same step
        #[arg(long, requires = "label")]
        register: bool,
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
    /// List registered hardware keys and live split trees
    List,
    /// Revoke a registered key. Always drops that token's pairings and
    /// private-bridge membership on any live tree. Optional --evict
    /// PSS-refreshes the survivors.
    Revoke {
        /// Hardware key id from `list`
        id: i64,
        /// Split tree containing this key's leaf
        #[arg(long, requires = "node")]
        key_id: Option<i64>,
        /// Leaf label as shown by `tree` (must be backed by this hardware key)
        #[arg(long, requires = "key_id")]
        node: Option<String>,
        /// Evict that leaf and PSS-refresh remaining sibling shares
        #[arg(long)]
        evict: bool,
        /// Survivor key files (repeatable): a `.pub`/`.key`, PEM, or hex
        /// key. Each file unwraps that hardware key's leaf share. Every
        /// remaining active sibling must be supplied here or at the prompt.
        #[arg(long = "share-file", requires = "evict")]
        share_files: Vec<String>,
        /// Drop whitelist permission (and any pairing) from --node to this peer
        #[arg(long = "deny-peer", requires_all = ["key_id", "node"])]
        deny_peers: Vec<String>,
        /// Tear down an established pairing between --node and this peer
        #[arg(long = "remove-peer", requires_all = ["key_id", "node"])]
        remove_peers: Vec<String>,
    },
    /// Remove a registered hardware key
    Remove { id: i64 },
    /// Split a secret into the live tree. `--leaf` builds that tree;
    /// `--tree-spec` is only for a nested snapshot. Sibling leaves are
    /// bound automatically when `--leaf` is used.
    Split {
        /// Nested-tree snapshot JSON. Prefer `--leaf` for a new tree.
        #[arg(long, conflicts_with_all = ["leaves", "root", "generate_keys", "register"])]
        tree_spec: Option<PathBuf>,
        /// Label stored on the `keys` row (e.g. master)
        #[arg(long)]
        label: String,
        /// Root node label. Inferred from dotted `--leaf` labels (M.S +
        /// M.A → M), or defaults to --label.
        #[arg(long)]
        root: Option<String>,
        /// Quorum threshold among --leaf children (ignored with --tree-spec)
        #[arg(long)]
        threshold: Option<u8>,
        /// Child leaf as label=path-to-pub (repeatable), e.g.
        /// M.S=SoftwareDepartment.pub
        #[arg(long = "leaf")]
        leaves: Vec<String>,
        /// Extra pairing as label=peer (repeatable). `--leaf` already
        /// binds every sibling pair.
        #[arg(long = "bind")]
        binds: Vec<String>,
        /// `.pub`, `.key`, PEM, or OpenSSH file to escrow. Omit to split
        /// a fresh random secret (printed once as hex).
        #[arg(long)]
        source: Option<PathBuf>,
        /// Generate an encryption keypair for each --leaf pub path
        #[arg(long, requires = "leaves")]
        generate_keys: bool,
        /// Register each --leaf public key (leaf label is the registry label)
        #[arg(long, requires = "leaves")]
        register: bool,
    },
    /// Pair two nodes, or reseal a leaf onto a new public key
    Bind {
        key_id: i64,
        #[arg(long)]
        node: String,
        /// Establish `node <-> peer` on the live tree
        #[arg(long, conflicts_with = "public_key_file")]
        peer: Option<String>,
        /// Rebind --node to this public key (node id unchanged)
        #[arg(long, conflicts_with = "peer")]
        public_key_file: Option<PathBuf>,
        /// Old key file that unwraps --node before a rebind
        #[arg(long = "share-file", requires = "public_key_file")]
        share_file: Option<String>,
        /// Register --public-key-file if it is not already in the registry
        #[arg(long, requires = "public_key_file")]
        register: bool,
    },
    /// Insert a leaf under a parent split and reshare that parent
    Add {
        key_id: i64,
        #[arg(long)]
        parent: String,
        /// New leaf label (e.g. M.F)
        #[arg(long)]
        node: String,
        #[arg(long)]
        public_key_file: PathBuf,
        /// Key files that recover the parent (repeatable)
        #[arg(long = "share-file")]
        share_files: Vec<String>,
        /// Generate a keypair at --public-key-file (.pub and sibling .key)
        #[arg(long)]
        generate_keys: bool,
        /// Register --public-key-file (uses --node as the registry label)
        #[arg(long)]
        register: bool,
    },
    /// Print live split trees, one tree, the LCA of --node labels, or
    /// write the live spec JSON
    Tree {
        /// Split-tree id from `list` / `split`. Omit to list every tree.
        key_id: Option<i64>,
        /// Two or more node labels or key files: print their lowest
        /// common ancestor instead of the full tree
        #[arg(long = "node", num_args = 2.., requires = "key_id")]
        nodes: Vec<String>,
        /// Write a snapshot of the live tree (active nodes and binds)
        #[arg(long, conflicts_with = "nodes", requires = "key_id")]
        output: Option<PathBuf>,
    },
    /// Reconstruct a key's secret from raw shares
    Reconstruct {
        key_id: i64,
        /// Start reconstruction at the LCA of these labels or key files
        /// (`M.A` / `AccountingDepartment.pub`). Omit to reconstruct from
        /// the root.
        #[arg(long = "node", num_args = 2..)]
        nodes: Vec<String>,
        /// Key file that unwraps a leaf share (repeatable): `.pub`, `.key`,
        /// PEM, or hex. Any leaf not covered here is prompted for instead.
        #[arg(long = "share-file")]
        share_files: Vec<String>,
        /// Write the reassembled secret as raw file bytes (a `.pub` comes
        /// back as the original file). Omit to print hex on stdout.
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Manage cross-branch whitelist entries and established pairings
    Bridge {
        #[command(subcommand)]
        command: BridgeCommand,
    },
    /// Lock (encrypt) or unlock (decrypt) a password- or quorum-protected file
    Access {
        #[command(subcommand)]
        command: AccessCommand,
    },
    /// Verify an Ed25519 signature (standalone or private-bridge)
    Verify {
        #[arg(long, required_unless_present = "bridge_uid")]
        public_key_file: Option<PathBuf>,
        #[arg(long)]
        message_file: PathBuf,
        #[arg(long)]
        signature_file: PathBuf,
        /// Private-bridge uid (KQBS artifact + membership check)
        #[arg(long)]
        bridge_uid: Option<String>,
        /// Local member verifying the artifact
        #[arg(long, requires = "bridge_uid")]
        as_node: Option<String>,
    },
    /// Sign a message with a private bridge plus a personal signing key
    Sign {
        #[arg(long)]
        bridge_uid: String,
        /// Local member label
        #[arg(long)]
        node: String,
        #[arg(long)]
        signing_key_file: PathBuf,
        /// Encryption private key that unwraps this store's sealed bridge secret
        #[arg(long)]
        share_file: String,
        #[arg(long)]
        message_file: PathBuf,
        #[arg(long)]
        signature_out: PathBuf,
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
    /// Push and pull opaque .kqpb envelopes through the mailbox relay
    Relay {
        #[command(subcommand)]
        command: RelayCommand,
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
enum BridgeCommand {
    /// Grant --node permission to form a cross-branch link with --peer
    Allow {
        key_id: i64,
        #[arg(long)]
        node: String,
        #[arg(long)]
        peer: String,
    },
    /// Revoke that permission and drop any established link between them
    Deny {
        key_id: i64,
        #[arg(long)]
        node: String,
        #[arg(long)]
        peer: String,
    },
    /// Establish a pairing if either node's whitelist allows it
    Add {
        key_id: i64,
        #[arg(long)]
        from: String,
        #[arg(long)]
        to: String,
    },
    /// Tear down an established pairing (whitelist is left intact)
    Remove {
        key_id: i64,
        #[arg(long)]
        from: String,
        #[arg(long)]
        to: String,
    },
    /// List whitelist entries and established pairings
    List { key_id: i64 },
    /// N-member private sign bridges. Each person (and each department
    /// manager parent) has their own store; this command writes per-recipient
    /// packages instead of sharing sealed secrets in one database.
    Private {
        #[command(subcommand)]
        command: PrivateBridgeCommand,
    },
}

#[derive(Subcommand)]
enum PrivateBridgeCommand {
    /// Create a private sign bridge. Writes every .kqpb envelope first,
    /// then commits this store. Either both land or neither does, so a
    /// failure at any point can simply be retried.
    Create {
        key_id: i64,
        /// Signing member as LABEL or LABEL=pub-file (repeatable).
        /// Each label must already have a registered signing public key.
        #[arg(long = "member", required = true)]
        members: Vec<String>,
        /// Department/CXO supervisor as LABEL or LABEL=pub-file.
        /// Direct parents of --member are required (M.S.2 implies M.S).
        #[arg(long = "supervisor")]
        supervisors: Vec<String>,
        /// Local node whose sealed copy stays in this database
        #[arg(long = "self")]
        self_node: Option<String>,
        /// Directory for per-recipient .kqpb packages
        #[arg(long)]
        output_dir: PathBuf,
        #[arg(long)]
        label: Option<String>,
    },
    /// List private bridges (optionally for one split tree)
    List {
        #[arg(long)]
        key_id: Option<i64>,
    },
    /// Show one private bridge by uid
    Show { uid: String },
    /// Print bridge-change events
    Events {
        #[arg(long)]
        uid: Option<String>,
        #[arg(long)]
        since: Option<i64>,
    },
    /// Import a per-person package into this store
    Import {
        #[arg(long)]
        file: PathBuf,
        /// Encryption private key that opens this package
        #[arg(long)]
        share_file: String,
    },
    /// Drop a signing member. Writes rotation/destroy packages first,
    /// then commits. Either both land or neither does, so a failure at
    /// any point can simply be retried.
    RemoveMember {
        uid: String,
        /// Member label to remove
        #[arg(long)]
        member: String,
        /// Local remaining member that holds the sealed bridge secret
        #[arg(long)]
        node: String,
        #[arg(long)]
        share_file: String,
        #[arg(long)]
        output_dir: PathBuf,
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
    #[arg(long, conflicts_with_all = ["source", "encrypted_path", "tree_spec", "leaves", "name", "share_files", "output"])]
    status: bool,
    /// state 0 only: file to encrypt
    #[arg(long, required_if_eq("state", "0"), conflicts_with_all = ["id", "share_files", "output"])]
    source: Option<PathBuf>,
    /// state 0 only: where to write the ciphertext
    #[arg(long, required_if_eq("state", "0"), conflicts_with_all = ["id", "share_files", "output"])]
    encrypted_path: Option<PathBuf>,
    /// state 0 only: nested-tree snapshot JSON. Prefer `--leaf`.
    #[arg(long, conflicts_with_all = ["id", "share_files", "output", "leaves"])]
    tree_spec: Option<PathBuf>,
    /// state 0 only: child leaf as label=path-to-pub (repeatable)
    #[arg(long = "leaf", conflicts_with_all = ["id", "share_files", "output", "tree_spec"])]
    leaves: Vec<String>,
    /// Root node label for `--leaf` (inferred from dotted labels)
    #[arg(long, requires = "leaves")]
    root: Option<String>,
    /// Quorum threshold among `--leaf` children
    #[arg(long, requires = "leaves")]
    threshold: Option<u8>,
    /// Extra pairing as label=peer (repeatable)
    #[arg(long = "bind", requires = "leaves")]
    binds: Vec<String>,
    /// Generate an encryption keypair for each --leaf pub path
    #[arg(long, requires = "leaves")]
    generate_keys: bool,
    /// Register each --leaf public key
    #[arg(long, requires = "leaves")]
    register: bool,
    /// state 0 only: override the stored file name (defaults to source's file name)
    #[arg(long, conflicts_with_all = ["id", "share_files", "output"])]
    name: Option<String>,
    /// state 1 / --status: which quorum-protected file
    #[arg(long, required_if_eq("state", "1"), conflicts_with_all = ["source", "encrypted_path", "tree_spec", "leaves", "name"])]
    id: Option<i64>,
    /// state 1 only: key file that unwraps a leaf share (repeatable):
    /// `.pub`, `.key`, PEM, or hex. Any leaf not covered is prompted for.
    #[arg(long = "share-file", conflicts_with_all = ["source", "encrypted_path", "tree_spec", "leaves", "name"])]
    share_files: Vec<String>,
    /// state 1 only: write plaintext here instead of stdout
    #[arg(long, conflicts_with_all = ["source", "encrypted_path", "tree_spec", "leaves", "name"])]
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

#[derive(Subcommand)]
enum RelayCommand {
    /// Upload every `.kqpb` in a directory to the relay inbox
    Push {
        /// Directory containing `.kqpb` envelopes
        #[arg(long)]
        dir: PathBuf,
        /// Relay base URL (or KEYQUORUM_RELAY_URL)
        #[arg(long)]
        url: Option<String>,
        /// Push-scope API key (or KEYQUORUM_RELAY_API_KEY, or a prompt)
        #[arg(long)]
        api_key: Option<String>,
    },
    /// Download envelopes for this device's pull-scope API key
    Pull {
        /// Import each envelope into --db using --share-file
        #[arg(long, requires = "share_file")]
        import: bool,
        /// Encryption private key that opens the envelopes
        #[arg(long, requires = "import")]
        share_file: Option<String>,
        /// Write retrieved envelopes here (required unless --import)
        #[arg(long, required_unless_present = "import")]
        output_dir: Option<PathBuf>,
        #[arg(long)]
        url: Option<String>,
        #[arg(long)]
        api_key: Option<String>,
        /// Only envelopes with id greater than this
        #[arg(long)]
        after: Option<i64>,
    },
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
    if let Command::Relay { command } = command {
        return run_relay(db_path, command);
    }

    let db_path_str = db_path.to_str().ok_or(Error::InvalidPath)?;
    let mut conn = db::open(db_path_str)?;

    match command {
        Command::Vault { command } => run_vault(&conn, command)?,
        Command::Access { command } => run_access(&mut conn, command)?,
        Command::Generate { .. }
        | Command::Register { .. }
        | Command::List
        | Command::Revoke { .. }
        | Command::Remove { .. }
        | Command::Split { .. }
        | Command::Bind { .. }
        | Command::Add { .. }
        | Command::Tree { .. }
        | Command::Reconstruct { .. }
        | Command::Bridge { .. } => run_tree_command(&mut conn, command)?,
        Command::Verify {
            public_key_file,
            message_file,
            signature_file,
            bridge_uid,
            as_node,
        } => {
            let message = fs::read(&message_file)?;
            if let Some(uid) = bridge_uid {
                let as_node = as_node
                    .unwrap_or_else(|| fatal_usage_error("verify --bridge-uid requires --as-node"));
                let bytes = fs::read(&signature_file)?;
                let artifact = signing::decode_bridge_signature(&bytes)?;
                private_bridge::verify_message(&conn, &uid, &as_node, &message, &artifact)?;
                println!("Private-bridge signature is valid");
            } else {
                let public_key_file = public_key_file.unwrap_or_else(|| {
                    fatal_usage_error("verify requires --public-key-file or --bridge-uid")
                });
                let public_key = read_key_array_32(&public_key_file)?;
                let signature = read_hex_array_64(&signature_file)?;
                signing::verify_signature(&public_key, &message, &signature)?;
                println!("Signature is valid");
            }
        }
        Command::Sign {
            bridge_uid,
            node,
            signing_key_file,
            share_file,
            message_file,
            signature_out,
        } => {
            let encryption_sk = zeroize::Zeroizing::new(read_key_array_32(Path::new(&share_file))?);
            let signing_sk = zeroize::Zeroizing::new(read_key_array_32(&signing_key_file)?);
            let message = fs::read(&message_file)?;
            let artifact = private_bridge::sign_message(
                &conn,
                &bridge_uid,
                &node,
                &encryption_sk,
                &signing_sk,
                &message,
            )?;
            locked_files::write_owner_only(
                &signature_out,
                &signing::encode_bridge_signature(&artifact)?,
            )?;
            println!("Wrote bridge signature to {}", signature_out.display());
        }
        Command::Export { command } => run_export(&conn, command)?,
        Command::Share { command } => run_share(&conn, command)?,
        Command::Pin { command } => run_pin(&conn, command)?,
        Command::Relay { .. } => {
            unreachable!("relay commands are handled before opening the org db")
        }
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

fn run_tree_command(conn: &mut Connection, command: Command) -> Result<()> {
    match command {
        Command::Generate {
            key_type,
            public_key_out,
            label,
            register,
        } => {
            let (secret_key, public_key) = match key_type {
                CliKeyType::Encryption => keys::generate_encryption_keypair(),
                CliKeyType::Signing => keys::generate_signing_keypair(),
            };
            write_hex_file(&public_key_out, &public_key)?;
            println!("{}", hex::encode(*secret_key));
            eprintln!("Public key written to {}", public_key_out.display());
            eprintln!("Private key printed to stdout above — this tool keeps no copy of it.");
            if register {
                let label = label.expect("--register requires --label");
                let id = keys::register_key(conn, &label, key_type.into(), &public_key)?;
                eprintln!("Registered {label} as hardware key {id}");
            } else {
                eprintln!(
                    "Register the public key with: keyquorum register --type <encryption|signing> --label <text> --public-key-file {}",
                    public_key_out.display()
                );
            }
        }
        Command::Register {
            key_type,
            label,
            public_key_file,
        } => {
            let public_key = read_key_bytes(&public_key_file)?;
            let id = keys::register_key(conn, &label, key_type.into(), &public_key)?;
            println!("Registered key {id}");
        }
        Command::List => {
            println!("Hardware keys:");
            let hardware = keys::list_keys(conn)?;
            if hardware.is_empty() {
                println!("  (none)");
            } else {
                for key in hardware {
                    println!(
                        "  {}\t{}\t{:?}\t{}\t{}",
                        key.id,
                        key.label,
                        key.key_type,
                        key.fingerprint,
                        key.revoked_at.as_deref().unwrap_or("-"),
                    );
                }
            }
            println!("Split trees:");
            let trees = key_tree::list_trees(conn)?;
            if trees.is_empty() {
                println!("  (none)");
            } else {
                for tree in trees {
                    println!("  {}\t{}", tree.key_id, tree.label);
                }
            }
        }
        Command::Revoke {
            id,
            key_id,
            node,
            evict,
            share_files,
            deny_peers,
            remove_peers,
        } => {
            apply_hardware_revoke(
                conn,
                HardwareRevokeArgs {
                    hardware_id: id,
                    key_id,
                    node_label: node.as_deref(),
                    evict,
                    share_files: &share_files,
                    deny_peers: &deny_peers,
                    remove_peers: &remove_peers,
                },
            )?;
        }
        Command::Remove { id } => {
            keys::remove_key(conn, id)?;
            println!("Removed key {id}");
        }
        Command::Split {
            tree_spec,
            label,
            root,
            threshold,
            leaves,
            binds,
            source,
            generate_keys,
            register,
        } => {
            let from_leaves = tree_spec.is_none();
            let spec = match tree_spec {
                Some(path) => parse_tree_spec(conn, &path)?,
                None => {
                    if leaves.is_empty() {
                        fatal_usage_error(
                            "split requires --leaf label=pub (repeatable) or --tree-spec FILE",
                        );
                    }
                    build_spec_from_leaves(
                        conn,
                        &label,
                        root.as_deref(),
                        threshold.unwrap_or(2),
                        &leaves,
                        generate_keys,
                        register,
                    )?
                }
            };
            let key_id = match source {
                Some(path) => {
                    let secret = read_key_file_payload(&path)?;
                    let key_id = key_tree::split(conn, &label, &secret, &spec)?;
                    eprintln!(
                        "Split key {key_id} from {}; reconstruct with --output to write the file back.",
                        path.display()
                    );
                    key_id
                }
                None => {
                    let secret = keyquorum::crypto::random_key();
                    let key_id = key_tree::split(conn, &label, &secret[..], &spec)?;
                    println!("{}", hex::encode(&secret[..]));
                    eprintln!("Split key {key_id}; secret printed to stdout above — this tool keeps no copy of it.");
                    key_id
                }
            };
            if from_leaves {
                key_tree::bind_all_sibling_leaf_pairs(conn, key_id)?;
            }
            for (a, b) in parse_bind_pairs(&binds)? {
                key_tree::bind_pair(conn, key_id, &a, &b)?;
            }
        }
        Command::Bind {
            key_id,
            node,
            peer,
            public_key_file,
            share_file,
            register,
        } => match (peer, public_key_file) {
            (Some(peer), None) => {
                key_tree::bind_pair(conn, key_id, &node, &peer)?;
                println!("Bound {node} <-> {peer}");
            }
            (None, Some(public_key_file)) => {
                let share_file = share_file.unwrap_or_else(|| {
                    fatal_usage_error("bind --public-key-file requires --share-file")
                });
                let new_id =
                    resolve_or_register_pub(conn, &node, &public_key_file, false, register)?;
                let old_secret = secret_for_named_leaf(conn, key_id, &node, &share_file)?;
                key_tree::rebind_leaf(conn, key_id, &node, new_id, old_secret.as_ref())?;
                println!("Rebound {node} to hardware key {new_id}");
            }
            _ => fatal_usage_error("bind requires --peer or --public-key-file"),
        },
        Command::Add {
            key_id,
            parent,
            node,
            public_key_file,
            share_files,
            generate_keys,
            register,
        } => {
            let hw_id =
                resolve_or_register_pub(conn, &node, &public_key_file, generate_keys, register)?;
            let summary = key_tree::describe(conn, key_id)?;
            let parent_node = find_tree_node(&summary.root, &parent).ok_or(Error::NodeNotFound)?;
            let shares = collect_shares(conn, parent_node, &share_files)?;
            let new_id =
                key_tree::add_leaf_and_reshare(conn, key_id, &parent, &node, hw_id, &shares)?;
            key_tree::bind_leaf_to_active_siblings(conn, key_id, &node)?;
            println!("Added {node} (node {new_id}); parent shares refreshed");
        }
        Command::Tree {
            key_id,
            nodes,
            output,
        } => match key_id {
            None => {
                let trees = key_tree::list_trees(conn)?;
                if trees.is_empty() {
                    println!("(no split trees)");
                } else {
                    for tree in trees {
                        println!("{}\t{}", tree.key_id, tree.label);
                    }
                }
            }
            Some(key_id) if nodes.is_empty() => {
                let summary = key_tree::describe(conn, key_id)?;
                println!("{} (key {})", summary.label, summary.key_id);
                print_tree_node(&summary.root, 0);
                if let Some(path) = output {
                    write_live_spec(conn, key_id, &path)?;
                }
            }
            Some(key_id) => print_lca(conn, key_id, &nodes)?,
        },
        Command::Reconstruct {
            key_id,
            nodes,
            share_files,
            output,
        } => {
            let summary = key_tree::describe(conn, key_id)?;
            let shares = collect_shares(conn, &summary.root, &share_files)?;
            let secret = if nodes.is_empty() {
                key_tree::reconstruct(conn, key_id, &shares)?
            } else {
                let tree = key_tree::KeyQuorumTree::load(conn, key_id)?;
                let mut indices = Vec::with_capacity(nodes.len());
                for token in &nodes {
                    indices.push(resolve_node_index(conn, &tree, token)?);
                }
                let lca_idx = tree.find_lowest_common_ancestor_of(&indices)?;
                key_tree::reconstruct_from_lca(conn, key_id, lca_idx, &shares)?
            };
            write_reassembled_secret(&secret, output.as_deref())?;
        }
        Command::Bridge { command } => run_bridge(conn, command)?,
        Command::Vault { .. }
        | Command::Access { .. }
        | Command::Verify { .. }
        | Command::Sign { .. }
        | Command::Export { .. }
        | Command::Share { .. }
        | Command::Pin { .. }
        | Command::Relay { .. } => unreachable!("non-tree commands are dispatched in run()"),
    }
    Ok(())
}

fn run_bridge(conn: &Connection, command: BridgeCommand) -> Result<()> {
    match command {
        BridgeCommand::Allow { key_id, node, peer } => {
            key_tree::allow_bridge(conn, key_id, &node, &peer)?;
            println!("Allowed {node} to bridge to {peer}");
        }
        BridgeCommand::Deny { key_id, node, peer } => {
            key_tree::deny_bridge(conn, key_id, &node, &peer)?;
            println!("Denied {node} bridging to {peer}");
        }
        BridgeCommand::Add { key_id, from, to } => {
            key_tree::add_bridge(conn, key_id, &from, &to)?;
            println!("Established bridge {from} <-> {to}");
        }
        BridgeCommand::Remove { key_id, from, to } => {
            key_tree::remove_bridge(conn, key_id, &from, &to)?;
            println!("Removed bridge {from} <-> {to}");
        }
        BridgeCommand::List { key_id } => {
            let listing = key_tree::list_bridges(conn, key_id)?;
            println!("Allowed:");
            if listing.allowed.is_empty() {
                println!("  (none)");
            } else {
                for (node, peer) in listing.allowed {
                    println!("  {node} -> {peer}");
                }
            }
            println!("Established:");
            if listing.established.is_empty() {
                println!("  (none)");
            } else {
                for link in listing.established {
                    println!("  {} <-> {}", link.from, link.to);
                }
            }
        }
        BridgeCommand::Private { command } => run_private_bridge(conn, command)?,
    }
    Ok(())
}

fn run_private_bridge(conn: &Connection, command: PrivateBridgeCommand) -> Result<()> {
    match command {
        PrivateBridgeCommand::Create {
            key_id,
            members,
            supervisors,
            self_node,
            output_dir,
            label,
        } => {
            let member_parties = resolve_parties(conn, Some(key_id), &members, true)?;
            let mut supervisor_parties = resolve_parties(conn, Some(key_id), &supervisors, false)?;
            let member_labels: Vec<String> =
                member_parties.iter().map(|p| p.label.clone()).collect();
            for notify in private_bridge::notify_labels(member_labels.iter().map(|s| s.as_str())) {
                if member_parties.iter().any(|p| p.label == notify) {
                    continue;
                }
                if supervisor_parties.iter().any(|p| p.label == notify) {
                    continue;
                }
                let pk = match private_bridge::encryption_public_for_label(
                    conn,
                    Some(key_id),
                    &notify,
                ) {
                    Ok(pk) => pk,
                    Err(_) => fatal_usage_error(&format!(
                        "need an encryption public key for supervisor {notify} (parent of a --member). Pass --supervisor {notify}=FILE.pub"
                    )),
                };
                supervisor_parties.push(private_bridge::BridgePartyInput {
                    label: notify,
                    encryption_public_key: pk,
                    signing_public_key: None,
                });
            }
            fs::create_dir_all(&output_dir)?;
            let planned = private_bridge::plan_create(
                Some(key_id),
                label.as_deref(),
                &member_parties,
                &supervisor_parties,
                self_node.as_deref(),
            )?;
            let pending = write_delivery_packages(&output_dir, &planned.created.packages)?;
            // A commit failure here drops `pending`, deleting the envelopes:
            // they name a bridge this store did not record, and leaving them
            // would make `create` fail on retry with "file exists".
            private_bridge::commit_planned_creation(conn, &planned)?;
            let written = pending.keep();
            let created = &planned.created;
            println!(
                "Created private bridge {} (generation {}). Notify {} store(s):",
                created.uid,
                created.generation,
                created.packages.len()
            );
            for (pkg, path) in created.packages.iter().zip(&written) {
                println!("  {} ({:?}) -> {}", pkg.label, pkg.role, path.display());
            }
        }
        PrivateBridgeCommand::List { key_id } => {
            let listing = private_bridge::list(conn, key_id)?;
            if listing.is_empty() {
                println!("(no private bridges)");
            } else {
                for bridge in listing {
                    let status = if bridge.destroyed {
                        "destroyed"
                    } else {
                        "live"
                    };
                    println!(
                        "{}\tgen {}\t{}\t{}",
                        bridge.uid,
                        bridge.generation,
                        status,
                        bridge.label.as_deref().unwrap_or("-")
                    );
                }
            }
        }
        PrivateBridgeCommand::Show { uid } => {
            print_bridge_summary(&private_bridge::get(conn, &uid)?);
        }
        PrivateBridgeCommand::Events { uid, since } => {
            let events = private_bridge::events(conn, uid.as_deref(), since)?;
            if events.is_empty() {
                println!("(no events)");
            } else {
                for event in events {
                    println!(
                        "{}\t{}\t{}\t{}",
                        event.id, event.uid, event.event_type, event.detail
                    );
                }
            }
        }
        PrivateBridgeCommand::Import { file, share_file } => {
            let bytes = fs::read(&file)?;
            let sk = zeroize::Zeroizing::new(read_key_array_32(Path::new(&share_file))?);
            let summary = private_bridge::import_package(conn, &bytes, &sk)?;
            println!("Imported private bridge {}", summary.uid);
            print_bridge_summary(&summary);
        }
        PrivateBridgeCommand::RemoveMember {
            uid,
            member,
            node,
            share_file,
            output_dir,
        } => {
            let sk = zeroize::Zeroizing::new(read_key_array_32(Path::new(&share_file))?);
            fs::create_dir_all(&output_dir)?;
            let planned = private_bridge::plan_remove_member(conn, &uid, &member, &node, &sk)?;
            let pending = write_delivery_packages(&output_dir, &planned.outcome.packages)?;
            // As in `create`: if the commit fails, this store stays on the old
            // generation, so the rotation envelopes must go with it.
            private_bridge::commit_planned_removal(conn, &planned)?;
            let written = pending.keep();
            let outcome = &planned.outcome;
            if outcome.destroyed {
                println!("Destroyed private bridge {uid}");
            } else {
                println!(
                    "Removed {member} from {uid}; remaining {}",
                    outcome.remaining_members.join(", ")
                );
            }
            println!("Deliver these packages to each store:");
            for (pkg, path) in outcome.packages.iter().zip(&written) {
                println!("  {} ({:?}) -> {}", pkg.label, pkg.role, path.display());
            }
        }
    }
    Ok(())
}

fn resolve_parties(
    conn: &Connection,
    key_id: Option<i64>,
    specs: &[String],
    require_signing: bool,
) -> Result<Vec<private_bridge::BridgePartyInput>> {
    let mut out = Vec::new();
    for spec in specs {
        let (label, pk) = if let Some((label, path)) = spec.split_once('=') {
            (label.to_string(), read_key_array_32(Path::new(path))?)
        } else {
            (
                spec.clone(),
                private_bridge::encryption_public_for_label(conn, key_id, spec)?,
            )
        };
        let signing_public_key = if require_signing {
            Some(private_bridge::signing_public_for_label(conn, &label)?)
        } else {
            None
        };
        out.push(private_bridge::BridgePartyInput {
            label,
            encryption_public_key: pk,
            signing_public_key,
        });
    }
    Ok(out)
}

/// Delivery envelopes written to disk ahead of the database commit they
/// belong to.
///
/// `write_owner_only` refuses to overwrite an existing file, so envelopes
/// left behind by a commit that failed after the write would block the very
/// retry that failure calls for — and they describe a bridge this store
/// never recorded, so they must not be delivered either. Dropping this
/// guard without [`PendingDelivery::keep`] deletes every file it created,
/// and only those.
#[must_use = "the delivery files are removed unless the commit calls keep()"]
#[derive(Debug)]
struct PendingDelivery {
    paths: Vec<PathBuf>,
}

impl PendingDelivery {
    /// The commit succeeded: hand back the paths and leave them on disk.
    fn keep(mut self) -> Vec<PathBuf> {
        std::mem::take(&mut self.paths)
    }
}

impl Drop for PendingDelivery {
    fn drop(&mut self) {
        for path in &self.paths {
            let _ = fs::remove_file(path);
        }
    }
}

/// Writes one owner-only `.kqpb` per package into `output_dir`. The caller
/// commits and then calls `keep()` on the returned guard; anything else —
/// an error here, a failed commit, an early return — removes the files
/// again so the command can simply be run once more.
fn write_delivery_packages(
    output_dir: &Path,
    packages: &[private_bridge::DeliveryPackage],
) -> Result<PendingDelivery> {
    let mut planned = Vec::with_capacity(packages.len());
    let mut claimed: BTreeSet<String> = BTreeSet::new();
    for pkg in packages {
        let name = sanitize_label(&pkg.label)?;
        let file = format!("{name}.kqpb");
        if !claimed.insert(name) {
            return Err(Error::AmbiguousDeliveryName(file));
        }
        planned.push((output_dir.join(file), pkg.bytes.as_slice()));
    }

    let mut pending = PendingDelivery { paths: Vec::new() };
    for (path, bytes) in planned {
        locked_files::write_owner_only(&path, bytes)?;
        pending.paths.push(path);
    }
    Ok(pending)
}

fn sanitize_label(label: &str) -> Result<String> {
    let mut out = String::with_capacity(label.len());
    for ch in label.chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_') {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() || out.chars().all(|c| c == '.') {
        return Err(Error::InvalidPath);
    }
    Ok(out)
}

fn print_bridge_summary(summary: &private_bridge::BridgeSummary) {
    println!(
        "{}  gen {}  {}",
        summary.uid,
        summary.generation,
        if summary.destroyed {
            "destroyed"
        } else {
            "live"
        }
    );
    if let Some(label) = &summary.label {
        println!("  label: {label}");
    }
    println!("  public: {}", hex::encode(summary.public_key));
    println!("  salt:   {}", hex::encode(summary.salt));
    println!("  parties:");
    for party in &summary.parties {
        println!(
            "    {}  {:?}  local={}  sealed={}",
            party.label, party.role, party.is_local, party.has_sealed_key
        );
    }
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
            let from_leaves = args.tree_spec.is_none();
            let spec = match args.tree_spec {
                Some(path) => parse_tree_spec(conn, &path)?,
                None => {
                    if args.leaves.is_empty() {
                        fatal_usage_error(
                            "access quorum --state 0 requires --leaf label=pub or --tree-spec FILE",
                        );
                    }
                    let name = args
                        .name
                        .clone()
                        .or_else(|| source.file_name().map(|n| n.to_string_lossy().into_owned()))
                        .unwrap_or_else(|| "file".into());
                    build_spec_from_leaves(
                        conn,
                        &name,
                        args.root.as_deref(),
                        args.threshold.unwrap_or(2),
                        &args.leaves,
                        args.generate_keys,
                        args.register,
                    )?
                }
            };
            let id =
                quorum::lock_file(conn, &source, &encrypted_path, args.name.as_deref(), &spec)?;
            if from_leaves {
                let file_status = quorum::status(conn, id)?;
                key_tree::bind_all_sibling_leaf_pairs(conn, file_status.tree.key_id)?;
                for (a, b) in parse_bind_pairs(&args.binds)? {
                    key_tree::bind_pair(conn, file_status.tree.key_id, &a, &b)?;
                }
            }
            println!("Locked file {id}");
        }
        Some(1) => {
            let id = require(args.id, "id");
            let file_status = quorum::status(conn, id)?;
            let shares = collect_shares(conn, &file_status.tree.root, &args.share_files)?;
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
            let recipient_public_key = read_key_array_32(&recipient_key_file)?;
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
            let recipient_public_key = read_key_array_32(&recipient_key_file)?;
            let password = prompt_secret("Unlock password: ")?;
            let bundle = export::export_file(conn, id, &password, &recipient_public_key)?;
            locked_files::write_owner_only(&output, &bundle)?;
            println!("Exported file {id} to {}", output.display());
        }
    }
    Ok(())
}

fn relay_url(explicit: Option<String>) -> Result<String> {
    if let Some(url) = explicit.filter(|s| !s.is_empty()) {
        return Ok(url);
    }
    match std::env::var("KEYQUORUM_RELAY_URL") {
        Ok(url) if !url.is_empty() => Ok(url),
        _ => Err(Error::RelayRequest(
            "relay URL required (--url or KEYQUORUM_RELAY_URL)".into(),
        )),
    }
}

fn relay_api_key(explicit: Option<String>) -> Result<String> {
    if let Some(key) = explicit.filter(|s| !s.is_empty()) {
        return Ok(key);
    }
    match std::env::var("KEYQUORUM_RELAY_API_KEY") {
        Ok(key) if !key.is_empty() => Ok(key),
        _ => prompt_secret("Relay API key: "),
    }
}

fn run_relay(db_path: &Path, command: RelayCommand) -> Result<()> {
    match command {
        RelayCommand::Push { dir, url, api_key } => {
            let url = relay_url(url)?;
            let api_key = relay_api_key(api_key)?;
            let mut uploaded = 0usize;
            let mut entries: Vec<_> = fs::read_dir(&dir)?.collect::<std::io::Result<_>>()?;
            entries.sort_by_key(|e| e.path());
            for entry in entries {
                let path = entry.path();
                if path.extension().and_then(|s| s.to_str()) != Some("kqpb") {
                    continue;
                }
                let bytes = fs::read(&path)?;
                let accepted = relay::push_inbox(&url, &api_key, &bytes)?;
                println!(
                    "{} -> id {} ({})",
                    path.display(),
                    accepted.id,
                    accepted.recipient_fingerprint
                );
                uploaded += 1;
            }
            if uploaded == 0 {
                return Err(Error::RelayRequest(format!(
                    "no .kqpb files in {}",
                    dir.display()
                )));
            }
        }
        RelayCommand::Pull {
            import,
            share_file,
            output_dir,
            url,
            api_key,
            after,
        } => {
            let url = relay_url(url)?;
            let api_key = relay_api_key(api_key)?;
            let listed = relay::pull_inbox(&url, &api_key, after)?;
            if listed.envelopes.is_empty() {
                println!("(no envelopes)");
                return Ok(());
            }

            let mut conn = if import {
                let db_path_str = db_path.to_str().ok_or(Error::InvalidPath)?;
                Some(db::open(db_path_str)?)
            } else {
                None
            };
            let share_sk = if import {
                let path = share_file.as_ref().ok_or(Error::InvalidPath)?;
                Some(zeroize::Zeroizing::new(read_key_array_32(Path::new(path))?))
            } else {
                None
            };

            if let Some(output_dir) = &output_dir {
                fs::create_dir_all(output_dir)?;
            }

            for item in &listed.envelopes {
                let bytes =
                    base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &item.bytes)
                        .map_err(|_| Error::InvalidBridgePackage)?;
                if let Some(output_dir) = &output_dir {
                    let path = output_dir.join(format!("{}.kqpb", item.id));
                    locked_files::write_owner_only(&path, &bytes)?;
                    println!("Wrote {}", path.display());
                }
                if let (Some(conn), Some(sk)) = (conn.as_mut(), share_sk.as_ref()) {
                    let summary = private_bridge::import_package(conn, &bytes, sk)?;
                    println!(
                        "Imported envelope {} as private bridge {} gen {}",
                        item.id, summary.uid, summary.generation
                    );
                }
            }
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
    let inactive = if node.is_active { "" } else { " [inactive]" };
    match &node.hardware_key_label {
        Some(label) => println!(
            "{indent}{} (node {}){inactive} -> hardware key {} ({label})",
            node.label,
            node.id,
            node.hardware_key_id.unwrap_or(-1)
        ),
        None => println!(
            "{indent}{} (node {}){inactive} [{} of {}]",
            node.label,
            node.id,
            node.threshold.unwrap_or(0),
            node.children.len()
        ),
    }
    if !node.allowed_bridges.is_empty() {
        println!(
            "{indent}  allowed bridges: {}",
            node.allowed_bridges.join(", ")
        );
    }
    for child in &node.children {
        print_tree_node(child, depth + 1);
    }
}

struct HardwareRevokeArgs<'a> {
    hardware_id: i64,
    key_id: Option<i64>,
    node_label: Option<&'a str>,
    evict: bool,
    share_files: &'a [String],
    deny_peers: &'a [String],
    remove_peers: &'a [String],
}

/// Ban `hardware_id` from new trees and drop its pairings on every live
/// spec. Optional `--evict` PSS-refreshes survivors of the matching leaf
/// (`--key-id` / `--node`, or the unique leaf this token backs).
fn apply_hardware_revoke(conn: &mut Connection, args: HardwareRevokeArgs<'_>) -> Result<()> {
    let HardwareRevokeArgs {
        hardware_id,
        key_id,
        node_label,
        evict,
        share_files,
        deny_peers,
        remove_peers,
    } = args;
    if let (Some(key_id), Some(node_label)) = (key_id, node_label) {
        let tree = key_tree::KeyQuorumTree::load(conn, key_id)?;
        let _node = leaf_backed_by(&tree, node_label, hardware_id)?;
        for peer in remove_peers {
            key_tree::remove_bridge(conn, key_id, node_label, peer)?;
            println!("Removed bridge {node_label} <-> {peer}");
        }
        for peer in deny_peers {
            key_tree::deny_bridge(conn, key_id, node_label, peer)?;
            println!("Denied {node_label} bridging to {peer}");
        }
    }

    let leaves = key_tree::drop_bindings_for_hardware(conn, hardware_id)?;
    for leaf in &leaves {
        println!(
            "Dropped binds for {} (node {}) on tree {}",
            leaf.label, leaf.node_id, leaf.key_id
        );
    }

    let mut evict_changes = Vec::new();
    if evict {
        let target = match (key_id, node_label) {
            (Some(key_id), Some(node_label)) => {
                let tree = key_tree::KeyQuorumTree::load(conn, key_id)?;
                let node = leaf_backed_by(&tree, node_label, hardware_id)?;
                (key_id, node.db_id)
            }
            _ => match leaves.as_slice() {
                [leaf] => (leaf.key_id, leaf.node_id),
                [] => fatal_usage_error(
                    "revoke --evict needs a live leaf; this hardware key backs none",
                ),
                _ => fatal_usage_error(
                    "this hardware key backs more than one leaf; pass --key-id and --node",
                ),
            },
        };
        let summary = key_tree::describe(conn, target.0)?;
        let shares = collect_shares(conn, &summary.root, share_files)?;
        let changes = key_tree::evict_and_refresh(conn, target.0, target.1, &shares)?;
        println!("Evicted node {}; survivor shares refreshed", target.1);
        evict_changes = changes;
    }

    let hardware = keys::get_key(conn, hardware_id)?;
    let mut labels = BTreeSet::new();
    labels.insert(hardware.label.clone());
    for leaf in &leaves {
        labels.insert(leaf.label.clone());
    }
    let mut revoke_changes = Vec::new();
    for label in labels {
        revoke_changes.extend(private_bridge::on_member_revoked(conn, &label)?);
    }

    keys::revoke_key(conn, hardware_id)?;
    println!("Revoked key {hardware_id}");

    write_bridge_change_notices(&evict_changes)?;
    write_bridge_change_notices(&revoke_changes)?;
    Ok(())
}

fn write_bridge_change_notices(changes: &[private_bridge::BridgeChange]) -> Result<()> {
    for change in changes {
        let kind = match change.kind {
            private_bridge::BridgeChangeKind::NeedsMemberRotate => "remaining members must rotate",
            private_bridge::BridgeChangeKind::Destroyed => "bridge destroyed",
        };
        println!(
            "Private bridge {}: removed {}; {}.",
            change.uid, change.removed_member, kind
        );
        println!(
            "  Notify these stores (members + department managers): {}",
            change.notify.join(", ")
        );
        let notice_path = format!(
            "bridge-{}-removed-{}.kqbn",
            change.uid,
            sanitize_label(&change.removed_member)?
        );
        locked_files::write_owner_only(Path::new(&notice_path), &change.notice)?;
        println!("  Wrote notice {notice_path}");
    }
    Ok(())
}

fn print_lca(conn: &Connection, key_id: i64, nodes: &[String]) -> Result<()> {
    let tree = key_tree::KeyQuorumTree::load(conn, key_id)?;
    let mut indices = Vec::with_capacity(nodes.len());
    for token in nodes {
        indices.push(resolve_node_index(conn, &tree, token)?);
    }
    let lca_idx = tree.find_lowest_common_ancestor_of(&indices)?;
    let lca = &tree.nodes[lca_idx];
    println!("{} (node {})", lca.id, lca.db_id);
    Ok(())
}

/// A node label (`M.A`) or a key file whose public key uniquely backs one
/// active leaf (`AccountingDepartment.pub`).
fn resolve_node_index(
    conn: &Connection,
    tree: &key_tree::KeyQuorumTree,
    token: &str,
) -> Result<usize> {
    if let Ok(idx) = tree.index_by_label(token) {
        return Ok(idx);
    }
    let path = Path::new(token);
    if !path.is_file() {
        return Err(Error::NodeNotFound);
    }
    let raw = read_key_bytes(path)?;
    if raw.len() != 32 {
        return Err(Error::InvalidPublicKey);
    }
    let arr: [u8; 32] = raw.as_slice().try_into().expect("length checked");
    let hardware = match keys::get_key_by_public_key(conn, &arr) {
        Ok(key) => key,
        Err(_) => {
            let public = keys::encryption_public_from_secret(&arr);
            keys::get_key_by_public_key(conn, &public)?
        }
    };
    let matches: Vec<usize> = tree
        .nodes
        .iter()
        .enumerate()
        .filter(|(_, node)| node.is_active && node.hardware_key_id == Some(hardware.id))
        .map(|(idx, _)| idx)
        .collect();
    match matches.as_slice() {
        [idx] => Ok(*idx),
        [] => Err(Error::NodeNotFound),
        _ => fatal_usage_error(&format!(
            "{token} backs more than one leaf; pass the node label from `tree`"
        )),
    }
}

fn leaf_backed_by<'a>(
    tree: &'a key_tree::KeyQuorumTree,
    label: &str,
    hardware_id: i64,
) -> Result<&'a key_tree::KeyNode> {
    let idx = tree.index_by_label(label)?;
    let node = &tree.nodes[idx];
    if node.hardware_key_id != Some(hardware_id) {
        fatal_usage_error(&format!(
            "--node '{label}' is not a leaf backed by hardware key {hardware_id}"
        ));
    }
    Ok(node)
}

/// Gathers raw shares for every active leaf in `root`. `--share-file` is a
/// path to the hardware key that backs the leaf (`.pub`, `.key`, PEM, or
/// hex). A matching private key unwraps the sealed share in the database.
/// `node_id=path` is still accepted as a raw already-unwrapped share.
/// Leaves not covered by a flag are prompted for (key-file path or hex
/// private key). Never takes share or key material as a bare argv value.
fn collect_shares(
    conn: &Connection,
    root: &TreeNodeSummary,
    share_files: &[String],
) -> Result<HashMap<i64, Vec<u8>>> {
    let mut leaves = Vec::new();
    collect_leaves(root, &mut leaves);

    let mut shares = HashMap::new();
    for entry in share_files {
        if let Some((node_id_str, path)) = entry.split_once('=') {
            if let Ok(node_id) = node_id_str.parse::<i64>() {
                apply_raw_share_file(&leaves, &mut shares, node_id, Path::new(path));
                continue;
            }
        }
        apply_key_file(conn, &leaves, &mut shares, Path::new(entry))?;
    }

    for (node_id, hardware_key_id, label) in &leaves {
        if shares.contains_key(node_id) {
            continue;
        }
        let prompt = format!(
            "Key for '{label}' (node {node_id}, hardware key {hardware_key_id}; path to .key/.pub or hex private key, blank to skip): "
        );
        let entered = prompt_secret(&prompt)?;
        let trimmed = entered.trim();
        if trimmed.is_empty() {
            continue;
        }
        let path = Path::new(trimmed);
        if path.exists() {
            apply_key_file(conn, &leaves, &mut shares, path)?;
        } else {
            let secret = hex::decode(trimmed)
                .unwrap_or_else(|_| fatal_usage_error("key must be a file path or hex-encoded"));
            unwrap_leaves_for_secret(conn, &leaves, &mut shares, &secret)?;
        }
    }

    Ok(shares)
}

fn apply_raw_share_file(
    leaves: &[(i64, i64, String)],
    shares: &mut HashMap<i64, Vec<u8>>,
    node_id: i64,
    path: &Path,
) {
    if !leaves.iter().any(|(id, _, _)| *id == node_id) {
        fatal_usage_error(&format!(
            "--share-file references node {node_id}, which isn't a leaf in this tree \
             (see `tree`/`--status` for valid leaf node ids)"
        ));
    }
    if shares.contains_key(&node_id) {
        fatal_usage_error(&format!(
            "--share-file for node {node_id} was given more than once"
        ));
    }
    let bytes = read_hex_bytes(path).unwrap_or_else(|err| fatal_usage_error(&err.to_string()));
    shares.insert(node_id, bytes);
}

fn apply_key_file(
    conn: &Connection,
    leaves: &[(i64, i64, String)],
    shares: &mut HashMap<i64, Vec<u8>>,
    path: &Path,
) -> Result<()> {
    let raw = read_key_bytes(path)?;
    if raw.len() != 32 {
        fatal_usage_error(&format!("{} is not a 32-byte key file", path.display()));
    }
    let arr: [u8; 32] = raw.as_slice().try_into().expect("length checked above");
    let secret = match keys::get_key_by_public_key(conn, &arr) {
        Ok(_) => resolve_private_for_public(path, &arr)?,
        Err(_) => zeroize::Zeroizing::new(arr),
    };
    unwrap_leaves_for_secret(conn, leaves, shares, secret.as_ref())
}

fn resolve_private_for_public(
    public_path: &Path,
    public_key: &[u8; 32],
) -> Result<zeroize::Zeroizing<[u8; 32]>> {
    let sibling = public_path.with_extension("key");
    if sibling != public_path && sibling.is_file() {
        let raw = read_key_bytes(&sibling)?;
        let secret: [u8; 32] = raw
            .as_slice()
            .try_into()
            .map_err(|_| Error::InvalidPublicKey)?;
        if keys::encryption_public_from_secret(&secret) != *public_key {
            fatal_usage_error(&format!(
                "{} does not match public key {}",
                sibling.display(),
                public_path.display()
            ));
        }
        return Ok(zeroize::Zeroizing::new(secret));
    }

    let entered = prompt_secret(&format!(
        "Private key for {} (hex, blank to skip): ",
        public_path.display()
    ))?;
    let trimmed = entered.trim();
    if trimmed.is_empty() {
        fatal_usage_error(&format!(
            "{} is a public key; pass the matching .key file or enter the private key",
            public_path.display()
        ));
    }
    let raw = keys::parse_key_text(trimmed)?;
    let secret: [u8; 32] = raw
        .as_slice()
        .try_into()
        .map_err(|_| Error::InvalidPublicKey)?;
    if keys::encryption_public_from_secret(&secret) != *public_key {
        fatal_usage_error(&format!(
            "private key does not match {}",
            public_path.display()
        ));
    }
    Ok(zeroize::Zeroizing::new(secret))
}

fn unwrap_leaves_for_secret(
    conn: &Connection,
    leaves: &[(i64, i64, String)],
    shares: &mut HashMap<i64, Vec<u8>>,
    secret: &[u8],
) -> Result<()> {
    let secret_arr: [u8; 32] = secret.try_into().map_err(|_| Error::InvalidPublicKey)?;
    let public = keys::encryption_public_from_secret(&secret_arr);
    let hardware = keys::get_key_by_public_key(conn, &public)?;
    let mut matched = false;
    for (node_id, hardware_key_id, _) in leaves {
        if *hardware_key_id != hardware.id {
            continue;
        }
        matched = true;
        if shares.contains_key(node_id) {
            continue;
        }
        shares.insert(
            *node_id,
            key_tree::unwrap_leaf_share(conn, *node_id, &secret_arr)?,
        );
    }
    if !matched {
        fatal_usage_error(&format!(
            "key file is registered as hardware key {} but does not back any leaf in this tree",
            hardware.id
        ));
    }
    Ok(())
}

fn collect_leaves(node: &TreeNodeSummary, out: &mut Vec<(i64, i64, String)>) {
    if node.is_active {
        if let Some(hardware_key_id) = node.hardware_key_id {
            out.push((node.id, hardware_key_id, node.label.clone()));
        }
    }
    for child in &node.children {
        collect_leaves(child, out);
    }
}

fn build_spec_from_leaves(
    conn: &Connection,
    key_label: &str,
    root: Option<&str>,
    threshold: u8,
    leaf_args: &[String],
    generate_keys: bool,
    register: bool,
) -> Result<NodeSpec> {
    let leaves = parse_spec_leaves(leaf_args)?;
    if threshold == 0 || (threshold as usize) > leaves.len() {
        return Err(Error::InvalidQuorumThreshold);
    }
    let root_label = infer_root_label(
        &leaves.iter().map(|l| l.label.clone()).collect::<Vec<_>>(),
        root,
        key_label,
    )?;
    let mut resolved = Vec::with_capacity(leaves.len());
    for leaf in &leaves {
        let hw_id =
            resolve_or_register_pub(conn, &leaf.label, &leaf.pub_path, generate_keys, register)?;
        resolved.push((leaf.label.clone(), hw_id));
    }
    Ok(NodeSpec::flat_split(root_label, threshold, resolved))
}

fn infer_root_label(
    leaf_labels: &[String],
    explicit: Option<&str>,
    fallback: &str,
) -> Result<String> {
    if let Some(root) = explicit {
        if root.is_empty() {
            fatal_usage_error("--root must not be empty");
        }
        return Ok(root.to_string());
    }
    let prefixes: Vec<Option<&str>> = leaf_labels
        .iter()
        .map(|label| label.rsplit_once('.').map(|(prefix, _)| prefix))
        .collect();
    if prefixes.iter().all(|prefix| prefix.is_some()) {
        let first = prefixes[0].expect("all prefixes are Some");
        if first.is_empty() || prefixes.iter().any(|prefix| prefix != &Some(first)) {
            fatal_usage_error("dotted --leaf labels do not share a common parent; pass --root");
        }
        return Ok(first.to_string());
    }
    if prefixes.iter().all(|prefix| prefix.is_none()) {
        return Ok(fallback.to_string());
    }
    fatal_usage_error("mix of dotted and undotted --leaf labels; pass --root");
}

fn parse_bind_pairs(args: &[String]) -> Result<Vec<(String, String)>> {
    let mut pairs = Vec::with_capacity(args.len());
    for entry in args {
        let (a, b) = entry.split_once('=').unwrap_or_else(|| {
            fatal_usage_error("--bind must be in the form label=peer (e.g. M.S=M.A)")
        });
        if a.is_empty() || b.is_empty() || a == b {
            fatal_usage_error("--bind must name two different labels");
        }
        pairs.push((a.to_string(), b.to_string()));
    }
    Ok(pairs)
}

fn resolve_or_register_pub(
    conn: &Connection,
    label: &str,
    pub_path: &Path,
    generate_keys: bool,
    register: bool,
) -> Result<i64> {
    if generate_keys {
        generate_leaf_keypair(pub_path)?;
    }
    let public_key = read_key_bytes(pub_path)?;
    if public_key.len() != 32 {
        return Err(Error::InvalidPublicKey);
    }
    match keys::get_key_by_public_key(conn, &public_key) {
        Ok(hardware) => {
            if register {
                eprintln!("Using existing hardware key {} for {label}", hardware.id);
            }
            Ok(hardware.id)
        }
        Err(_) if register => {
            let id = keys::register_key(conn, label, keys::KeyType::Encryption, &public_key)?;
            eprintln!("Registered {label} as hardware key {id}");
            Ok(id)
        }
        Err(err) => Err(err),
    }
}

fn secret_for_named_leaf(
    conn: &Connection,
    key_id: i64,
    label: &str,
    share_file: &str,
) -> Result<zeroize::Zeroizing<[u8; 32]>> {
    let tree = key_tree::KeyQuorumTree::load(conn, key_id)?;
    let idx = tree.index_by_label(label)?;
    if !tree.nodes[idx].is_active || tree.nodes[idx].hardware_key_id.is_none() {
        return Err(Error::NodeNotFound);
    }
    let path = Path::new(share_file);
    let raw = read_key_bytes(path)?;
    if raw.len() != 32 {
        return Err(Error::InvalidPublicKey);
    }
    let arr: [u8; 32] = raw.as_slice().try_into().expect("length checked");
    let secret = match keys::get_key_by_public_key(conn, &arr) {
        Ok(_) => resolve_private_for_public(path, &arr)?,
        Err(_) => zeroize::Zeroizing::new(arr),
    };
    Ok(secret)
}

fn find_tree_node<'a>(node: &'a TreeNodeSummary, label: &str) -> Option<&'a TreeNodeSummary> {
    if node.label == label {
        return Some(node);
    }
    node.children
        .iter()
        .find_map(|child| find_tree_node(child, label))
}

fn write_live_spec(conn: &Connection, key_id: i64, path: &Path) -> Result<()> {
    let spec = key_tree::export_spec(conn, key_id)?;
    let rendered = serde_json::to_string_pretty(&spec).map_err(|_| Error::InvalidTreeSpec)?;
    fs::write(path, format!("{rendered}\n"))?;
    eprintln!("Wrote live spec to {}", path.display());
    Ok(())
}

struct SpecLeaf {
    label: String,
    pub_path: PathBuf,
}

fn parse_spec_leaves(args: &[String]) -> Result<Vec<SpecLeaf>> {
    let mut leaves = Vec::with_capacity(args.len());
    let mut seen = std::collections::HashSet::new();
    for entry in args {
        let (label, path) = entry.split_once('=').unwrap_or_else(|| {
            fatal_usage_error(
                "--leaf must be in the form label=path (e.g. M.S=SoftwareDepartment.pub)",
            )
        });
        if label.is_empty() || path.is_empty() {
            fatal_usage_error("--leaf must be in the form label=path");
        }
        if !seen.insert(label.to_string()) {
            return Err(Error::DuplicateNodeLabel);
        }
        leaves.push(SpecLeaf {
            label: label.to_string(),
            pub_path: PathBuf::from(path),
        });
    }
    Ok(leaves)
}

fn generate_leaf_keypair(pub_path: &Path) -> Result<()> {
    if pub_path.exists() {
        fatal_usage_error(&format!(
            "refusing to overwrite existing key file {}",
            pub_path.display()
        ));
    }
    let key_path = pub_path.with_extension("key");
    if key_path.exists() {
        fatal_usage_error(&format!(
            "refusing to overwrite existing key file {}",
            key_path.display()
        ));
    }
    if let Some(parent) = pub_path.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            fs::create_dir_all(parent)?;
        }
    }
    let (secret, public) = keys::generate_encryption_keypair();
    write_hex_file(pub_path, &public)?;
    write_hex_file(&key_path, secret.as_ref())?;
    eprintln!(
        "Generated {} and {}",
        pub_path.display(),
        key_path.display()
    );
    Ok(())
}

fn parse_tree_spec(conn: &Connection, path: &Path) -> Result<NodeSpec> {
    let contents = fs::read_to_string(path)?;
    let mut value: serde_json::Value =
        serde_json::from_str(&contents).map_err(|_| Error::InvalidTreeSpec)?;
    let base = path.parent().unwrap_or_else(|| Path::new("."));
    resolve_public_key_files(conn, &mut value, base)?;
    serde_json::from_value(value).map_err(|_| Error::InvalidTreeSpec)
}

/// Leaves may name a registered key by `public_key_file` instead of
/// `hardware_key_id`. Paths are relative to the tree-spec file.
fn resolve_public_key_files(
    conn: &Connection,
    value: &mut serde_json::Value,
    base: &Path,
) -> Result<()> {
    let serde_json::Value::Object(map) = value else {
        return Ok(());
    };
    if let Some(file) = map.remove("public_key_file") {
        if map.contains_key("hardware_key_id") {
            return Err(Error::InvalidTreeSpec);
        }
        let rel = file.as_str().ok_or(Error::InvalidTreeSpec)?;
        let raw = read_key_bytes(&base.join(rel))?;
        if raw.len() != 32 {
            return Err(Error::InvalidPublicKey);
        }
        let hardware = keys::get_key_by_public_key(conn, &raw)?;
        map.insert("hardware_key_id".to_string(), hardware.id.into());
    }
    if let Some(serde_json::Value::Array(arr)) = map.get_mut("children") {
        for child in arr {
            resolve_public_key_files(conn, child, base)?;
        }
    }
    Ok(())
}

/// Exact file bytes for `--source`, after checking the text parses as a key.
fn read_key_file_payload(path: &Path) -> Result<Vec<u8>> {
    let contents = fs::read(path)?;
    let text = std::str::from_utf8(&contents).map_err(|_| Error::InvalidPublicKey)?;
    keys::parse_key_text(text)?;
    if contents.is_empty() {
        return Err(Error::InvalidPublicKey);
    }
    Ok(contents)
}

fn write_reassembled_secret(secret: &[u8], output: Option<&Path>) -> Result<()> {
    match output {
        Some(path) => {
            locked_files::write_owner_only(path, secret)?;
            eprintln!("Wrote reassembled key to {}", path.display());
        }
        None => println!("{}", hex::encode(secret)),
    }
    Ok(())
}

fn read_key_bytes(path: &Path) -> Result<Vec<u8>> {
    let contents = fs::read_to_string(path)?;
    keys::parse_key_text(&contents)
}

fn read_key_array_32(path: &Path) -> Result<[u8; 32]> {
    read_key_bytes(path)?
        .try_into()
        .map_err(|_| Error::InvalidPublicKey)
}

fn read_hex_bytes(path: &Path) -> Result<Vec<u8>> {
    let contents = fs::read_to_string(path)?;
    hex::decode(contents.trim()).map_err(|_| Error::InvalidPublicKey)
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
mod tests;
