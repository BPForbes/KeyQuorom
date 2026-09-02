//! Provider-only mailbox host. Compiled only with `--features provider`.
//! Hidden from `keyquorum --help`. Customers use `loadkey` with a URL
//! and bearer they were given.
//!
//! `--features provider` compiles these commands; it does not authorize a
//! host. `serve` requires a KeyQuorum-signed `provider.kqcert` and the
//! matching relay private key. It does not mint the `kql_…` API root.
//! Official API-root minting is `api-root generate`: cert, signed
//! `provider-policy.kqpolicy`, Corporate Network id, and hardware
//! proof-of-possession. Caller `--network` / `--ssid` values are a
//! ceremony/dev presence check for `root generate` only — they are not
//! production authority. Production networks come from the signed policy.

use clap::Subcommand;
use keyquorum::db;
use keyquorum::error::{Error, Result};
use keyquorum::keys::{self, KeyType};
use keyquorum::locked_files;
use keyquorum::provider::authorize::{self, ApiRootRequest};
use keyquorum::provider::hardware_auth::{self, HardwareAuthority, ProviderChallenge};
use keyquorum::provider::policy::{
    self, CorporateNetwork, HardwareAuthorityEntry, NetworkMode, NewPolicy, PERM_API_ROOT_GENERATE,
};
use keyquorum::provider::{self, NewCertificate, KEYQUORUM_PROVIDER_ROOT_PUBLIC_KEY};
use keyquorum::relay::{self, ApiKeyScope, AppState, NewApiKey, ProviderIdentity};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::signal;
use tracing_subscriber::EnvFilter;

#[derive(Subcommand)]
pub enum HostCommand {
    /// Listen for envelope push/pull. Does not mint API keys.
    Serve {
        #[arg(long, default_value = "127.0.0.1:8787")]
        bind: String,
        /// `provider.kqcert` (or KEYQUORUM_PROVIDER_CERT)
        #[arg(long)]
        cert: Option<PathBuf>,
        /// Relay Ed25519 private key file (or KEYQUORUM_RELAY_KEY)
        #[arg(long)]
        relay_key: Option<PathBuf>,
        /// Optional signed revocation list (or KEYQUORUM_PROVIDER_KRL)
        #[arg(long)]
        krl: Option<PathBuf>,
        /// Personal/org SQLite to scan for date-based TTL files. Defaults
        /// to the global `--db` when that file already exists.
        #[arg(long)]
        scan_db: Option<PathBuf>,
        /// How often to delete expired mailbox envelopes and TTL files.
        #[arg(long, default_value_t = 60, value_parser = clap::value_parser!(u64).range(1..))]
        scan_interval_seconds: u64,
    },
    /// Generate a relay identity keypair (private key printed once).
    Identity {
        #[command(subcommand)]
        command: IdentityCommand,
    },
    /// Issue a `provider.kqcert` with the offline provider-root private key.
    Certify {
        /// Root private key file (or KEYQUORUM_PROVIDER_ROOT_KEY as key text)
        #[arg(long)]
        root_key: Option<PathBuf>,
        #[arg(long)]
        relay_public_key: PathBuf,
        #[arg(long)]
        provider_id: String,
        #[arg(long)]
        serial: String,
        #[arg(long)]
        issued_at: Option<String>,
        #[arg(long)]
        expires_at: String,
        #[arg(long, default_value = "provider")]
        capabilities: String,
        #[arg(long, default_value = "KeyQuorumRoot")]
        issuer_id: String,
        #[arg(long)]
        out: PathBuf,
    },
    /// Issue a signed provider revocation list (`.kqrl`).
    Krl {
        #[arg(long)]
        root_key: Option<PathBuf>,
        #[arg(long)]
        issued_at: Option<String>,
        #[arg(long = "serial", required = true)]
        serials: Vec<String>,
        #[arg(long)]
        out: PathBuf,
    },
    /// Mint, list, rotate, or revoke API keys on this host (not over HTTP)
    Keys {
        #[command(subcommand)]
        command: KeysCommand,
    },
    /// Seller-root keypair. Allowed only on a configured VPN tunnel.
    Root {
        #[command(subcommand)]
        command: RootCommand,
    },
    /// Issue a provider-root-signed hardware/network policy.
    Policy {
        #[command(subcommand)]
        command: PolicyCommand,
    },
    /// Official `kql_…` API-root minting.
    ApiRoot {
        #[command(subcommand)]
        command: ApiRootCommand,
    },
}

#[derive(Subcommand)]
pub enum RootCommand {
    /// Print the root private key once. Requires a live VPN CIDR or Wi-Fi SSID.
    Generate {
        #[arg(long)]
        public_key_out: PathBuf,
        /// Seller VPN CIDR (repeatable). Ceremony only; not production authority.
        #[arg(long = "network")]
        networks: Vec<String>,
        /// Seller Wi-Fi SSID (repeatable, or KEYQUORUM_ROOT_SSIDS). Ceremony only.
        #[arg(long = "ssid")]
        ssids: Vec<String>,
    },
}

#[derive(Subcommand)]
pub enum PolicyCommand {
    /// Write `provider-policy.kqpolicy` signed by the offline provider root.
    Issue {
        #[arg(long)]
        root_key: Option<PathBuf>,
        #[arg(long)]
        relay_public_key: PathBuf,
        #[arg(long)]
        provider_id: String,
        #[arg(long)]
        policy_id: String,
        #[arg(long)]
        issued_at: Option<String>,
        #[arg(long)]
        expires_at: String,
        #[arg(long, default_value = "provider")]
        capabilities: String,
        /// hex(SHA-256(pubkey)) of an authorized signing token (repeatable)
        #[arg(long = "hardware-fingerprint", required = true)]
        hardware_fingerprints: Vec<String>,
        #[arg(long = "revoked-hardware")]
        revoked_hardware: Vec<String>,
        /// `id` or `id:cidr[,cidr…]` (repeatable). Wi-Fi may omit the CIDR.
        #[arg(long = "corporate-network", required = true)]
        corporate_networks: Vec<String>,
        #[arg(long, default_value = "vpn")]
        network_mode: String,
        /// Required when `--network-mode wifi`. Not compiled into the binary.
        #[arg(long)]
        ssid: Option<String>,
        #[arg(long)]
        bssid: Option<String>,
        #[arg(long, default_value_t = 1)]
        hardware_threshold: u8,
        #[arg(long = "permission", default_value = "api-root.generate")]
        permissions: Vec<String>,
        #[arg(long)]
        out: PathBuf,
    },
}

#[derive(Subcommand)]
pub enum ApiRootCommand {
    /// Mint the licensee issuer after all provider gates succeed.
    Generate {
        #[arg(long)]
        cert: Option<PathBuf>,
        #[arg(long)]
        relay_key: Option<PathBuf>,
        #[arg(long)]
        krl: Option<PathBuf>,
        /// Signed policy (or KEYQUORUM_PROVIDER_POLICY)
        #[arg(long)]
        policy: Option<PathBuf>,
        /// Selects a Corporate Network already listed in the signed policy.
        #[arg(long)]
        network_id: String,
        /// File-based stand-in for the hardware signing key (tests/dev).
        #[arg(long)]
        hardware_key: Option<PathBuf>,
        #[arg(long)]
        hardware_public_key: Option<PathBuf>,
        #[arg(long)]
        hardware_signature: Option<String>,
        /// Rejected: caller CIDRs are not production authority.
        #[arg(long = "network")]
        networks: Vec<String>,
    },
}

#[derive(Subcommand)]
pub enum IdentityCommand {
    Generate {
        #[arg(long)]
        public_key_out: PathBuf,
    },
}

#[derive(Subcommand)]
pub enum KeysCommand {
    Create {
        #[arg(long)]
        scope: String,
        /// Required for inbox.pull: hex SHA-256 of the recipient X25519 public key
        #[arg(long)]
        fingerprint: Option<String>,
        #[arg(long)]
        label: Option<String>,
        #[arg(long)]
        ttl_seconds: Option<i64>,
        /// Licensee issuer (`kql_…`). Prompted or KEYQUORUM_LICENSEE_KEY if omitted.
        #[arg(long)]
        licensee_key: Option<String>,
    },
    List,
    Revoke {
        id: i64,
    },
    Rotate {
        id: i64,
        #[arg(long)]
        licensee_key: Option<String>,
    },
}

pub fn run(mailbox_db: &Path, org_db: &Path, command: HostCommand) -> Result<()> {
    match command {
        HostCommand::Serve {
            bind,
            cert,
            relay_key,
            krl,
            scan_db,
            scan_interval_seconds,
        } => {
            let scan_db = scan_db.or_else(|| org_db.is_file().then(|| org_db.to_path_buf()));
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .map_err(Error::Io)?
                .block_on(serve(
                    mailbox_db,
                    &bind,
                    cert,
                    relay_key,
                    krl,
                    scan_db,
                    scan_interval_seconds,
                ))
        }
        HostCommand::Identity { command } => run_identity(command),
        HostCommand::Certify {
            root_key,
            relay_public_key,
            provider_id,
            serial,
            issued_at,
            expires_at,
            capabilities,
            issuer_id,
            out,
        } => run_certify(
            root_key,
            &relay_public_key,
            &provider_id,
            &serial,
            issued_at,
            &expires_at,
            &capabilities,
            &issuer_id,
            &out,
        ),
        HostCommand::Krl {
            root_key,
            issued_at,
            serials,
            out,
        } => run_krl(root_key, issued_at, &serials, &out),
        HostCommand::Keys { command } => {
            let db_path = mailbox_db.to_str().ok_or(Error::InvalidPath)?;
            let conn = relay::open(db_path)?;
            run_keys(&conn, command)
        }
        HostCommand::Root { command } => run_root(command),
        HostCommand::Policy { command } => run_policy(command),
        HostCommand::ApiRoot { command } => {
            let db_path = mailbox_db.to_str().ok_or(Error::InvalidPath)?;
            let conn = relay::open(db_path)?;
            run_api_root(&conn, command)
        }
    }
}

fn print_new_licensee(issuer: &relay::CreatedLicensee) {
    eprintln!("Created licensee issuer key (shown once):");
    eprintln!("  {}", issuer.token);
    eprintln!("Only this key can mint or rotate customer API keys.");
    eprintln!("It is not a KeyQuorum provider certificate.");
    eprintln!("Store this; it cannot be recovered from the database.");
}

fn licensee_secret(explicit: Option<String>) -> Result<String> {
    if let Some(key) = explicit.filter(|s| !s.is_empty()) {
        return Ok(key);
    }
    match std::env::var("KEYQUORUM_LICENSEE_KEY") {
        Ok(key) if !key.is_empty() => Ok(key),
        _ => rpassword::prompt_password("Licensee key: ").map_err(Error::from),
    }
}

fn require_licensee(conn: &rusqlite::Connection, explicit: Option<String>) -> Result<()> {
    relay::authenticate_licensee(conn, &licensee_secret(explicit)?)
}

fn authorize_mint(conn: &rusqlite::Connection, licensee_key: Option<String>) -> Result<()> {
    if !relay::licensee_issuer_exists(conn)? {
        return Err(Error::ApiRootMissing);
    }
    require_licensee(conn, licensee_key)
}

fn run_keys(conn: &rusqlite::Connection, command: KeysCommand) -> Result<()> {
    match command {
        KeysCommand::Create {
            scope,
            fingerprint,
            label,
            ttl_seconds,
            licensee_key,
        } => {
            authorize_mint(conn, licensee_key)?;
            let created = relay::create_api_key(
                conn,
                &NewApiKey {
                    scope: ApiKeyScope::parse(&scope)?,
                    recipient_fingerprint: fingerprint,
                    label,
                    ttl_seconds,
                },
            )?;
            println!("Created API key {}", created.info.id);
            println!("scope: {}", created.info.scope);
            if let Some(fp) = &created.info.recipient_fingerprint {
                println!("fingerprint: {fp}");
            }
            if let Some(expires) = &created.info.expires_at {
                println!("expires: {expires}");
            }
            println!("token (shown once): {}", created.token);
        }
        KeysCommand::List => {
            let keys = relay::list_api_keys(conn)?;
            if keys.is_empty() {
                println!("(no API keys)");
            } else {
                for key in keys {
                    println!(
                        "{}\t{}\t{}\t{}\t{}",
                        key.id,
                        key.scope,
                        key.recipient_fingerprint.as_deref().unwrap_or("-"),
                        key.revoked_at.as_deref().unwrap_or("live"),
                        key.label.as_deref().unwrap_or("-")
                    );
                }
            }
        }
        KeysCommand::Revoke { id } => {
            relay::revoke_api_key(conn, id)?;
            println!("Revoked API key {id}");
        }
        KeysCommand::Rotate { id, licensee_key } => {
            authorize_mint(conn, licensee_key)?;
            let created = relay::rotate_api_key(conn, id)?;
            println!("Rotated API key {id} -> {}", created.info.id);
            println!("token (shown once): {}", created.token);
        }
    }
    Ok(())
}

fn run_root(command: RootCommand) -> Result<()> {
    match command {
        RootCommand::Generate {
            public_key_out,
            networks,
            ssids,
        } => {
            let networks = provider::root_network::optional_networks_from_cli_or_env(&networks)?;
            let ssids = provider::network::ssids_from_cli_or_env(&ssids);
            provider::root_network::require_root_ceremony(&networks, &ssids)?;
            let (secret, public) = provider::generate_relay_identity();
            locked_files::write_owner_only(&public_key_out, hex::encode(public).as_bytes())?;
            println!("{}", hex::encode(*secret));
            eprintln!("Public key written to {}", public_key_out.display());
            eprintln!("Root private key printed to stdout above — this tool keeps no copy of it.");
            Ok(())
        }
    }
}

fn run_policy(command: PolicyCommand) -> Result<()> {
    match command {
        PolicyCommand::Issue {
            root_key,
            relay_public_key,
            provider_id,
            policy_id,
            issued_at,
            expires_at,
            capabilities,
            hardware_fingerprints,
            revoked_hardware,
            corporate_networks,
            network_mode,
            ssid,
            bssid,
            hardware_threshold,
            permissions,
            out,
        } => run_policy_issue(
            root_key,
            &relay_public_key,
            &provider_id,
            &policy_id,
            issued_at,
            &expires_at,
            &capabilities,
            &hardware_fingerprints,
            &revoked_hardware,
            &corporate_networks,
            &network_mode,
            ssid,
            bssid,
            hardware_threshold,
            &permissions,
            &out,
        ),
    }
}

fn run_api_root(conn: &rusqlite::Connection, command: ApiRootCommand) -> Result<()> {
    match command {
        ApiRootCommand::Generate {
            cert,
            relay_key,
            krl,
            policy,
            network_id,
            hardware_key,
            hardware_public_key,
            hardware_signature,
            networks,
        } => run_api_root_generate(
            conn,
            cert,
            relay_key,
            krl,
            policy,
            &network_id,
            hardware_key,
            hardware_public_key,
            hardware_signature,
            &networks,
        ),
    }
}

#[allow(clippy::too_many_arguments)]
fn run_policy_issue(
    root_key: Option<PathBuf>,
    relay_public_key: &Path,
    provider_id: &str,
    policy_id: &str,
    issued_at: Option<String>,
    expires_at: &str,
    capabilities: &str,
    hardware_fingerprints: &[String],
    revoked_hardware: &[String],
    corporate_networks: &[String],
    network_mode: &str,
    ssid: Option<String>,
    bssid: Option<String>,
    hardware_threshold: u8,
    permissions: &[String],
    out: &Path,
) -> Result<()> {
    let root = read_root_key(root_key)?;
    let relay_public = read_key_array_32(relay_public_key)?;
    let issued_at = match issued_at.filter(|s| !s.is_empty()) {
        Some(value) => value,
        None => provider::system_now_utc()?,
    };
    let capabilities = provider::parse_capabilities(capabilities)?;
    let mode = NetworkMode::parse(network_mode)?;
    let hardware = collect_hardware(hardware_fingerprints, revoked_hardware)?;
    let networks = collect_networks(corporate_networks, mode, ssid, bssid)?;
    let bytes = policy::issue_policy(
        &root,
        &NewPolicy {
            provider_id,
            policy_id,
            relay_public_key: &relay_public,
            issued_at: &issued_at,
            expires_at,
            capabilities,
            hardware_threshold,
            hardware: &hardware,
            networks: &networks,
            permissions,
        },
    )?;
    locked_files::write_owner_only(out, &bytes)?;
    eprintln!("Wrote provider policy to {}", out.display());
    Ok(())
}

fn collect_hardware(
    fingerprints: &[String],
    revoked: &[String],
) -> Result<Vec<HardwareAuthorityEntry>> {
    let revoked: std::collections::HashSet<String> = revoked
        .iter()
        .map(|fp| policy::normalize_fingerprint(fp))
        .collect::<Result<std::collections::HashSet<_>>>()?;
    let mut out = Vec::new();
    for raw in fingerprints {
        let fingerprint = policy::normalize_fingerprint(raw)?;
        let is_revoked = revoked.contains(&fingerprint);
        out.push(HardwareAuthorityEntry {
            fingerprint,
            key_type: KeyType::Signing,
            authority: HardwareAuthority::ProviderApiRoot,
            revoked: is_revoked,
        });
    }
    Ok(out)
}

fn collect_networks(
    specs: &[String],
    mode: NetworkMode,
    ssid: Option<String>,
    bssid: Option<String>,
) -> Result<Vec<CorporateNetwork>> {
    let ssid = ssid.filter(|s| !s.is_empty());
    let bssid = match bssid.filter(|s| !s.is_empty()) {
        Some(value) => Some(provider::network::normalize_bssid(&value)?),
        None => None,
    };
    let mut out = Vec::new();
    for spec in specs {
        let (network_id, cidrs) = match spec.split_once(':') {
            Some((id, rest)) => (
                id,
                rest.split(',')
                    .map(str::trim)
                    .filter(|part| !part.is_empty())
                    .map(str::to_string)
                    .collect::<Vec<_>>(),
            ),
            None => (spec.as_str(), Vec::new()),
        };
        if network_id.is_empty() {
            return Err(Error::InvalidProviderPolicy);
        }
        if mode == NetworkMode::Vpn && cidrs.is_empty() {
            return Err(Error::InvalidProviderPolicy);
        }
        if mode == NetworkMode::Wifi && ssid.is_none() {
            return Err(Error::InvalidProviderPolicy);
        }
        out.push(CorporateNetwork {
            network_id: network_id.to_string(),
            mode,
            cidrs,
            ssid: ssid.clone(),
            bssid_mac: bssid.clone(),
            gateway_mac: None,
            verifier_public_key: None,
        });
    }
    Ok(out)
}

#[allow(clippy::too_many_arguments)]
fn run_api_root_generate(
    conn: &rusqlite::Connection,
    cert: Option<PathBuf>,
    relay_key: Option<PathBuf>,
    krl: Option<PathBuf>,
    policy: Option<PathBuf>,
    network_id: &str,
    hardware_key: Option<PathBuf>,
    hardware_public_key: Option<PathBuf>,
    hardware_signature: Option<String>,
    networks: &[String],
) -> Result<()> {
    let identity = load_serve_identity(cert, relay_key, krl)?;
    let policy_path =
        path_or_env(policy, "KEYQUORUM_PROVIDER_POLICY").ok_or(Error::InvalidProviderPolicy)?;
    let policy_bytes = std::fs::read(&policy_path)?;
    let now = provider::system_now_utc()?;
    let cert = provider::parse_certificate(&identity.certificate)?;
    let nonce = *keyquorum::crypto::random_key();
    let (hardware_public_key, hardware_signature) = hardware_proof(
        &cert,
        network_id,
        &now,
        &nonce,
        hardware_key,
        hardware_public_key,
        hardware_signature,
    )?;
    let local_addrs = provider::root_network::list_local_addresses()?;
    let wifi_links = provider::network::list_wifi_links()?;
    let revoked = std::collections::HashSet::new();
    let outcome = authorize::authorize_api_root_generation(&ApiRootRequest {
        root_public_key: &KEYQUORUM_PROVIDER_ROOT_PUBLIC_KEY,
        certificate: &identity.certificate,
        relay_private_key: &identity.relay_private_key,
        policy: &policy_bytes,
        now_utc: &now,
        revoked: &revoked,
        network_id,
        local_addrs: &local_addrs,
        wifi_links: &wifi_links,
        caller_networks: networks,
        hardware_public_key: &hardware_public_key,
        hardware_signature: &hardware_signature,
        timestamp: &now,
        nonce: &nonce,
    });
    match outcome {
        Ok(authorized) => {
            let issuer = relay::create_licensee_issuer_if_empty(conn);
            let success = issuer.is_ok();
            let _ = relay::record_provider_auth_event(
                conn,
                PERM_API_ROOT_GENERATE,
                Some(&authorized.certificate.provider_id),
                Some(&authorized.network_id),
                Some(&authorized.hardware_fingerprint),
                success,
            );
            let issuer = issuer?;
            print_new_licensee(&issuer);
            Ok(())
        }
        Err(err) => {
            let _ = relay::record_provider_auth_event(
                conn,
                PERM_API_ROOT_GENERATE,
                Some(&cert.provider_id),
                Some(network_id),
                None,
                false,
            );
            Err(err)
        }
    }
}

fn hardware_proof(
    cert: &provider::Certificate,
    network_id: &str,
    timestamp: &str,
    nonce: &[u8; 32],
    hardware_key: Option<PathBuf>,
    hardware_public_key: Option<PathBuf>,
    hardware_signature: Option<String>,
) -> Result<([u8; 32], [u8; 64])> {
    if let Some(path) = hardware_key {
        let secret = read_key_array_32(&path)?;
        let public = ed25519_dalek::SigningKey::from_bytes(&secret)
            .verifying_key()
            .to_bytes();
        let challenge = ProviderChallenge {
            provider_id: &cert.provider_id,
            relay_id: &cert.relay_public_key,
            network_policy_id: network_id,
            timestamp,
            nonce,
            required_authority: HardwareAuthority::ProviderApiRoot,
        };
        let signature = hardware_auth::sign_provider_hardware(&secret, &challenge)?;
        return Ok((public, signature));
    }
    let public_path = hardware_public_key.ok_or(Error::ProviderHardwareDenied)?;
    let signature_hex = hardware_signature.ok_or(Error::ProviderHardwareDenied)?;
    let public = read_key_array_32(&public_path)?;
    let signature = parse_signature_hex(&signature_hex)?;
    Ok((public, signature))
}

fn parse_signature_hex(value: &str) -> Result<[u8; 64]> {
    let bytes = hex::decode(value.trim()).map_err(|_| Error::ProviderHardwareDenied)?;
    bytes.try_into().map_err(|_| Error::ProviderHardwareDenied)
}

fn run_identity(command: IdentityCommand) -> Result<()> {
    match command {
        IdentityCommand::Generate { public_key_out } => {
            let (secret, public) = provider::generate_relay_identity();
            locked_files::write_owner_only(&public_key_out, hex::encode(public).as_bytes())?;
            println!("{}", hex::encode(*secret));
            eprintln!("Public key written to {}", public_key_out.display());
            eprintln!("Private key printed to stdout above — this tool keeps no copy of it.");
            Ok(())
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn run_certify(
    root_key: Option<PathBuf>,
    relay_public_key: &Path,
    provider_id: &str,
    serial: &str,
    issued_at: Option<String>,
    expires_at: &str,
    capabilities: &str,
    issuer_id: &str,
    out: &Path,
) -> Result<()> {
    let root = read_root_key(root_key)?;
    let relay_public = read_key_array_32(relay_public_key)?;
    let issued_at = match issued_at.filter(|s| !s.is_empty()) {
        Some(value) => value,
        None => provider::system_now_utc()?,
    };
    let capabilities = provider::parse_capabilities(capabilities)?;
    let bytes = provider::issue_certificate(
        &root,
        &NewCertificate {
            provider_id,
            serial,
            relay_public_key: &relay_public,
            issued_at: &issued_at,
            expires_at,
            capabilities,
            issuer_id,
        },
    )?;
    locked_files::write_owner_only(out, &bytes)?;
    eprintln!("Wrote provider certificate to {}", out.display());
    Ok(())
}

fn run_krl(
    root_key: Option<PathBuf>,
    issued_at: Option<String>,
    serials: &[String],
    out: &Path,
) -> Result<()> {
    let root = read_root_key(root_key)?;
    let issued_at = match issued_at.filter(|s| !s.is_empty()) {
        Some(value) => value,
        None => provider::system_now_utc()?,
    };
    let bytes = provider::issue_revocation_list(&root, &issued_at, serials)?;
    locked_files::write_owner_only(out, &bytes)?;
    eprintln!("Wrote provider revocation list to {}", out.display());
    Ok(())
}

fn path_or_env(flag: Option<PathBuf>, env_name: &str) -> Option<PathBuf> {
    flag.filter(|p| !p.as_os_str().is_empty())
        .or_else(|| match std::env::var(env_name) {
            Ok(value) if !value.is_empty() => Some(PathBuf::from(value)),
            _ => None,
        })
}

fn read_key_bytes(path: &Path) -> Result<Vec<u8>> {
    let contents = std::fs::read_to_string(path)?;
    keys::parse_key_text(&contents)
}

fn read_key_array_32(path: &Path) -> Result<[u8; 32]> {
    read_key_bytes(path)?
        .try_into()
        .map_err(|_| Error::InvalidPublicKey)
}

fn read_root_key(path: Option<PathBuf>) -> Result<[u8; 32]> {
    if let Some(path) = path {
        return read_key_array_32(&path);
    }
    match std::env::var("KEYQUORUM_PROVIDER_ROOT_KEY") {
        Ok(value) if !value.is_empty() => keys::parse_key_text(&value)?
            .try_into()
            .map_err(|_| Error::InvalidPublicKey),
        _ => Err(Error::InvalidProviderCertificate),
    }
}

fn load_serve_identity(
    cert: Option<PathBuf>,
    relay_key: Option<PathBuf>,
    krl: Option<PathBuf>,
) -> Result<ProviderIdentity> {
    let cert_path =
        path_or_env(cert, "KEYQUORUM_PROVIDER_CERT").ok_or(Error::ProviderIdentityMissing)?;
    let key_path =
        path_or_env(relay_key, "KEYQUORUM_RELAY_KEY").ok_or(Error::ProviderIdentityMissing)?;
    let krl_path = path_or_env(krl, "KEYQUORUM_PROVIDER_KRL");
    let certificate = std::fs::read(&cert_path)?;
    let relay_private_key = zeroize::Zeroizing::new(read_key_array_32(&key_path)?);
    let now = provider::system_now_utc()?;
    let revoked =
        provider::load_revocation_list(&KEYQUORUM_PROVIDER_ROOT_PUBLIC_KEY, krl_path.as_deref())?;
    let cert = provider::self_check(
        &KEYQUORUM_PROVIDER_ROOT_PUBLIC_KEY,
        &certificate,
        &relay_private_key,
        &now,
        &revoked,
    )?;
    eprintln!(
        "provider identity {} serial {} expires {}",
        cert.provider_id, cert.serial, cert.expires_at
    );
    Ok(ProviderIdentity {
        certificate,
        relay_private_key,
    })
}

#[allow(clippy::too_many_arguments)]
async fn serve(
    mailbox_db: &Path,
    bind: &str,
    cert: Option<PathBuf>,
    relay_key: Option<PathBuf>,
    krl: Option<PathBuf>,
    scan_db: Option<PathBuf>,
    scan_interval_seconds: u64,
) -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let identity = load_serve_identity(cert, relay_key, krl)?;
    let db_path = mailbox_db.to_str().ok_or(Error::InvalidPath)?;
    let conn = relay::open(db_path)?;
    if !relay::licensee_issuer_exists(&conn)? {
        eprintln!("API root is not present; customer keys cannot be minted until api-root generate succeeds");
    }

    let addr: SocketAddr = bind
        .parse()
        .map_err(|e| Error::RelayRequest(format!("invalid bind address: {e}")))?;
    let listener = TcpListener::bind(addr).await?;
    let local = listener.local_addr()?;
    eprintln!("mailbox listening on http://{local}");
    eprintln!("Swagger UI: http://{local}/swagger-ui");
    if let Some(path) = &scan_db {
        eprintln!("TTL file scan: {}", path.display());
    }

    let state = AppState::with_identity(conn, identity);
    spawn_ttl_scan(state.db.clone(), scan_db, scan_interval_seconds);

    axum::serve(listener, relay::router(state))
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

fn spawn_ttl_scan(
    mailbox: Arc<Mutex<rusqlite::Connection>>,
    scan_db: Option<PathBuf>,
    interval_seconds: u64,
) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(interval_seconds));
        loop {
            ticker.tick().await;
            let envelopes = {
                let conn = mailbox
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                relay::purge_expired_envelopes(&conn)
            };
            match envelopes {
                Ok(n) if n > 0 => tracing::info!("purged {n} expired mailbox envelope(s)"),
                Ok(_) => {}
                Err(err) => tracing::warn!("mailbox TTL scan failed: {err}"),
            }
            if let Some(path) = scan_db.as_ref().filter(|path| path.is_file()) {
                let Some(path) = path.to_str() else {
                    tracing::warn!("TTL file scan path is not valid UTF-8");
                    continue;
                };
                match db::open(path).and_then(|conn| locked_files::purge_expired(&conn)) {
                    Ok(n) if n > 0 => tracing::info!("purged {n} expired TTL file(s)"),
                    Ok(_) => {}
                    Err(err) => tracing::warn!("TTL file scan failed: {err}"),
                }
            }
        }
    });
}

async fn shutdown_signal() {
    let _ = signal::ctrl_c().await;
}
