//! Provider-only mailbox host. Compiled only with `--features provider`.
//! Hidden from `keyquorum --help`. Customers use `loadkey` with a URL
//! and bearer they were given.

use clap::Subcommand;
use keyquorum::error::{Error, Result};
use keyquorum::relay::{ApiKeyScope, AppState, NewApiKey};
use keyquorum::{db, locked_files, relay};
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
        /// Personal/org SQLite to scan for date-based TTL files. Defaults
        /// to the global `--db` when that file already exists.
        #[arg(long)]
        scan_db: Option<PathBuf>,
        /// How often to delete expired mailbox envelopes and TTL files.
        #[arg(long, default_value_t = 60, value_parser = clap::value_parser!(u64).range(1..))]
        scan_interval_seconds: u64,
    },
    /// Mint, list, rotate, or revoke API keys on this host (not over HTTP)
    Keys {
        #[command(subcommand)]
        command: KeysCommand,
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
    let db_path = mailbox_db.to_str().ok_or(Error::InvalidPath)?;
    match command {
        HostCommand::Serve {
            bind,
            scan_db,
            scan_interval_seconds,
        } => {
            let scan_db = scan_db.or_else(|| org_db.is_file().then(|| org_db.to_path_buf()));
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .map_err(Error::Io)?
                .block_on(serve(db_path, &bind, scan_db, scan_interval_seconds))
        }
        HostCommand::Keys { command } => {
            let conn = relay::open(db_path)?;
            run_keys(&conn, command)
        }
    }
}

fn print_new_licensee(issuer: &relay::CreatedLicensee) {
    eprintln!("Created licensee issuer key (shown once):");
    eprintln!("  {}", issuer.token);
    eprintln!("Only this key can mint or rotate customer API keys.");
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
    let supplied = licensee_key.filter(|s| !s.is_empty()).or_else(|| {
        match std::env::var("KEYQUORUM_LICENSEE_KEY") {
            Ok(key) if !key.is_empty() => Some(key),
            _ => None,
        }
    });
    if let Some(issuer) = relay::authorize_licensee_or_bootstrap(conn, supplied.as_deref())? {
        print_new_licensee(&issuer);
        return Ok(());
    }
    if supplied.is_none() {
        require_licensee(conn, None)?;
    }
    Ok(())
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

async fn serve(
    db_path: &str,
    bind: &str,
    scan_db: Option<PathBuf>,
    scan_interval_seconds: u64,
) -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let conn = relay::open(db_path)?;
    if let Some(issuer) = relay::bootstrap_licensee_if_empty(&conn)? {
        print_new_licensee(&issuer);
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

    let state = AppState::new(conn);
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
