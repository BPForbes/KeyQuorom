//! KeyQuorum envelope mailbox: store and forward opaque `.kqpb` files.

use clap::{Parser, Subcommand};
use keyquorum::error::{Error, Result};
use keyquorum::relay::{self, ApiKeyScope, AppState, NewApiKey};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use tokio::net::TcpListener;
use tokio::signal;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(
    name = "kq-relay",
    about = "KeyQuorum mailbox relay (opaque .kqpb transport)",
    version
)]
struct Cli {
    /// Path to the relay-only SQLite database (not an organization store)
    #[arg(long, global = true, default_value = "keyquorum-relay.sqlite")]
    db: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Listen for envelope push/pull and API-key administration
    Serve {
        #[arg(long, default_value = "127.0.0.1:8787")]
        bind: String,
    },
    /// Manage API keys in the relay database (no HTTP)
    Keys {
        #[command(subcommand)]
        command: KeysCommand,
    },
}

#[derive(Subcommand)]
enum KeysCommand {
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
    },
    List,
    Revoke {
        id: i64,
    },
    Rotate {
        id: i64,
    },
}

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<()> {
    let cli = Cli::parse();
    let db_path = cli.db.to_str().ok_or(Error::InvalidPath)?;
    match cli.command {
        Command::Serve { bind } => serve(db_path, &bind).await,
        Command::Keys { command } => {
            let conn = relay::open(db_path)?;
            run_keys(&conn, command)
        }
    }
}

fn run_keys(conn: &rusqlite::Connection, command: KeysCommand) -> Result<()> {
    match command {
        KeysCommand::Create {
            scope,
            fingerprint,
            label,
            ttl_seconds,
        } => {
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
        KeysCommand::Rotate { id } => {
            let created = relay::rotate_api_key(conn, id)?;
            println!("Rotated API key {id} -> {}", created.info.id);
            println!("token (shown once): {}", created.token);
        }
    }
    Ok(())
}

async fn serve(db_path: &str, bind: &str) -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let conn = relay::open(db_path)?;
    if let Some(admin) = relay::bootstrap_admin_if_empty(&conn)? {
        eprintln!("Created bootstrap admin API key (shown once):");
        eprintln!("  {}", admin.token);
        eprintln!("Store this; it cannot be recovered from the database.");
    }

    let addr: SocketAddr = bind
        .parse()
        .map_err(|e| Error::RelayRequest(format!("invalid bind address: {e}")))?;
    let listener = TcpListener::bind(addr).await?;
    let local = listener.local_addr()?;
    eprintln!("kq-relay listening on http://{local}");
    eprintln!("Swagger UI: http://{local}/swagger-ui");

    axum::serve(listener, relay::router(AppState::new(conn)))
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

async fn shutdown_signal() {
    let _ = signal::ctrl_c().await;
}
