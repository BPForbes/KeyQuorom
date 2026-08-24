//! Command-line interface over the KeyQuorum library: the password vault,
//! password-locked files, and share links. Hardware-key quorum unlocking
//! isn't implemented yet, so it has no CLI surface.

use clap::{Parser, Subcommand};
use keyquorum::error::{Error, Result};
use keyquorum::{db, locked_files, sharing, vault};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

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
    /// Encrypt a file under a password
    Lock {
        source: PathBuf,
        encrypted_path: PathBuf,
    },
    /// Decrypt a password-locked file
    Unlock {
        id: i64,
        /// Write plaintext here instead of stdout
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Manage time-limited share links
    Share {
        #[command(subcommand)]
        command: ShareCommand,
    },
}

#[derive(Subcommand)]
enum VaultCommand {
    /// Store a new credential
    Add {
        label: String,
        #[arg(long)]
        username: Option<String>,
    },
    /// Retrieve a stored credential
    Get { id: i64 },
}

#[derive(Subcommand)]
enum ShareCommand {
    /// Create a share link for a vault credential
    CreateCredential {
        credential_id: i64,
        #[arg(long, default_value_t = 3600)]
        ttl_seconds: i64,
        #[arg(long)]
        max_uses: Option<i64>,
    },
    /// Create a share link for a password-locked file
    CreateFile {
        file_id: i64,
        #[arg(long, default_value_t = 3600)]
        ttl_seconds: i64,
        #[arg(long)]
        max_uses: Option<i64>,
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
    let db_path = db_path.to_str().ok_or(Error::InvalidPath)?;
    let conn = db::open(db_path)?;

    match command {
        Command::Vault { command } => match command {
            VaultCommand::Add { label, username } => {
                let password = prompt_secret("Credential password: ")?;
                let master_password = prompt_secret("Master password: ")?;
                let id = vault::add_credential(
                    &conn,
                    &label,
                    username.as_deref(),
                    &password,
                    &master_password,
                )?;
                println!("Stored credential {id}");
            }
            VaultCommand::Get { id } => {
                let master_password = prompt_secret("Master password: ")?;
                let credential = vault::get_credential(&conn, id, &master_password)?;
                println!("Label:    {}", credential.label);
                println!(
                    "Username: {}",
                    credential.username.as_deref().unwrap_or("-")
                );
                println!("Password: {}", credential.password);
            }
        },
        Command::Lock {
            source,
            encrypted_path,
        } => {
            let password = prompt_secret("Lock password: ")?;
            let id = locked_files::lock_file(&conn, &source, &encrypted_path, &password)?;
            println!("Locked file {id}");
        }
        Command::Unlock { id, output } => {
            let password = prompt_secret("Unlock password: ")?;
            let plaintext = locked_files::unlock_file(&conn, id, &password)?;
            match output {
                Some(path) => locked_files::write_owner_only(&path, &plaintext)?,
                None => io::stdout().write_all(&plaintext)?,
            }
        }
        Command::Share { command } => match command {
            ShareCommand::CreateCredential {
                credential_id,
                ttl_seconds,
                max_uses,
            } => {
                let share =
                    sharing::create_credential_share(&conn, credential_id, ttl_seconds, max_uses)?;
                print_share(&share);
            }
            ShareCommand::CreateFile {
                file_id,
                ttl_seconds,
                max_uses,
            } => {
                let share = sharing::create_file_share(&conn, file_id, ttl_seconds, max_uses)?;
                print_share(&share);
            }
            ShareCommand::RedeemCredential => {
                let token = prompt_secret("Credential share token: ")?;
                let credential_id = sharing::redeem_credential_share(&conn, &token)?;
                println!("Redeemed credential {credential_id}");
            }
            ShareCommand::RedeemFile => {
                let token = prompt_secret("File share token: ")?;
                let file_id = sharing::redeem_file_share(&conn, &token)?;
                println!("Redeemed file {file_id}");
            }
            ShareCommand::RevokeCredential { share_id } => {
                sharing::revoke_credential_share(&conn, share_id)?;
                println!("Revoked credential share {share_id}");
            }
            ShareCommand::RevokeFile { share_id } => {
                sharing::revoke_file_share(&conn, share_id)?;
                println!("Revoked file share {share_id}");
            }
        },
    }

    Ok(())
}

fn print_share(share: &sharing::Share) {
    println!("Share id:   {}", share.id);
    println!("Token:      {}", share.token);
    println!("Expires at: {}", share.expires_at);
}

fn prompt_secret(prompt: &str) -> Result<String> {
    rpassword::prompt_password(prompt).map_err(Error::from)
}
