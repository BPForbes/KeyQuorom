# AGENTS.md

Instructions for AI coding agents (Codex, and similar agent tooling) working in this
repository.

## Project overview

KeyQuorum is a secure file-sharing system centered on hardware key sharing. Files are
encrypted and bound to registered physical tokens (e.g. USB devices). Unlocking a
protected file requires presenting a quorum of the registered hardware keys, providing
layered, hardware-backed access control.

The project is a Rust Cargo crate. Private sign bridges live in `src/private_bridge.rs`
and the `keyquorum` CLI. `create` and `remove-member` generate delivery packages first
and commit only after those files are written — do not persist a live bridge before
the envelopes exist. The two must stay in step in both directions: if the commit
fails, the CLI deletes the `.kqpb` files it just wrote, because `write_owner_only`
refuses to overwrite and leftovers would block the retry.

The mailbox relay (`src/relay/`, `kq-relay`) stores opaque `.kqpb` envelopes and
the canonical *public* split-tree as JSON documents (full context). It must never
unseal envelopes or hold wrapped shares or private keys. `relay push` updates
those documents from the sender's store; `relay pull` returns a sliced copy that
the personal SQLite file translates. A personal SQLite file should keep only the
subgraph that person needs (own lineage, siblings, descendants, and
established-bridge peers plus those peers' ancestors). API keys are shown once;
the relay persists only `hex(SHA-256(raw))`. Customer API keys are minted only
by the licensee (`kq-relay keys create|rotate` with the `kql_…` issuer); HTTP
cannot create or rotate bearers. `keyquorum loadkey` calls `POST /keycheck`
(no auth) and stores that hash plus a sealed bearer in the personal SQLite
file. Later commands re-check the hash and inject the bearer. Never commit
bearers, `.kqpb` files, or the relay database.

## Setup / build / test

- Build: `cargo build`
- Test: `cargo test --locked --all-targets --all-features`
- Lint: `cargo clippy --locked --all-targets --all-features -- -D warnings`
- Format: `cargo fmt`

Run format, lint, and tests before considering any change complete.

## Code style

- Follow standard Rust conventions and `rustfmt` defaults; no project-specific style
  guide exists yet.
- Keep changes minimal and scoped to the request. Avoid speculative abstractions or
  unrelated scaffolding.

## Security

This project handles cryptographic key material, hardware tokens, and encrypted user
files, so treat it as security-sensitive:

- Never commit private keys, tokens, `.env` files, secrets, or plaintext copies of
  protected/test files. See `.gitignore` for excluded patterns (`*.key`, `*.pem`,
  `*.secret`, `*.token`, `*.kqkey`, `*.kqpb`, `*.kqbn`, `secrets/`, `keys/`,
  `test-keys/`, etc.).
- Take extra care with code touching key derivation, encryption/decryption, or
  quorum/threshold logic — bugs there are security bugs, not just correctness bugs.

## Pull requests

- Write clear, descriptive commit messages explaining why a change was made.
- Keep PRs focused on a single logical change where possible.

## Other agent instruction files

This repo also carries `CLAUDE.md` (Claude) and `.cursorrules` (Cursor). Keep guidance
consistent across these files when updating one.
