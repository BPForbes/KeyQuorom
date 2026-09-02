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

The mailbox relay (`src/relay/`) stores opaque `.kqpb` envelopes and
the canonical *public* split-tree as JSON documents (full context). It must never
unseal envelopes or hold wrapped shares or private keys. `relay push` merges
the sender's public topology into those documents and leaves nodes the sender
does not hold in place; `tree publish` (admin) replaces a document. `relay pull`
returns a sliced copy that the personal SQLite file translates. A personal SQLite
file should keep only the subgraph that person needs (own lineage, siblings,
descendants, and established-bridge peers plus those peers' ancestors). API keys
are shown once; the relay persists only `hex(SHA-256(raw))`. Customer API keys
are minted only by a service provider. `POST /api/v1/{provider_id}/register`
is not API-key protected; the caller must prove possession of hardware
listed in this host's KeyQuorum-signed provider policy. The path provider
id is the group; the hardware public key and fingerprint identify which
service provider registered and when. The KeyQuorum relay identity key
signs that binding. Official clients still only talk to a relay that proves
a KeyQuorum-root-signed cert. The mailbox host is a **hidden**
`keyquorum host` subcommand, compiled only with `--features provider`.
That feature is a build capability, not authorization. A trusted relay also
requires a KeyQuorum-signed `provider.kqcert` and the matching relay
private key; official clients challenge `POST /provider-identity` and
disconnect if the certificate, signature, expiry, capabilities, or
revocation check fails. Do not document
`host` in README or other customer-facing docs — buyers get
a URL and an API key and use `keyquorum loadkey` / `relay push` /
`relay pull`. Default `cargo build` produces `keyquorum` without that
subcommand. `keyquorum loadkey` authenticates the relay, then calls
`POST /keycheck` (no auth) and stores that hash plus a sealed bearer in the
personal SQLite file. Later commands re-check the hash and inject the
bearer. Never commit bearers, `.kqpb` files, `*.kqcert`, `*.kqrl`,
`*.kqpolicy`, provider root keys, or the relay database.

## Setup / build / test

- Build (customer CLI): `cargo build --release` (no mailbox host subcommand)
- Build (provider-capable binary): `cargo build --release --features provider`
  (compiles host capabilities; authorization is a signed `provider.kqcert`)
- Test: `cargo test --locked --all-targets --all-features`
- Lint: `cargo clippy --locked --all-targets --all-features -- -D warnings`
- Format: `cargo fmt`

Run format, lint, and tests before considering any change complete.

## Code style

- Follow standard Rust conventions and `rustfmt` defaults; no project-specific style
  guide exists yet.
- Keep changes minimal and scoped to the request. Avoid speculative abstractions or
  unrelated scaffolding.
- Put tests in their own file next to the module they cover, not in an inline
  `#[cfg(test)]` module inside the implementation. Use `src/<module>/tests.rs`
  (directory module: `#[cfg(test)] mod tests;`) or `src/<module>.rs` with
  `#[cfg(test)] #[path = "<module>/tests.rs"] mod tests;`. Nested files such as
  `src/relay/client.rs` load `src/relay/client/tests.rs` the same way. Shared
  test helpers belong in a `#[cfg(test)]` module, not in production code.

## Security

This project handles cryptographic key material, hardware tokens, and encrypted user
files, so treat it as security-sensitive:

- Never commit private keys, tokens, `.env` files, secrets, or plaintext copies of
  protected/test files. See `.gitignore` for excluded patterns (`*.key`, `*.pem`,
  `*.secret`, `*.token`, `*.kqkey`, `*.kqpb`, `*.kqbn`, `*.kqcert`, `*.kqrl`,
  `*.kqpolicy`, `secrets/`, `keys/`, `provider-secrets/`, `test-keys/`, etc.).
- Take extra care with code touching key derivation, encryption/decryption, or
  quorum/threshold logic — bugs there are security bugs, not just correctness bugs.

## Pull requests

- Write clear, descriptive commit messages explaining why a change was made.
- Keep PRs focused on a single logical change where possible.

## Other agent instruction files

This repo also carries `CLAUDE.md` (Claude) and `.cursorrules` (Cursor). Keep guidance
consistent across these files when updating one.
