# CLAUDE.md

Guidance for Claude Code (and other Claude-based agents) working in this repository.

## Project overview

KeyQuorum is a secure file-sharing system centered on hardware key sharing. Files are
encrypted and bound to registered physical tokens (e.g. USB devices). Unlocking a
protected file requires presenting a quorum of the registered hardware keys, providing
layered, hardware-backed access control.

The project is a Rust Cargo crate (see `.gitignore` for Cargo-related patterns).
Private sign bridges live in `src/private_bridge.rs` and the `keyquorum` CLI.
`create` and `remove-member` generate delivery packages first and commit only after
those files are written — do not persist a live bridge before the envelopes exist.
The two must stay in step in both directions: if the commit fails, the CLI deletes
the `.kqpb` files it just wrote, because `write_owner_only` refuses to overwrite and
leftovers would block the retry.

## Working conventions

- Keep changes minimal and scoped to what's requested — don't scaffold unrelated
  modules, abstractions, or tooling ahead of need.
- After Rust work, run `cargo build`, `cargo fmt`,
  `cargo clippy --locked --all-targets --all-features -- -D warnings`, and
  `cargo test --locked --all-targets --all-features` before considering a change
  complete.
- Match existing code style; this repo has no established style guide yet, so follow
  standard Rust conventions (`rustfmt` defaults) unless told otherwise.

## Security

This project deals directly with cryptographic key material, hardware tokens, and
encrypted user files. Treat it as security-sensitive:

- Never commit private keys, tokens, `.env` files, secrets, or plaintext copies of
  protected/test files. See `.gitignore` for patterns already excluded (`*.key`,
  `*.pem`, `*.secret`, `*.token`, `*.kqkey`, `*.kqpb`, `*.kqbn`, `secrets/`,
  `keys/`, `test-keys/`, etc.).
- Be extra careful with any code touching key derivation, encryption/decryption, or
  quorum/threshold logic — correctness bugs here are security bugs.
- Flag anything that looks like a hardcoded secret or credential before committing.

## Other agent instruction files

This repo also carries `AGENTS.md` (Codex and other agent tooling) and `.cursorrules`
(Cursor). Keep guidance consistent across these files when updating one.
