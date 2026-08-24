# AGENTS.md

Instructions for AI coding agents (Codex, and similar agent tooling) working in this
repository.

## Project overview

KeyQuorum is a secure file-sharing system centered on hardware key sharing. Files are
encrypted and bound to registered physical tokens (e.g. USB devices). Unlocking a
protected file requires presenting a quorum of the registered hardware keys, providing
layered, hardware-backed access control.

The project is Rust-based. It is currently in an early scaffolding stage — no source
tree, build manifest, or CI pipeline exists yet. Verify a `Cargo.toml` actually exists
before assuming `cargo build`, `cargo test`, or `cargo clippy` will run.

## Setup / build / test

No build system is present yet. Once a Cargo workspace is added:

- Build: `cargo build`
- Test: `cargo test`
- Lint: `cargo clippy --all-targets --all-features`
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
  `*.secret`, `*.token`, `*.kqkey`, `secrets/`, `keys/`, `test-keys/`, etc.).
- Take extra care with code touching key derivation, encryption/decryption, or
  quorum/threshold logic — bugs there are security bugs, not just correctness bugs.

## Pull requests

- Write clear, descriptive commit messages explaining why a change was made.
- Keep PRs focused on a single logical change where possible.

## Other agent instruction files

This repo also carries `CLAUDE.md` (Claude) and `.cursorrules` (Cursor). Keep guidance
consistent across these files when updating one.
