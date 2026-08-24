# KeyQuorum

KeyQuorum is a secure file-sharing system centered on hardware key sharing. Files are encrypted and bound to registered physical tokens, such as USB devices. Access requires the necessary hardware keys to be presented before a protected file can be unlocked, providing layered, hardware-backed access control.

## Status

Early scaffolding. Core architecture, encryption scheme, and hardware-key protocol are still being designed and implemented.

## Concept

- Files are encrypted at rest and bound to one or more registered hardware tokens.
- Unlocking a protected file requires presenting a quorum of the registered keys, rather than a single token or password.
- The goal is layered, hardware-backed access control that resists single-point compromise (a lost or stolen token alone should not be enough to unlock protected data).

## Getting Started

Build the CLI with `cargo build --release`; the binary is `target/release/keyquorum`.

The hardware-key quorum flow isn't implemented yet, but the CLI already covers what's
built so far — the password vault, password-locked files, and share links:

```sh
keyquorum lock ./secret.txt ./secret.txt.kqenc
keyquorum unlock 1 --output ./secret.txt

keyquorum vault add "Email" --username alice
keyquorum vault get 1

keyquorum share create-file 1 --ttl-seconds 3600
keyquorum share redeem-file
```

Passwords and share tokens are always prompted for interactively rather than taken as
arguments. Run `keyquorum --help` for the full command list.

## Security

This project handles cryptographic key material and encrypted user data. Never commit private keys, tokens, secrets, or plaintext copies of protected files to this repository — see `.gitignore` for patterns already excluded.

## Contributing

AI coding agents working in this repository should read the relevant instructions file for their tool:

- `CLAUDE.md` for Claude
- `AGENTS.md` for Codex and other agent tooling
- `.cursorrules` for Cursor

Code review automation is configured via `.coderabbit.yaml`.

## License

Licensed under the MIT License. See [LICENSE](LICENSE) for details.
