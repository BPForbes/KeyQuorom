# KeyQuorum

KeyQuorum is a secure file-sharing system centered on hardware key sharing. Files are encrypted and bound to registered physical tokens, such as USB devices. Access requires the necessary hardware keys to be presented before a protected file can be unlocked, providing layered, hardware-backed access control.

## Status

Early scaffolding, though the CLI now covers most of what the concept below describes.
Hardware-key quorum splitting/reconstruction is implemented in software (keys are
software keypairs today, not real hardware tokens yet — see Roadmap). No real
hardware/USB integration exists.

## Concept

- A key — the data key protecting a file, or a secret split for its own sake — can be
  divided recursively: split into parts, any of which can itself be split further,
  forming a tree (e.g. a company master key splits across departments, and one
  department's own share splits again across its team). A flat "M-of-N hardware keys"
  quorum is just the simplest one-level tree.
- Unlocking a protected file means reconstructing its key's tree: presenting a quorum of
  the registered keys, rather than a single token or password.
- The goal is layered, hardware-backed access control that resists single-point
  compromise (a lost or stolen key alone should not be enough to unlock protected data).

## Getting Started

Build the CLI with `cargo build --release`; the binary is `target/release/keyquorum`.
Passwords, PINs, and raw quorum shares are always prompted for interactively (or read
from a `--share-file`) rather than taken as plain arguments. Run `keyquorum --help` for
the full command list.

### Keys

```sh
# Generate a keypair. The private key is printed to stdout ONCE and never
# written to disk by this tool — redirect it yourself.
keyquorum key generate --type encryption --public-key-out alice.pub > alice.key
keyquorum key register --type encryption --label alice --public-key-file alice.pub
keyquorum key list
```

### Splitting a key (standalone escrow, or protecting a file)

A key's split tree is described as a JSON file, e.g. `tree.json`:

```json
{
  "label": "root", "threshold": 2,
  "children": [
    { "label": "alice", "hardware_key_id": 1 },
    { "label": "dept", "threshold": 1, "children": [
        { "label": "bob", "hardware_key_id": 2 },
        { "label": "carol", "hardware_key_id": 3 }
    ]}
  ]
}
```

```sh
keyquorum key split --tree-spec tree.json --label "escrow demo"
keyquorum key tree <key-id>
keyquorum key reconstruct <key-id> --share-file <alice-node-id>=alice_share.hex --share-file <bob-node-id>=bob_share.hex

keyquorum access quorum --state 0 --source ./secret.txt --encrypted-path ./secret.txt.kqenc --tree-spec tree.json
keyquorum access quorum --status --id <file-id>
keyquorum access quorum --state 1 --id <file-id> --share-file <alice-node-id>=alice_share.hex --share-file <bob-node-id>=bob_share.hex
```

`<key-id>` and `<file-id>` are printed by `key split`/`access quorum
--state 0` ("Split key 1" / "Locked file 1"). `<alice-node-id>` and
`<bob-node-id>` are each leaf's own node id, printed by `key tree`/
`access quorum --status` — copy them from there. `--share-file` is keyed
by that node id, not the `hardware_key_id` values from the tree-spec JSON
above (a different, unrelated set of ids) — the same hardware key can
back more than one leaf, so only the node id is guaranteed unique.

### Password-protected files and credentials

```sh
keyquorum access password --state 0 --source ./secret.txt --encrypted-path ./secret.txt.kqenc
keyquorum access password --state 1 --id 1 --output ./secret.txt

keyquorum vault add "Email" --username alice
keyquorum vault get 1
```

Either can also take `--pin` to require a 4-digit PIN (attempt-limited, FIDO2-PIN-style)
alongside the password. A successful one-time PIN check is cached for one hour; end that
window early with, for example, `keyquorum pin relock --resource credential --id 1`.

### Signature verification, export, and sharing

```sh
keyquorum verify --public-key-file signer.pub --message-file msg.txt --signature-file msg.sig

keyquorum export credential 1 --recipient-key-file bob.pub --output cred.kqxb
keyquorum export file 1 --recipient-key-file bob.pub --output file.kqxb

keyquorum share create-file 1 --ttl-seconds 3600 --pin
keyquorum share redeem-file
```

## Roadmap

These are deliberately not implemented — not stubbed, just not yet built — because they
all need a private-key custody model (a software file? the OS keychain? real hardware?)
that hasn't been decided:

- **Persisted private-key custody** for `key generate` (today the private key only ever
  goes to stdout).
- **`key unwrap-share`** — turning a stored, sealed quorum share back into the raw share
  a hardware key's own private key would produce.
- **`sign`** — producing a signature (`verify` is implemented).
- **`import`** — opening an `export` bundle on the receiving end (the bundle format and
  encoder are already final).

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
