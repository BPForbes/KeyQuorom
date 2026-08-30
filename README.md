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
Passwords, PINs, and hardware-key material are always prompted for interactively (or read
from a `--share-file` key path) rather than taken as plain arguments. Run `keyquorum --help` for
the full command list.

### Hardware keys

Hardware and tree verbs are top-level (`generate`, `split`, `bind`, …).

```sh
# Generate a keypair. The private key is printed to stdout ONCE and never
# written to disk by this tool — redirect it yourself.
keyquorum generate --type encryption --public-key-out alice.pub --label alice --register > alice.key
keyquorum register --type encryption --label bob --public-key-file bob.pub
keyquorum list
```

`generate --register` writes the public key and records it in one step.
`list` shows hardware keys and every live split tree.

### Splitting a secret (standalone escrow, or protecting a file)

The live SQLite tree **is** the spec. `split`, `bind`, `add`, `revoke`,
`bridge`, and `access quorum --state 0 --leaf` write that tree in place.
There is no JSON file to author first. `tree --output` writes a snapshot
of whatever is stored now. `--tree-spec FILE` remains only for a nested
one-shot tree.

Labels must be unique within a tree. `tree <id> --node A B` prints that
set's lowest common ancestor; `reconstruct --node A B` starts recovery
at that ancestor. `tree` with no id lists every stored spec.

`split --source master.pub` escrows that key file (hex, PEM, or OpenSSH).
`--leaf` builds a one-level tree and binds every sibling pair (so `M.S <-> M.A`
is recorded even after later refreshes). Reconstruct with the holders' key
files and `--output`. A 2-of-2 department tree (`M` = `master.pub`,
`M.S` = `SoftwareDepartment.pub`, `M.A` = `AccountingDepartment.pub`)
reassembles the master from the two department keys:

```sh
keyquorum split --label master --threshold 2 \
  --leaf M.S=SoftwareDepartment.pub --leaf M.A=AccountingDepartment.pub \
  --source master.pub --generate-keys --register
keyquorum reconstruct <key-id> \
  --share-file SoftwareDepartment.pub --share-file AccountingDepartment.pub \
  --output master.pub
# same thing, naming the nodes:
# keyquorum reconstruct <key-id> --node M.S M.A \
#   --share-file SoftwareDepartment.pub --share-file AccountingDepartment.pub \
#   --output master.pub
keyquorum tree
keyquorum tree <key-id> --output org.json
```

`--generate-keys` creates each leaf's `.pub` / `.key` pair; `--register`
records those public keys. Dotted leaf labels (`M.S`, `M.A`) infer the
root node `M`. `--bind M.S=M.A` adds an extra pairing; `--leaf` already
binds sibling leaves.

A `.pub` share file uses the sibling `.key` (or a private-key prompt) to
unwrap that department's sealed share. Both departments are required
because `M`'s threshold is 2.

Later commands keep changing that same tree. Pairings are stored by node
id, so they survive a secret refresh, a new leaf, or a leaf moving to a
new public key:

```sh
# Pair two nodes (whitelist both ways + establish the link)
keyquorum bind <key-id> --node M.S --peer M.A

# Move M.S onto a new token; node id — and the bind — stay put
keyquorum bind <key-id> --node M.S \
  --public-key-file NewSoftware.pub --share-file SoftwareDepartment.key --register

# Grow M to 2-of-3; survivor node ids (and M.S <-> M.A) stay put
keyquorum add <key-id> --parent M --node M.F \
  --public-key-file FinanceDepartment.pub \
  --share-file SoftwareDepartment.pub --share-file AccountingDepartment.pub \
  --generate-keys --register
```

```sh
keyquorum tree 1 --node alice bob
keyquorum reconstruct 1 --node alice bob --share-file alice.pub --share-file bob.key
keyquorum bridge allow 1 --node alice --peer it
keyquorum bridge add 1 --from alice --to it
keyquorum bridge list 1
keyquorum bridge remove 1 --from alice --to it
keyquorum bridge deny 1 --node alice --peer it
```

`bind --peer` is the usual way to stand up `A <-> B`. `bridge allow` /
`deny` change the whitelist only. `bridge add` / `remove` stand up or
tear down an established pairing (add requires a whitelist hit on either
side; deny also drops any pairing).

Banning a hardware key is `revoke <hardware-id>`. That always drops
pairings and whitelist rows for every live leaf sealed to that token.
`--evict` PSS-refreshes survivors of that leaf (`--key-id` / `--node`,
or the unique leaf the token backs). Eviction needs a parent threshold
of at least 2, and every remaining active sibling must be a
hardware-backed leaf — a 1-of-N parent is refused. Binds between
survivors stay. `--share-file` is that sibling's actual key file
(`.pub` / `.key` from `generate` or `split --generate-keys`, or a PEM /
OpenSSH public key). A `.pub` file uses a sibling `.key` when present.

```sh
keyquorum split --label "team escrow" --threshold 2 \
  --leaf alice=alice.pub --leaf bob=bob.pub --leaf carol=carol.pub \
  --generate-keys --register
keyquorum tree <key-id>
keyquorum revoke <carol-hardware-id> --evict \
  --share-file alice.key --share-file bob.pub
# pin a leaf when the token backs more than one:
#   --key-id <key-id> --node carol
```

```sh
keyquorum split --label "escrow demo" --threshold 2 \
  --leaf alice=alice.pub --leaf bob=bob.pub
keyquorum tree <key-id>
keyquorum reconstruct <key-id> --share-file alice.key --share-file bob.pub

keyquorum access quorum --state 0 --source ./secret.txt --encrypted-path ./secret.txt.kqenc \
  --leaf alice=alice.pub --leaf bob=bob.pub --generate-keys --register
keyquorum access quorum --status --id <file-id>
keyquorum access quorum --state 1 --id <file-id> --share-file alice.key --share-file bob.pub
```

`<key-id>` and `<file-id>` are printed by `split` / `access quorum
--state 0` ("Split key 1" / "Locked file 1"). `--share-file` takes the
same key files `generate` wrote (`alice.pub` / `alice.key`) or another
standard public-key file (PEM, OpenSSH `.pub`). The private key unwraps
every leaf sealed to that hardware key. `tree` still prints leaf node
ids for inspection.

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

- **Persisted private-key custody** for `generate` (today the private key only ever
  goes to stdout).
- **`unwrap-share`** — turning a stored, sealed quorum share back into the raw share
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
