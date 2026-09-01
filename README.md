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

### Private sign bridges (per-person stores)

A private sign bridge is an N-person group that can co-sign files. Each
node is its own storage: `M.A.1` is an employee, `M.A` is the accounting
manager, `M` is a cross-department manager (CXO). A bridge of `M.S.2`,
`M.S.3`, and `M.A.2` therefore notifies **five** stores — those three
employees plus department managers `M.S` and `M.A`. The CXO is not in
that set unless a member is itself a department manager.

Members receive a sealed copy of a shared Ed25519 key (plus salts).
Managers receive roster metadata only so they can track the live
standard. This database never keeps another person's sealed secret;
`create` / `remove-member` write one `.kqpb` **envelope** per store.

Those two commands use the same plan-then-commit pattern: they generate
every envelope first, write the files, then persist the new (or rotated)
bridge in this database. Either both land or neither does: a failed write
leaves no live row for that change, and a failed commit deletes the
envelopes it just wrote — they describe a bridge this store never
recorded, and `.kqpb` files are never overwritten, so leaving them behind
would block the retry. Either way, run the command again. There is no
separate "redeliver initial packages" command because a failed create
never commits.

Each `--member` must already have a registered **signing** public key
under that label (`generate --type signing --label M.S.2 --register`).
The roster stores that key. `verify` checks the artifact against the
roster-bound personal key, not a pub declared only on the signature.

Each `.kqpb` is a cryptographic envelope (same idea as `KQXB` export
bundles): the outside names the recipient’s X25519 public key; the inside
is `crypto_box`-sealed so only that store’s encryption private key can
open it. A mailbox, USB drop, or email can carry the envelope without
being able to read the letter. `.kqbn` eviction notices are the
exception — they are public routing slips, not sealed envelopes.

```text
outside (anyone can see)     inside (recipient only)
-------------------------    --------------------------------
KQPB magic, kind             wrap_salt || bridge secret (members)
recipient encryption pub     or roster + salts (managers)
                             roster includes each member's
                             personal signing pub
                             + rotate/destroy auth sig
```

Five people in the example means five envelopes, each addressed to a
different pub. Operators can copy those files out of band, or push them
through the mailbox relay (`keyquorum relay push`) so each store can
`relay pull --import` locally.

```sh
# Each member needs a registered signing public key under their label:
keyquorum generate --type signing --label M.S.2 --register \
  --public-key-out M.S.2.sign.pub > M.S.2.sign.key
# …same for M.S.3 and M.A.2

# On any machine that can see the tree (and manager encryption pubs):
keyquorum bridge private create 1 \
  --member M.S.2 --member M.S.3 --member M.A.2 \
  --supervisor M.S=SoftwareManager.pub --supervisor M.A=AccountingManager.pub \
  --self M.S.2 --output-dir ./bridge-packages --label eng-acct

# Each other person imports into *their* database:
keyquorum --db ma2.sqlite bridge private import \
  --file ./bridge-packages/M.A.2.kqpb --share-file Accounting2.key

# Sign with the bridge key + the member's personal signing key:
keyquorum sign --bridge-uid <uid> --node M.A.2 \
  --signing-key-file Accounting2.sign.key --share-file Accounting2.key \
  --message-file report.pdf --signature-out report.kqbs

# Peer verifies with their membership and the artifact:
keyquorum --db ms2.sqlite verify --bridge-uid <uid> --as-node M.S.2 \
  --message-file report.pdf --signature-file report.kqbs
```

If `M.S` revokes `M.S.3`'s hardware key, that label is dropped from
every live private bridge. Ordinary `revoke` (not only `--evict`)
prints the notify list and writes a `.kqbn` notice **after** the
hardware revoke commits. Remaining members must rotate (the departed
person still holds the old bridge secret). A remaining member then:

```sh
keyquorum bridge private remove-member <uid> --member M.S.3 \
  --node M.S.2 --share-file Software2.key --output-dir ./bridge-packages
# Copy the new packages to M.S.2, M.A.2, M.S, M.A, and M.S.3
# (or `keyquorum relay push --dir ./bridge-packages`).
```

A two-person bridge is destroyed when one member is removed.

Banning a hardware key is `revoke <hardware-id>`. That always drops
pairings and whitelist rows for every live leaf sealed to that token,
and drops that label from every live private sign bridge. `--evict`
PSS-refreshes survivors of that leaf (`--key-id` / `--node`, or the
unique leaf the token backs). Eviction needs a parent threshold of at
least 2, and every remaining active sibling must be a hardware-backed
leaf — a 1-of-N parent is refused. Binds between survivors stay.
`--share-file` is that sibling's actual key file (`.pub` / `.key` from
`generate` or `split --generate-keys`, or a PEM / OpenSSH public key).
A `.pub` file uses a sibling `.key` when present.

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
keyquorum sign --bridge-uid <uid> --node M.A.2 \
  --signing-key-file ma2.sign.key --share-file ma2.key \
  --message-file msg.txt --signature-out msg.kqbs
keyquorum verify --bridge-uid <uid> --as-node M.S.2 \
  --message-file msg.txt --signature-file msg.kqbs

keyquorum export credential 1 --recipient-key-file bob.pub --output cred.kqxb
keyquorum export file 1 --recipient-key-file bob.pub --output file.kqxb

keyquorum share create-file 1 --ttl-seconds 3600 --pin
keyquorum share redeem-file
```

### Mailbox relay

The `kq-relay` binary is a transport-only inbox for sealed `.kqpb` envelopes.
It indexes packages by the recipient X25519 fingerprint in the outer header
and never unseals them. Organization SQLite data and private keys stay on
the device. Put TLS in front of it (Caddy, nginx); the process itself binds
loopback by default.

```sh
# First start mints an admin API key and prints it once.
kq-relay --db keyquorum-relay.sqlite serve --bind 127.0.0.1:8787
# Swagger UI: http://127.0.0.1:8787/swagger-ui

# Host-local key management (talks to the relay SQLite, not HTTP):
kq-relay --db keyquorum-relay.sqlite keys create --scope inbox.push --label ops
kq-relay --db keyquorum-relay.sqlite keys create \
  --scope inbox.pull --fingerprint <hex-sha256-of-recipient-x25519-pub> --label alice
kq-relay --db keyquorum-relay.sqlite keys list
kq-relay --db keyquorum-relay.sqlite keys rotate --id 2
kq-relay --db keyquorum-relay.sqlite keys revoke --id 2
```

Scopes are least-privilege: `inbox.push` uploads, `inbox.pull` reads only
the fingerprint bound to that key, `admin` creates/lists/rotates/revokes
keys over HTTP (`POST /api-keys`, …). Bearers are shown once (`kq_…`);
the database stores `hex(SHA-256(raw))` only.

```sh
export KEYQUORUM_RELAY_URL=http://127.0.0.1:8787
# Prefer KEYQUORUM_RELAY_API_KEY or a prompt; --api-key is for scripts.
keyquorum relay push --dir ./bridge-packages --api-key "$PUSH_KEY"
keyquorum relay pull --output-dir ./inbox --api-key "$PULL_KEY"
keyquorum --db alice.sqlite relay pull --import --share-file alice.key --api-key "$PULL_KEY"
```

Lost or compromised API keys: mint a replacement (`keys rotate` or
`keys create`) and revoke the old id. Envelopes already in the mailbox
are unchanged. Missed pulls: `GET /inbox?after=<id>` (or `--after`)
replays anything not yet downloaded; `bridge private import` still
rejects stale generations.

## Roadmap

[#10](https://github.com/BPForbes/KeyQuorom/issues/10) mailbox transport
(`kq-relay`, API keys, `relay push` / `relay pull --import`) is in place.
Still open on that issue: authenticated envelopes for hardware-key reissue
and key-tree restructure (private-bridge create/rotate/remove-member already
emit `.kqpb` files the relay can carry).

These still need a private-key custody model (a software file, OS keychain, or real hardware) that hasn't been decided:

- **Persisted private-key custody** for `generate` (today the private key only ever
  goes to stdout).
- **`unwrap-share`** — turning a stored, sealed quorum share back into the raw share
  a hardware key's own private key would produce.
- **`import`** of password-vault / locked-file `export` bundles (the bundle format
  and encoder are already final). Private-bridge `.kqpb` import is implemented.

## Security

This project handles cryptographic key material and encrypted user data. Never commit private keys, tokens, secrets, API key bearers, or plaintext copies of protected files to this repository — see `.gitignore` for patterns already excluded.

The mailbox relay is transport only: it cannot decrypt `.kqpb` envelopes and must not be given the organization database or private keys. Store only hashed API keys in the relay SQLite file. Recover a lost bearer by rotating or minting a new key and revoking the old one; recover a missed update by pulling again and importing on the device that holds the matching decryption key.

## Contributing

AI coding agents working in this repository should read the relevant instructions file for their tool:

- `CLAUDE.md` for Claude
- `AGENTS.md` for Codex and other agent tooling
- `.cursorrules` for Cursor

Code review automation is configured via `.coderabbit.yaml`.

## License

Licensed under the MIT License. See [LICENSE](LICENSE) for details.
