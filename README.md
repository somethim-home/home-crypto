# home-crypto

**Status: unreviewed — do not use for real data before an external review.**

End-to-end encryption for Home Files, the family file storage on the home server. One Rust crate shared by every
client (desktop, Android, web via wasm, iOS later via uniffi) and by the `home-files` backend, which uses it for
format validation only and never holds a key.

Everything is built on the [age](https://c2sp.org/age) format through the official `age` crate (pinned
`=0.12.1`): X25519 recipients, scrypt passphrase recipients and the STREAM payload. There are no new
cryptographic primitives. The design decides only *which* age file is encrypted to *which* recipients, and that
layer is what needs the review.

- `docs/threat-model.md`: assets, actors, what is protected, the metadata the server still sees, the web-client
  caveat, and what happens when keys are lost.
- `docs/format.md`: the exact format. Our own design decisions are marked **[own design]** and unresolved
  points **[open]**.

## What it is

- Person identities: create, seal with a passphrase (scrypt) and with a printed recovery key, unlock either way,
  change the passphrase, replace the recovery key.
- Keyring: the person's accepted spaces and every epoch key of each. It has a version counter that detects
  rollback.
- Spaces: per-epoch identities, grants (invitations), rosters, and rotation records for removing a member.
- File objects: streaming encryption and decryption with SHA-256 of the content, seekable range reads, a check
  that the object id matches, and re-encryption to a new epoch.
- Manifest: a canonical binary encoding plus encrypted segments, with deterministic merge (commutative,
  associative, idempotent), conflict detection and compaction.
- Share links: the space key travels in the URL fragment.

## What it is not

- Not a server, client or sync engine. Transport, storage, quotas and authentication (home-auth) live elsewhere.
- Not authenticated between members. age has no signatures, so members of a space trust each other, and grants
  can be forged by the server (see the threat model).
- Not metadata-private. Object ids, sizes, times, membership and access patterns are visible to the server.
- Not post-quantum. It uses X25519 only.
- Not protected against a malicious web bundle. A browser client trusts the server that delivers its code.

## Building and checking

```
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo check --target wasm32-unknown-unknown
```

Test vectors live in `tests/vectors/`; their README explains which are deterministic and how to regenerate them.
Property tests in `tests/manifest_props.rs` cover merge, compaction, encoding and parser robustness. A cargo-fuzz
target for the manifest parser is in `fuzz/`. Running it needs nightly and `cargo install cargo-fuzz`:

```
cd fuzz && cargo +nightly fuzz run manifest_decode seeds/manifest_decode
```

## Safety notes

- `#![forbid(unsafe_code)]`. The library code has no `unwrap`, `expect`, `panic!`, `unreachable!` or slice
  indexing; clippy denies these outside tests.
- Panic paths that remain in dependencies:
  - age draws its randomness from `rand::rngs::OsRng`, which panics if the OS random number generator fails.
    This affects key generation and every encryption. This crate's own ids use `getrandom` and return an error
    instead.
  - `age::scrypt::Recipient::set_work_factor` asserts `0 < log_n < 64`. `ScryptCost` only allows 1–30, so the
    assertion cannot fire.
  - age's STREAM writer and reader assert internal invariants on chunk sizes.
- The scrypt identity refuses work factors above `ScryptCost::UNLOCK_MAX` (22), so a hostile identity file cannot
  make unlocking run for hours.

## Findings about the `age` crate (0.12.1)

- **Header re-wrapping is not possible through the public API.** `Encryptor` always generates a fresh file key,
  and `Decryptor` never exposes the header or the file key. Re-wrapping would mean reimplementing age header
  parsing, serialisation and the header MAC on top of `age-core`. Removing a member therefore re-encrypts each
  object instead (format §6.3). This is an open question.
- The scrypt stanza must be the only stanza in a file, so the passphrase and recovery seals are two separate
  files.
- Seekable decryption works: `StreamReader` implements `Seek` when the input is `Read + Seek`.
- There is no way to inject randomness, so ciphertext test vectors cannot be reproduced exactly.
- There is no hybrid post-quantum identity (Go age 1.3 has `age1pq…`; the Rust crate only has the
  encrypt-only `tag`/`tagpq` recipients).
- It builds for `wasm32-unknown-unknown` once `getrandom`'s `js` feature is enabled, which `Cargo.toml` does
  for that target. Without age's `web-sys` feature, scrypt calibration falls back to a fixed guess. This crate
  always sets the work factor explicitly, so that does not matter here.

## Licence

None yet; the owner will choose one later. All rights reserved for now (see `LICENSE`).
