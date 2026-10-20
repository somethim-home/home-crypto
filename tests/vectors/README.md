# Test vectors

Inputs are fixed in `tests/vectors.rs`: six X25519 identities generated once with `age-keygen` (Go age 1.3.2),
user ids `a1…a1` (Alice) and `b0…b0` (Bob), space id `5a…5a`, object id `0b…0b`, passphrase
`correct horse battery staple` (scrypt `log_n = 10`, test-only cost).

Deterministic — `cargo test --test vectors` rebuilds these from the fixed inputs and compares byte for byte:

| File | Content |
| --- | --- |
| `user-identity.txt` | Alice's `user-identity` record |
| `keyring.txt` | Alice's keyring, version 3, epochs 1 and 2 of the space |
| `grant.txt` | Grant of epoch 1 from Alice |
| `roster.txt` | Epoch 1 roster: Alice admin, Bob read; non-ASCII name |
| `rotation.txt` | Rotation 1 → 2 removing Bob |
| `manifest-snapshot.bin` | Manifest with a dir, a delete, a file and one concurrent write (one conflict) |
| `object-content.bin` | 70 000 bytes of object content (crosses one 64 KiB chunk boundary) |
| `share-link.txt` | Share link for epoch 1 |
| `fingerprints.txt` | Recipient fingerprints and safety numbers of epochs 1 and 2 |

Not deterministic — age draws a fresh file key, nonce and ephemeral key (or scrypt salt) from the OS RNG on every
encryption, and the `age` crate offers no way to inject randomness. These were generated once and are only
checked by decryption against the deterministic files above:

| File | Encrypted to |
| --- | --- |
| `identity.passphrase.age` | scrypt passphrase |
| `identity.recovery.age` | recovery recipient |
| `keyring.age` | Alice's keyring recipient |
| `grant.age` | Bob's grant recipient |
| `roster.age`, `rotation.age`, `object.age` | epoch 1 space recipient |
| `manifest-snapshot.age` | epoch 2 space recipient |

Regenerate everything (ciphertexts will differ, plaintexts must not):

```
cargo test --test vectors -- --ignored regenerate
```

Interoperability check done when generating, with the Go reference implementation:

```
age -d -i epoch1.key object.age | tail -c +22 | cmp - object-content.bin
age -d -i epoch1.key roster.age | cmp - roster.txt
```
