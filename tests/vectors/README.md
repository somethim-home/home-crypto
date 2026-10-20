# Test vectors

Inputs are fixed in `tests/vectors.rs`: six X25519 identities generated once with `age-keygen` (Go age 1.3.2),
two Ed25519 seeds (Alice's and Bob's signing keys) generated once with
`head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n'`, user ids `a1…a1` (Alice) and `b0…b0` (Bob), space id
`5a…5a`, object id `0b…0b`, passphrase `correct horse battery staple` (scrypt `log_n = 10`, test-only cost).

Ed25519 signatures are deterministic, so the signed records below are byte-for-byte reproducible.

Deterministic — `cargo test --test vectors` rebuilds these from the fixed inputs and compares byte for byte:

| File | Content |
| --- | --- |
| `user-identity.txt` | Alice's `user-identity` record, including her signing key |
| `keyring.txt` | Alice's keyring, version 3, epochs 1 and 2 of the space, pins for Alice and Bob |
| `grant.txt` | Grant of epoch 1 to Bob, signed by Alice |
| `roster.txt` | Epoch 1 roster: Alice admin, Bob read, with verifying keys; non-ASCII name; signed by Alice |
| `rotation.txt` | Rotation 1 → 2 removing Bob, signed by Alice |
| `manifest-snapshot.bin` | Manifest with a dir, a delete, a file and one concurrent write (one conflict) |
| `object-content.bin` | 70 000 bytes of object content (crosses one 64 KiB chunk boundary) |
| `share-link.txt` | Share link for epoch 1 |
| `fingerprints.txt` | Recipient fingerprints and safety numbers of epochs 1 and 2; verifying key, person fingerprint and safety number of Alice and Bob |

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

The format-version-2 regeneration rewrote every `.txt` vector and the ciphertexts of the five records; the
`object.age` and `manifest-snapshot.age` ciphertexts were restored from version 1 (`git checkout`), since the
object and manifest encodings did not change.

Interoperability check done when generating, with the Go reference implementation:

```
age -d -i epoch1.key object.age | tail -c +22 | cmp - object-content.bin
age -d -i epoch1.key roster.age | cmp - roster.txt
age -d -i epoch1.key rotation.age | cmp - rotation.txt
age -d -i bob-grant.key grant.age | cmp - grant.txt
```

and, for the signatures, with an independent Ed25519 implementation (Python `cryptography` 50, OpenSSL
backend): for `grant.txt`, `roster.txt` and `rotation.txt`, the bytes before the last line verify against
Alice's verifying key, re-signing them with Alice's seed gives the same signature, and the person fingerprints
in `fingerprints.txt` equal `SHA-256("home-crypto/v2/person <user-id> <grant recipient> <verifying key>")`.
