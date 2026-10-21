# home-crypto docs

| Document | Covers |
| --- | --- |
| [../README.md](../README.md) | What the crate is and is not, where it sits next to Home, latchkey and infra, building and checking, panic paths left in dependencies, findings about the `age` crate |
| [format.md](format.md) | The exact format, version 2: text and signed records, keys per person (`user-identity`, `keyring`), spaces (rosters, grants, adding and removing members), share links, file objects and re-encryption, the manifest (model, merge, view, compaction, binary encoding), format identifiers and versioning, open questions. Own design decisions are marked **[own design]**, unresolved points **[open]** |
| [threat-model.md](threat-model.md) | Assets, actors, what is protected, what the server can still see or do, the web-client caveat, lost keys, an actor-by-actor summary |
| [../tests/vectors/README.md](../tests/vectors/README.md) | The test vectors: which are deterministic, which are not, and how to regenerate them |
| [../SECURITY.md](../SECURITY.md) | How to report a problem; the review status of the format |

## Reading order

Reviewing the design: [threat-model.md](threat-model.md), then [format.md](format.md), then the code in
`src/` (each module maps to a format section: `identity`, `keyring`, `space`, `sign`, `record`, `object`,
`manifest`, `share`).

Using the crate: the [README](../README.md), then `tests/flows.rs`: unlocking an identity, the keyring,
invitations, rosters and rotations (and the forgeries they refuse), and objects across epochs, end to end.

## Related repositories

- [home](https://github.com/somethim-home/home): the server and apps that use this crate; its README has the
  Files API, client flow and data layout.
- [latchkey](https://github.com/somethim/latchkey): sign-in, which is deliberately separate from unlocking files.
- [infra](https://github.com/somethim-home/infra): how the owner's server is deployed.
