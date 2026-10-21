# Security policy

## Status of the format

home-crypto is **unreviewed**. The format (docs/format.md) composes age and Ed25519 in our own way, and that
composition is **pending an external cryptographic review**. Until the review is done and its findings are
addressed, do not rely on it to protect real data, and expect the format to change (format identifiers and
versioning are in docs/format.md §8).

Known limits are documented rather than hidden: see docs/threat-model.md ("What is not protected",
"Web-client trust caveat") and the **[open]** points in docs/format.md. A report that one of those limits
exists is welcome but not a vulnerability in itself; a report that the format fails to give a protection the
threat model claims is exactly what we want to hear.

## Reporting a problem

Please report privately, not in a public issue:

- GitHub: **Security → Report a vulnerability** on this repository (private vulnerability reporting), or
- e-mail: contact@arbikullakshi.com, with "home-crypto security" in the subject.

Include what you found, the commit you looked at, and if you can a test or test vector that shows it. You will
get an answer within a week; fixes are made in the open once a fix is ready. There is no bug bounty: this is a
personal project.

## Scope

In scope: this crate's code, the format and the threat model. Problems in the server, the apps or the sign-in
belong to [home](https://github.com/somethim-home/home) or [latchkey](https://github.com/somethim/latchkey);
problems in age or ed25519-dalek themselves belong upstream (please tell us too, so we can pin a fixed
version).
