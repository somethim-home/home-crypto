//! End-to-end encryption format for Home Files, built only on the `age` format.
//!
//! The format is specified in `docs/format.md`; the threat model in `docs/threat-model.md`.
//! Unreviewed: do not use for real data before an external review.

#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::unreachable,
        clippy::todo,
        clippy::unimplemented
    )
)]

mod agefile;
mod binary;
pub mod error;
pub mod identity;
pub mod ids;
pub mod keyring;
pub mod manifest;
pub mod object;
mod record;
pub mod share;
pub mod space;

pub use age::secrecy::{ExposeSecret, SecretString};
pub use error::Error;
