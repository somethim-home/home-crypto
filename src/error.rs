//! Errors returned by this crate.

use std::fmt;

use crate::ids::UserId;

#[derive(Debug)]
pub enum Error {
    Encrypt(age::EncryptError),
    /// age refused to decrypt: wrong key, corrupted or truncated ciphertext, or excessive work factor.
    Decrypt(age::DecryptError),
    Io(std::io::Error),
    Random,
    /// Input does not follow the format; the text names the rule that failed.
    Malformed(&'static str),
    TooLarge,
    WorkFactor(u8),
    WrongUser,
    WrongSpace,
    WrongObject,
    RecipientMismatch,
    Rollback {
        seen: u64,
        got: u64,
    },
    Equivocation,
    Overflow,
    Signing,
    /// The signature does not verify against the signer's key.
    BadSignature,
    /// A record that must be signed carries no `signature` line.
    Unsigned,
    /// The signer is not allowed to make this change (not an admin of the trusted roster, or removed by it).
    NotAuthorized,
    /// A verifying key differs from the one pinned for that person.
    KeyChanged {
        user: UserId,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Encrypt(e) => write!(f, "encryption failed: {e}"),
            Self::Decrypt(e) => write!(f, "decryption failed: {e}"),
            Self::Io(e) => write!(f, "i/o error: {e}"),
            Self::Random => f.write_str("random number generator failed"),
            Self::Malformed(rule) => write!(f, "malformed input: {rule}"),
            Self::TooLarge => f.write_str("plaintext exceeds the size limit"),
            Self::WorkFactor(n) => write!(f, "scrypt work factor {n} outside the accepted range"),
            Self::WrongUser => f.write_str("record belongs to a different user"),
            Self::WrongSpace => f.write_str("record belongs to a different space or epoch"),
            Self::WrongObject => f.write_str("object id does not match"),
            Self::RecipientMismatch => {
                f.write_str("grant does not match the rotation's recipient fingerprint")
            }
            Self::Rollback { seen, got } => {
                write!(
                    f,
                    "keyring version {got} is older than version {seen} already seen"
                )
            }
            Self::Equivocation => f.write_str("same operation id with different content"),
            Self::Overflow => f.write_str("counter overflow"),
            Self::Signing => f.write_str("signing failed"),
            Self::BadSignature => f.write_str("signature does not verify"),
            Self::Unsigned => f.write_str("record is not signed"),
            Self::NotAuthorized => f.write_str("signer is not authorised for this change"),
            Self::KeyChanged { user } => {
                write!(f, "verifying key of {user} differs from the pinned key")
            }
        }
    }
}

impl std::error::Error for Error {}

impl From<age::EncryptError> for Error {
    fn from(e: age::EncryptError) -> Self {
        Self::Encrypt(e)
    }
}

impl From<age::DecryptError> for Error {
    fn from(e: age::DecryptError) -> Self {
        Self::Decrypt(e)
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}
