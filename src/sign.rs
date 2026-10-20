//! Ed25519 signatures on grants, rosters and rotations (format §1.2).

use std::fmt;

use age::secrecy::SecretString;
use ed25519_dalek::Signer;
use zeroize::Zeroizing;

use crate::Error;
use crate::ids::{UserId, from_hex, random_bytes, to_hex};

/// A person's Ed25519 key; lives only inside the sealed `user-identity` record.
#[derive(Clone)]
pub(crate) struct SigningKey(ed25519_dalek::SigningKey);

impl SigningKey {
    pub(crate) fn generate() -> Result<Self, Error> {
        let seed = Zeroizing::new(random_bytes::<32>()?);
        Ok(Self(ed25519_dalek::SigningKey::from_bytes(&seed)))
    }

    pub(crate) fn parse(text: &str) -> Result<Self, Error> {
        let seed = Zeroizing::new(from_hex::<32>(text)?);
        Ok(Self(ed25519_dalek::SigningKey::from_bytes(&seed)))
    }

    pub(crate) fn to_secret_string(&self) -> SecretString {
        let seed = Zeroizing::new(self.0.to_bytes());
        SecretString::from(to_hex(seed.as_slice()))
    }

    pub(crate) fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey(self.0.verifying_key())
    }

    pub(crate) fn sign(&self, message: &[u8]) -> Result<Signature, Error> {
        self.0
            .try_sign(message)
            .map(Signature)
            .map_err(|_| Error::Signing)
    }
}

/// Published next to the grant recipient and listed in every roster.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct VerifyingKey(ed25519_dalek::VerifyingKey);

impl VerifyingKey {
    /// Parses 64 lowercase hex characters; weak (small-order) keys are refused.
    pub fn parse(text: &str) -> Result<Self, Error> {
        let key = ed25519_dalek::VerifyingKey::from_bytes(&from_hex::<32>(text)?)
            .map_err(|_| Error::Malformed("verifying key"))?;
        if key.is_weak() {
            return Err(Error::Malformed("weak verifying key"));
        }
        Ok(Self(key))
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), Error> {
        self.0
            .verify_strict(message, &signature.0)
            .map_err(|_| Error::BadSignature)
    }
}

impl fmt::Display for VerifyingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&to_hex(&self.0.to_bytes()))
    }
}

impl fmt::Debug for VerifyingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "VerifyingKey({self})")
    }
}

#[derive(Clone)]
pub(crate) struct Signature(ed25519_dalek::Signature);

impl Signature {
    pub(crate) fn parse(text: &str) -> Result<Self, Error> {
        Ok(Self(ed25519_dalek::Signature::from_bytes(&from_hex::<64>(
            text,
        )?)))
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&to_hex(&self.0.to_bytes()))
    }
}

/// A decoded record whose signature has not been checked yet.
///
/// The content is reachable only through [`Signed::unverified`] (for display, e.g. "invitation from …, as
/// claimed") or after a successful verification.
pub struct Signed<T> {
    value: T,
    signer: UserId,
    message: Zeroizing<Vec<u8>>,
    signature: Signature,
}

impl<T> Signed<T> {
    pub(crate) fn new(value: T, signer: UserId, message: &[u8], signature: Signature) -> Self {
        Self {
            value,
            signer,
            message: Zeroizing::new(message.to_vec()),
            signature,
        }
    }

    /// The claimed signer, as written in the record.
    pub fn signer(&self) -> UserId {
        self.signer
    }

    pub fn unverified(&self) -> &T {
        &self.value
    }

    /// Checks the signature against the claimed signer's key, which the caller looked up and trusts.
    pub fn verify(self, key: &VerifyingKey) -> Result<T, Error> {
        key.verify(&self.message, &self.signature)?;
        Ok(self.value)
    }
}

impl<T: fmt::Debug> fmt::Debug for Signed<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Signed")
            .field("signer", &self.signer)
            .field("unverified", &self.value)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_round_trip_and_weak_keys_are_refused() {
        let key = SigningKey::generate().unwrap();
        let text = age::secrecy::ExposeSecret::expose_secret(&key.to_secret_string()).to_owned();
        let again = SigningKey::parse(&text).unwrap();
        assert_eq!(again.verifying_key(), key.verifying_key());
        let public = key.verifying_key().to_string();
        assert_eq!(VerifyingKey::parse(&public).unwrap(), key.verifying_key());
        assert!(VerifyingKey::parse(&public.to_uppercase()).is_err());
        let identity_point = format!("01{}", "00".repeat(31));
        assert!(VerifyingKey::parse(&identity_point).is_err());
    }

    #[test]
    fn verification_binds_message_and_key() {
        let key = SigningKey::generate().unwrap();
        let other = SigningKey::generate().unwrap();
        let signature = key.sign(b"message").unwrap();
        let signed = |m: &[u8]| Signed::new((), UserId([1; 16]), m, signature.clone());
        assert!(signed(b"message").verify(&key.verifying_key()).is_ok());
        assert!(signed(b"messagf").verify(&key.verifying_key()).is_err());
        assert!(signed(b"message").verify(&other.verifying_key()).is_err());
    }
}
