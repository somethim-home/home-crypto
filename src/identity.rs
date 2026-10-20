//! A person's identities and their sealed record (format §2.1).

use age::secrecy::{ExposeSecret, SecretString};
use age::x25519;

use crate::ids::UserId;
use crate::record::{self, MAX_RECORD_BYTES};
use crate::{Error, agefile};

const KIND: &str = "user-identity";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ScryptCost(u8);

impl ScryptCost {
    pub const SEAL: Self = Self(18);
    pub const UNLOCK_MAX: Self = Self(22);

    /// Accepts 1..=30; age itself panics outside 1..64 and values above 30 need terabytes.
    pub fn new(log_n: u8) -> Result<Self, Error> {
        if (1..=30).contains(&log_n) {
            Ok(Self(log_n))
        } else {
            Err(Error::WorkFactor(log_n))
        }
    }

    pub fn log_n(self) -> u8 {
        self.0
    }
}

/// The recovery identity, shown once to the person and never stored by the client.
pub struct RecoveryKey(x25519::Identity);

impl RecoveryKey {
    pub fn parse(text: &str) -> Result<Self, Error> {
        record::parse_identity(text.trim()).map(Self)
    }

    pub fn to_secret_string(&self) -> SecretString {
        self.0.to_string()
    }
}

#[derive(Clone)]
pub struct UserKeys {
    user_id: UserId,
    grant: x25519::Identity,
    keyring: x25519::Identity,
    recovery_recipient: x25519::Recipient,
}

impl UserKeys {
    /// New identities for a person's first device, with the recovery key to print.
    pub fn generate(user_id: UserId) -> (Self, RecoveryKey) {
        let recovery = x25519::Identity::generate();
        let keys = Self {
            user_id,
            grant: x25519::Identity::generate(),
            keyring: x25519::Identity::generate(),
            recovery_recipient: recovery.to_public(),
        };
        (keys, RecoveryKey(recovery))
    }

    pub fn user_id(&self) -> UserId {
        self.user_id
    }

    /// The only public recipient of a person; published so others can send grants.
    pub fn grant_recipient(&self) -> x25519::Recipient {
        self.grant.to_public()
    }

    pub(crate) fn grant_identity(&self) -> &x25519::Identity {
        &self.grant
    }

    pub(crate) fn keyring_identity(&self) -> &x25519::Identity {
        &self.keyring
    }

    pub(crate) fn keyring_recipient(&self) -> x25519::Recipient {
        self.keyring.to_public()
    }

    /// Replaces the recovery identity; both sealed files must be written again afterwards.
    pub fn new_recovery_key(&mut self) -> RecoveryKey {
        let recovery = x25519::Identity::generate();
        self.recovery_recipient = recovery.to_public();
        RecoveryKey(recovery)
    }

    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let mut w = record::Writer::new(KIND);
        w.field("user-id", &self.user_id.to_string())?;
        w.field("grant-identity", self.grant.to_string().expose_secret())?;
        w.field("keyring-identity", self.keyring.to_string().expose_secret())?;
        w.field("recovery-recipient", &self.recovery_recipient.to_string())?;
        w.finish()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = record::Reader::new(bytes, KIND)?;
        let keys = Self {
            user_id: UserId::from_hex(r.field("user-id")?)?,
            grant: record::parse_identity(r.field("grant-identity")?)?,
            keyring: record::parse_identity(r.field("keyring-identity")?)?,
            recovery_recipient: record::parse_recipient(r.field("recovery-recipient")?)?,
        };
        r.finish()?;
        Ok(keys)
    }

    /// `identity.passphrase.age`.
    pub fn seal_with_passphrase(
        &self,
        passphrase: SecretString,
        cost: ScryptCost,
    ) -> Result<Vec<u8>, Error> {
        let mut recipient = age::scrypt::Recipient::new(passphrase);
        recipient.set_work_factor(cost.log_n());
        agefile::encrypt(&recipient, &self.encode()?)
    }

    /// `identity.recovery.age`.
    pub fn seal_for_recovery(&self) -> Result<Vec<u8>, Error> {
        agefile::encrypt(&self.recovery_recipient, &self.encode()?)
    }

    pub fn unlock_with_passphrase(
        sealed: &[u8],
        passphrase: SecretString,
        max_cost: ScryptCost,
        expected: UserId,
    ) -> Result<Self, Error> {
        let mut identity = age::scrypt::Identity::new(passphrase);
        identity.set_max_work_factor(max_cost.log_n());
        let identities: [&dyn age::Identity; 1] = [&identity];
        let plaintext = agefile::decrypt(identities.into_iter(), sealed, MAX_RECORD_BYTES)?;
        Self::checked(&plaintext, expected)
    }

    pub fn unlock_with_recovery(
        sealed: &[u8],
        recovery: &RecoveryKey,
        expected: UserId,
    ) -> Result<Self, Error> {
        let identities: [&dyn age::Identity; 1] = [&recovery.0];
        let plaintext = agefile::decrypt(identities.into_iter(), sealed, MAX_RECORD_BYTES)?;
        Self::checked(&plaintext, expected)
    }

    fn checked(plaintext: &[u8], expected: UserId) -> Result<Self, Error> {
        let keys = Self::decode(plaintext)?;
        if keys.user_id != expected {
            return Err(Error::WrongUser);
        }
        Ok(keys)
    }
}
