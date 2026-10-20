//! A person's accepted spaces (format §2.2), the source of truth for space identities.

use std::collections::BTreeMap;

use age::secrecy::ExposeSecret;

use crate::identity::UserKeys;
use crate::ids::{SpaceId, UserId};
use crate::record::{self, MAX_RECORD_BYTES, parse_u64};
use crate::sign::{Signed, VerifyingKey};
use crate::space::{Epoch, Grant, Roster, SpaceKey};
use crate::{Error, agefile};

const KIND: &str = "keyring";

/// How a verifying key relates to the pins (trust on first use).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Trust {
    /// The key equals the pinned key.
    Pinned,
    /// No key is pinned for this person yet; show their fingerprint before relying on it.
    FirstUse,
}

#[derive(Clone, Debug)]
pub struct Keyring {
    user_id: UserId,
    version: u64,
    keys: BTreeMap<(SpaceId, Epoch), SpaceKey>,
    pins: BTreeMap<UserId, VerifyingKey>,
}

impl Keyring {
    pub fn new(user_id: UserId) -> Self {
        Self {
            user_id,
            version: 0,
            keys: BTreeMap::new(),
            pins: BTreeMap::new(),
        }
    }

    pub fn version(&self) -> u64 {
        self.version
    }

    pub fn insert(&mut self, key: SpaceKey) {
        self.keys.insert((key.space_id(), key.epoch()), key);
    }

    pub fn remove_space(&mut self, space_id: SpaceId) {
        self.keys.retain(|(id, _), _| *id != space_id);
    }

    pub fn space_keys(&self, space_id: SpaceId) -> Vec<&SpaceKey> {
        self.keys
            .range((space_id, Epoch(0))..=(space_id, Epoch(u32::MAX)))
            .map(|(_, k)| k)
            .collect()
    }

    pub fn latest(&self, space_id: SpaceId) -> Option<&SpaceKey> {
        self.space_keys(space_id).last().copied()
    }

    pub fn spaces(&self) -> Vec<SpaceId> {
        let mut ids: Vec<SpaceId> = self.keys.keys().map(|(id, _)| *id).collect();
        ids.dedup();
        ids
    }

    pub fn pinned(&self, user: UserId) -> Option<&VerifyingKey> {
        self.pins.get(&user)
    }

    /// Compares `key` with the pin for `user`; a different key is an error, never silently replaced.
    pub fn check_pin(&self, user: UserId, key: &VerifyingKey) -> Result<Trust, Error> {
        match self.pins.get(&user) {
            None => Ok(Trust::FirstUse),
            Some(pinned) if pinned == key => Ok(Trust::Pinned),
            Some(_) => Err(Error::KeyChanged { user }),
        }
    }

    /// Pins `key` for `user` on first use; fails if a different key is pinned.
    pub fn pin(&mut self, user: UserId, key: VerifyingKey) -> Result<Trust, Error> {
        let trust = self.check_pin(user, &key)?;
        self.pins.insert(user, key);
        Ok(trust)
    }

    /// Pins every member of an accepted roster, or none if any of them conflicts with a pin.
    pub fn pin_members(&mut self, roster: &Roster) -> Result<(), Error> {
        for m in &roster.members {
            self.check_pin(m.user_id, &m.verifying_key)?;
        }
        for m in &roster.members {
            self.pins.insert(m.user_id, m.verifying_key);
        }
        Ok(())
    }

    /// Replaces a pin after the person confirmed the new fingerprint out of band.
    pub fn replace_pin(&mut self, user: UserId, key: VerifyingKey) {
        self.pins.insert(user, key);
    }

    /// Verifies an invitation against the pinned key of its signer, or `published` (the key the server
    /// lists next to the signer's grant recipient) on first use. A published key that differs from the pin
    /// is reported as [`Error::KeyChanged`].
    pub fn verify_invitation(
        &self,
        grant: Signed<Grant>,
        published: &VerifyingKey,
    ) -> Result<(Grant, Trust), Error> {
        let trust = self.check_pin(grant.signer(), published)?;
        Ok((grant.verify(published)?, trust))
    }

    /// Union with a concurrently written keyring; the result is written as the next version.
    /// Conflicting pins for the same person are refused.
    pub fn merge(&mut self, other: &Keyring) -> Result<(), Error> {
        if other.user_id != self.user_id {
            return Err(Error::WrongUser);
        }
        for (user, key) in &other.pins {
            self.check_pin(*user, key)?;
        }
        self.pins.extend(other.pins.iter().map(|(u, k)| (*u, *k)));
        for (slot, key) in &other.keys {
            self.keys.entry(*slot).or_insert_with(|| key.clone());
        }
        self.version = self.version.max(other.version);
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let mut w = record::Writer::new(KIND);
        w.field("user-id", &self.user_id.to_string())?;
        w.field("version", &self.version.to_string())?;
        for ((space_id, epoch), key) in &self.keys {
            let line = format!(
                "{space_id} {} {}",
                epoch.0,
                key.identity_string().expose_secret()
            );
            w.field("space", &line)?;
        }
        for (user, key) in &self.pins {
            w.field("pin", &format!("{user} {key}"))?;
        }
        w.finish()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = record::Reader::new(bytes, KIND)?;
        let user_id = UserId::from_hex(r.field("user-id")?)?;
        let version = parse_u64(r.field("version")?)?;
        let mut keys = BTreeMap::new();
        let mut previous = None;
        for line in r.repeated("space")? {
            let mut parts = line.split(' ');
            let (id, epoch, identity) =
                match (parts.next(), parts.next(), parts.next(), parts.next()) {
                    (Some(id), Some(epoch), Some(identity), None) => (id, epoch, identity),
                    _ => return Err(Error::Malformed("space line")),
                };
            let slot = (SpaceId::from_hex(id)?, Epoch::parse(epoch)?);
            if previous.is_some_and(|p| p >= slot) {
                return Err(Error::Malformed("space lines must be sorted and unique"));
            }
            previous = Some(slot);
            let identity = record::parse_identity(identity)?;
            keys.insert(slot, SpaceKey::from_identity(slot.0, slot.1, identity));
        }
        let mut pins = BTreeMap::new();
        let mut previous = None;
        for line in r.repeated("pin")? {
            let (user, key) = line.split_once(' ').ok_or(Error::Malformed("pin line"))?;
            let user = UserId::from_hex(user)?;
            if previous.is_some_and(|p| p >= user) {
                return Err(Error::Malformed("pin lines must be sorted and unique"));
            }
            previous = Some(user);
            pins.insert(user, VerifyingKey::parse(key)?);
        }
        r.finish()?;
        Ok(Self {
            user_id,
            version,
            keys,
            pins,
        })
    }

    /// Increments the version and encrypts to the keyring recipient, which the server never sees.
    pub fn seal(&mut self, keys: &UserKeys) -> Result<Vec<u8>, Error> {
        if keys.user_id() != self.user_id {
            return Err(Error::WrongUser);
        }
        self.version = self.version.checked_add(1).ok_or(Error::Overflow)?;
        agefile::encrypt(&keys.keyring_recipient(), &self.encode()?)
    }

    /// `highest_seen` is the highest version this device has opened before (0 on a new device).
    pub fn open(sealed: &[u8], keys: &UserKeys, highest_seen: u64) -> Result<Self, Error> {
        let identities: [&dyn age::Identity; 1] = [keys.keyring_identity()];
        let keyring = Self::decode(&agefile::decrypt(
            identities.into_iter(),
            sealed,
            MAX_RECORD_BYTES,
        )?)?;
        if keyring.user_id != keys.user_id() {
            return Err(Error::WrongUser);
        }
        if keyring.version < highest_seen {
            return Err(Error::Rollback {
                seen: highest_seen,
                got: keyring.version,
            });
        }
        Ok(keyring)
    }
}
