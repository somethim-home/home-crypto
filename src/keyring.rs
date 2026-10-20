//! A person's accepted spaces (format §2.2), the source of truth for space identities.

use std::collections::BTreeMap;

use age::secrecy::ExposeSecret;

use crate::identity::UserKeys;
use crate::ids::{SpaceId, UserId};
use crate::record::{self, MAX_RECORD_BYTES, parse_u64};
use crate::space::{Epoch, SpaceKey};
use crate::{Error, agefile};

const KIND: &str = "keyring";

#[derive(Clone, Debug)]
pub struct Keyring {
    user_id: UserId,
    version: u64,
    keys: BTreeMap<(SpaceId, Epoch), SpaceKey>,
}

impl Keyring {
    pub fn new(user_id: UserId) -> Self {
        Self {
            user_id,
            version: 0,
            keys: BTreeMap::new(),
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

    /// Union with a concurrently written keyring; the result is written as the next version.
    pub fn merge(&mut self, other: &Keyring) -> Result<(), Error> {
        if other.user_id != self.user_id {
            return Err(Error::WrongUser);
        }
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
        r.finish()?;
        Ok(Self {
            user_id,
            version,
            keys,
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
