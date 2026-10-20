//! Space identities, grants, rosters and rotations (format §3).

use std::fmt;

use age::secrecy::ExposeSecret;
use age::x25519;
use sha2::{Digest, Sha256};

use crate::identity::UserKeys;
use crate::ids::{SpaceId, UserId, from_hex, to_hex};
use crate::record::{self, MAX_RECORD_BYTES, parse_u64, strictly_sorted};
use crate::{Error, agefile};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Epoch(pub u32);

impl Epoch {
    pub const FIRST: Self = Self(1);

    pub fn next(self) -> Result<Self, Error> {
        self.0.checked_add(1).map(Self).ok_or(Error::Overflow)
    }

    pub(crate) fn parse(text: &str) -> Result<Self, Error> {
        let n = u32::try_from(parse_u64(text)?).map_err(|_| Error::Malformed("epoch"))?;
        if n == 0 {
            return Err(Error::Malformed("epoch"));
        }
        Ok(Self(n))
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Fingerprint(pub [u8; 32]);

impl Fingerprint {
    pub fn of(recipient: &x25519::Recipient) -> Self {
        Self(Sha256::digest(recipient.to_string().as_bytes()).into())
    }

    /// First 16 bytes in groups of four hex digits, for comparison in person.
    pub fn safety_number(&self) -> String {
        let hex = to_hex(self.0.get(..16).unwrap_or(&[]));
        let groups: Vec<&str> = hex
            .as_bytes()
            .chunks(4)
            .filter_map(|c| std::str::from_utf8(c).ok())
            .collect();
        groups.join(" ")
    }
}

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&to_hex(&self.0))
    }
}

impl fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Fingerprint({self})")
    }
}

#[derive(Clone)]
pub struct SpaceKey {
    space_id: SpaceId,
    epoch: Epoch,
    identity: x25519::Identity,
}

impl SpaceKey {
    pub fn generate(space_id: SpaceId, epoch: Epoch) -> Self {
        Self::from_identity(space_id, epoch, x25519::Identity::generate())
    }

    /// Restores a key from its `AGE-SECRET-KEY-1…` string.
    pub fn parse(space_id: SpaceId, epoch: Epoch, identity: &str) -> Result<Self, Error> {
        record::parse_identity(identity).map(|i| Self::from_identity(space_id, epoch, i))
    }

    pub(crate) fn from_identity(
        space_id: SpaceId,
        epoch: Epoch,
        identity: x25519::Identity,
    ) -> Self {
        Self {
            space_id,
            epoch,
            identity,
        }
    }

    pub fn space_id(&self) -> SpaceId {
        self.space_id
    }

    pub fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// Never give this to the server: its secrecy is what prevents forged objects and manifests.
    pub fn recipient(&self) -> x25519::Recipient {
        self.identity.to_public()
    }

    pub fn fingerprint(&self) -> Fingerprint {
        Fingerprint::of(&self.recipient())
    }

    pub(crate) fn identity(&self) -> &x25519::Identity {
        &self.identity
    }

    pub(crate) fn identity_string(&self) -> age::secrecy::SecretString {
        self.identity.to_string()
    }

    pub(crate) fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        agefile::encrypt(&self.recipient(), plaintext)
    }

    pub(crate) fn open(&self, sealed: &[u8], limit: usize) -> Result<Vec<u8>, Error> {
        let identities: [&dyn age::Identity; 1] = [&self.identity];
        agefile::decrypt(identities.into_iter(), sealed, limit)
    }
}

impl fmt::Debug for SpaceKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SpaceKey")
            .field("space_id", &self.space_id)
            .field("epoch", &self.epoch)
            .field("fingerprint", &self.fingerprint())
            .finish_non_exhaustive()
    }
}

/// One epoch identity delivered to one person. Unauthenticated: the server can forge grants.
#[derive(Debug, Clone)]
pub struct Grant {
    pub granted_by: UserId,
    pub key: SpaceKey,
}

impl Grant {
    const KIND: &str = "grant";

    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let mut w = record::Writer::new(Self::KIND);
        w.field("space-id", &self.key.space_id.to_string())?;
        w.field("epoch", &self.key.epoch.0.to_string())?;
        w.field("granted-by", &self.granted_by.to_string())?;
        w.field("space-identity", self.key.identity_string().expose_secret())?;
        w.finish()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = record::Reader::new(bytes, Self::KIND)?;
        let space_id = SpaceId::from_hex(r.field("space-id")?)?;
        let epoch = Epoch::parse(r.field("epoch")?)?;
        let granted_by = UserId::from_hex(r.field("granted-by")?)?;
        let identity = record::parse_identity(r.field("space-identity")?)?;
        r.finish()?;
        Ok(Self {
            granted_by,
            key: SpaceKey::from_identity(space_id, epoch, identity),
        })
    }

    pub fn seal(&self, member: &x25519::Recipient) -> Result<Vec<u8>, Error> {
        agefile::encrypt(member, &self.encode()?)
    }

    pub fn open(sealed: &[u8], keys: &UserKeys) -> Result<Self, Error> {
        let identities: [&dyn age::Identity; 1] = [keys.grant_identity()];
        Self::decode(&agefile::decrypt(
            identities.into_iter(),
            sealed,
            MAX_RECORD_BYTES,
        )?)
    }
}

/// Enforced by the server only: every member can technically write valid files.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Admin,
    Write,
    Read,
}

impl Role {
    fn as_str(self) -> &'static str {
        match self {
            Self::Admin => "admin",
            Self::Write => "write",
            Self::Read => "read",
        }
    }

    fn parse(text: &str) -> Result<Self, Error> {
        match text {
            "admin" => Ok(Self::Admin),
            "write" => Ok(Self::Write),
            "read" => Ok(Self::Read),
            _ => Err(Error::Malformed("role")),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Member {
    pub user_id: UserId,
    pub role: Role,
    pub grant_recipient: x25519::Recipient,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Roster {
    pub space_id: SpaceId,
    pub epoch: Epoch,
    pub name: String,
    pub members: Vec<Member>,
}

impl Roster {
    const KIND: &str = "roster";
    const MAX_NAME: usize = 256;

    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        let mut w = record::Writer::new(Self::KIND);
        w.field("space-id", &self.space_id.to_string())?;
        w.field("epoch", &self.epoch.0.to_string())?;
        w.field("name", &self.name)?;
        for m in &self.members {
            let line = format!("{} {} {}", m.user_id, m.role.as_str(), m.grant_recipient);
            w.field("member", &line)?;
        }
        w.finish()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = record::Reader::new(bytes, Self::KIND)?;
        let space_id = SpaceId::from_hex(r.field("space-id")?)?;
        let epoch = Epoch::parse(r.field("epoch")?)?;
        let name = r.field("name")?.to_owned();
        let members = r
            .repeated("member")?
            .into_iter()
            .map(|line| {
                let mut parts = line.split(' ');
                let member = match (parts.next(), parts.next(), parts.next(), parts.next()) {
                    (Some(id), Some(role), Some(recipient), None) => Member {
                        user_id: UserId::from_hex(id)?,
                        role: Role::parse(role)?,
                        grant_recipient: record::parse_recipient(recipient)?,
                    },
                    _ => return Err(Error::Malformed("member line")),
                };
                Ok(member)
            })
            .collect::<Result<Vec<_>, Error>>()?;
        r.finish()?;
        let roster = Self {
            space_id,
            epoch,
            name,
            members,
        };
        roster.validate()?;
        Ok(roster)
    }

    fn validate(&self) -> Result<(), Error> {
        if self.name.len() > Self::MAX_NAME {
            return Err(Error::Malformed("space name length"));
        }
        if self.members.is_empty() || !strictly_sorted(&self.members, |m| m.user_id) {
            return Err(Error::Malformed(
                "members must be non-empty, sorted and unique",
            ));
        }
        Ok(())
    }

    pub fn seal(&self, key: &SpaceKey) -> Result<Vec<u8>, Error> {
        if key.space_id != self.space_id || key.epoch != self.epoch {
            return Err(Error::WrongSpace);
        }
        key.seal(&self.encode()?)
    }

    pub fn open(sealed: &[u8], key: &SpaceKey) -> Result<Self, Error> {
        let roster = Self::decode(&key.open(sealed, MAX_RECORD_BYTES)?)?;
        if roster.space_id != key.space_id || roster.epoch != key.epoch {
            return Err(Error::WrongSpace);
        }
        Ok(roster)
    }

    pub fn member(&self, user_id: UserId) -> Option<&Member> {
        self.members.iter().find(|m| m.user_id == user_id)
    }
}

/// Announcement of a new epoch, encrypted to the previous epoch's recipient.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rotation {
    pub space_id: SpaceId,
    pub from: Epoch,
    pub to: Epoch,
    pub to_fingerprint: Fingerprint,
    pub removed: Vec<UserId>,
}

impl Rotation {
    const KIND: &str = "rotation";

    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        let mut w = record::Writer::new(Self::KIND);
        w.field("space-id", &self.space_id.to_string())?;
        w.field("from-epoch", &self.from.0.to_string())?;
        w.field("to-epoch", &self.to.0.to_string())?;
        w.field("to-recipient-sha256", &self.to_fingerprint.to_string())?;
        for user in &self.removed {
            w.field("removed", &user.to_string())?;
        }
        w.finish()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = record::Reader::new(bytes, Self::KIND)?;
        let rotation = Self {
            space_id: SpaceId::from_hex(r.field("space-id")?)?,
            from: Epoch::parse(r.field("from-epoch")?)?,
            to: Epoch::parse(r.field("to-epoch")?)?,
            to_fingerprint: Fingerprint(from_hex(r.field("to-recipient-sha256")?)?),
            removed: r
                .repeated("removed")?
                .into_iter()
                .map(UserId::from_hex)
                .collect::<Result<_, _>>()?,
        };
        r.finish()?;
        rotation.validate()?;
        Ok(rotation)
    }

    fn validate(&self) -> Result<(), Error> {
        if self.from.next()? != self.to {
            return Err(Error::Malformed("rotation must advance the epoch by one"));
        }
        if !strictly_sorted(&self.removed, |u| *u) {
            return Err(Error::Malformed("removed users must be sorted and unique"));
        }
        Ok(())
    }

    pub fn seal(&self, previous: &SpaceKey) -> Result<Vec<u8>, Error> {
        if previous.space_id != self.space_id || previous.epoch != self.from {
            return Err(Error::WrongSpace);
        }
        previous.seal(&self.encode()?)
    }

    pub fn open(sealed: &[u8], previous: &SpaceKey) -> Result<Self, Error> {
        let rotation = Self::decode(&previous.open(sealed, MAX_RECORD_BYTES)?)?;
        if rotation.space_id != previous.space_id || rotation.from != previous.epoch {
            return Err(Error::WrongSpace);
        }
        Ok(rotation)
    }

    /// The only way a grant for a new epoch of a known space is accepted without asking the person.
    pub fn accept(&self, grant: Grant) -> Result<SpaceKey, Error> {
        if grant.key.space_id != self.space_id || grant.key.epoch != self.to {
            return Err(Error::WrongSpace);
        }
        if grant.key.fingerprint() != self.to_fingerprint {
            return Err(Error::RecipientMismatch);
        }
        Ok(grant.key)
    }
}

/// Everything an admin client uploads to rotate a space.
pub struct RotationOutput {
    pub key: SpaceKey,
    pub rotation: Vec<u8>,
    pub roster: Vec<u8>,
    pub grants: Vec<(UserId, Vec<u8>)>,
}

/// Rotates `previous` to a new epoch whose identity only the members left in the roster receive.
pub fn rotate(
    previous: &SpaceKey,
    roster: &Roster,
    removed: &[UserId],
    actor: UserId,
) -> Result<RotationOutput, Error> {
    let key = SpaceKey::generate(previous.space_id, previous.epoch.next()?);
    let mut removed = removed.to_vec();
    removed.sort();
    removed.dedup();
    let rotation = Rotation {
        space_id: previous.space_id,
        from: previous.epoch,
        to: key.epoch,
        to_fingerprint: key.fingerprint(),
        removed: removed.clone(),
    };
    let next_roster = Roster {
        space_id: key.space_id,
        epoch: key.epoch,
        name: roster.name.clone(),
        members: roster
            .members
            .iter()
            .filter(|m| removed.binary_search(&m.user_id).is_err())
            .cloned()
            .collect(),
    };
    let grant = Grant {
        granted_by: actor,
        key: key.clone(),
    };
    let grants = next_roster
        .members
        .iter()
        .map(|m| Ok((m.user_id, grant.seal(&m.grant_recipient)?)))
        .collect::<Result<_, Error>>()?;
    Ok(RotationOutput {
        rotation: rotation.seal(previous)?,
        roster: next_roster.seal(&key)?,
        grants,
        key,
    })
}
