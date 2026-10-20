//! Space identities, grants, rosters and rotations (format §3).

use std::fmt;

use age::secrecy::ExposeSecret;
use age::x25519;
use sha2::{Digest, Sha256};

use crate::identity::UserKeys;
use crate::ids::{SpaceId, UserId, from_hex, to_hex};
use crate::record::{self, MAX_RECORD_BYTES, parse_u64, strictly_sorted};
use crate::sign::{Signed, VerifyingKey};
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

    /// A person's fingerprint: SHA-256 of `home-crypto/v2/person <user-id> <age1…> <verifying key>`.
    pub fn of_person(
        user_id: UserId,
        grant_recipient: &x25519::Recipient,
        verifying_key: &VerifyingKey,
    ) -> Self {
        let text = format!("home-crypto/v2/person {user_id} {grant_recipient} {verifying_key}");
        Self(Sha256::digest(text.as_bytes()).into())
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

/// One epoch identity delivered to one person, signed by the member who grants it.
#[derive(Debug, Clone)]
pub struct Grant {
    pub granted_to: UserId,
    pub key: SpaceKey,
}

impl Grant {
    const KIND: &str = "grant";

    pub fn encode(&self, signer: &UserKeys) -> Result<Vec<u8>, Error> {
        let mut w = record::Writer::new(Self::KIND);
        w.field("space-id", &self.key.space_id.to_string())?;
        w.field("epoch", &self.key.epoch.0.to_string())?;
        w.field("granted-to", &self.granted_to.to_string())?;
        w.field("space-identity", self.key.identity_string().expose_secret())?;
        w.finish_signed(signer.user_id(), signer.signing_key())
    }

    pub fn decode(bytes: &[u8]) -> Result<Signed<Self>, Error> {
        record::decode_signed(bytes, Self::KIND, |r| {
            let space_id = SpaceId::from_hex(r.field("space-id")?)?;
            let epoch = Epoch::parse(r.field("epoch")?)?;
            let granted_to = UserId::from_hex(r.field("granted-to")?)?;
            let identity = record::parse_identity(r.field("space-identity")?)?;
            Ok(Self {
                granted_to,
                key: SpaceKey::from_identity(space_id, epoch, identity),
            })
        })
    }

    pub fn seal(&self, signer: &UserKeys, member: &x25519::Recipient) -> Result<Vec<u8>, Error> {
        agefile::encrypt(member, &self.encode(signer)?)
    }

    /// Refuses grants addressed to someone else, so a member cannot forward a grant they received.
    pub fn open(sealed: &[u8], keys: &UserKeys) -> Result<Signed<Self>, Error> {
        let identities: [&dyn age::Identity; 1] = [keys.grant_identity()];
        let grant = Self::decode(&agefile::decrypt(
            identities.into_iter(),
            sealed,
            MAX_RECORD_BYTES,
        )?)?;
        if grant.unverified().granted_to != keys.user_id() {
            return Err(Error::WrongUser);
        }
        Ok(grant)
    }
}

/// Roles authorise signed changes: only an admin's grants, rosters and rotations are accepted by members.
/// Writing objects and manifest entries is still enforced by the server only.
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
    pub verifying_key: VerifyingKey,
}

impl Member {
    pub fn of(keys: &UserKeys, role: Role) -> Self {
        Self {
            user_id: keys.user_id(),
            role,
            grant_recipient: keys.grant_recipient(),
            verifying_key: keys.verifying_key(),
        }
    }

    pub fn fingerprint(&self) -> Fingerprint {
        Fingerprint::of_person(self.user_id, &self.grant_recipient, &self.verifying_key)
    }
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

    pub fn encode(&self, signer: &UserKeys) -> Result<Vec<u8>, Error> {
        self.validate()?;
        let mut w = record::Writer::new(Self::KIND);
        w.field("space-id", &self.space_id.to_string())?;
        w.field("epoch", &self.epoch.0.to_string())?;
        w.field("name", &self.name)?;
        for m in &self.members {
            let line = format!(
                "{} {} {} {}",
                m.user_id,
                m.role.as_str(),
                m.grant_recipient,
                m.verifying_key
            );
            w.field("member", &line)?;
        }
        w.finish_signed(signer.user_id(), signer.signing_key())
    }

    pub fn decode(bytes: &[u8]) -> Result<Signed<Self>, Error> {
        record::decode_signed(bytes, Self::KIND, |r| {
            let space_id = SpaceId::from_hex(r.field("space-id")?)?;
            let epoch = Epoch::parse(r.field("epoch")?)?;
            let name = r.field("name")?.to_owned();
            let members = r
                .repeated("member")?
                .into_iter()
                .map(|line| {
                    let mut parts = line.split(' ');
                    match (
                        parts.next(),
                        parts.next(),
                        parts.next(),
                        parts.next(),
                        parts.next(),
                    ) {
                        (Some(id), Some(role), Some(recipient), Some(key), None) => Ok(Member {
                            user_id: UserId::from_hex(id)?,
                            role: Role::parse(role)?,
                            grant_recipient: record::parse_recipient(recipient)?,
                            verifying_key: VerifyingKey::parse(key)?,
                        }),
                        _ => Err(Error::Malformed("member line")),
                    }
                })
                .collect::<Result<Vec<_>, Error>>()?;
            let roster = Self {
                space_id,
                epoch,
                name,
                members,
            };
            roster.validate()?;
            Ok(roster)
        })
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

    pub fn seal(&self, key: &SpaceKey, signer: &UserKeys) -> Result<Vec<u8>, Error> {
        if key.space_id != self.space_id || key.epoch != self.epoch {
            return Err(Error::WrongSpace);
        }
        key.seal(&self.encode(signer)?)
    }

    pub fn open(sealed: &[u8], key: &SpaceKey) -> Result<Signed<Self>, Error> {
        let roster = Self::decode(&key.open(sealed, MAX_RECORD_BYTES)?)?;
        let claimed = roster.unverified();
        if claimed.space_id != key.space_id || claimed.epoch != key.epoch {
            return Err(Error::WrongSpace);
        }
        Ok(roster)
    }

    pub fn member(&self, user_id: UserId) -> Option<&Member> {
        self.members.iter().find(|m| m.user_id == user_id)
    }

    /// The verifying key of `user` if this roster makes them an admin.
    pub fn admin_key(&self, user: UserId) -> Result<&VerifyingKey, Error> {
        match self.member(user) {
            Some(m) if m.role == Role::Admin => Ok(&m.verifying_key),
            _ => Err(Error::NotAuthorized),
        }
    }
}

impl Signed<Roster> {
    /// The first roster a device accepts for a space: signed by `signer_key` (the inviter's key, pinned or
    /// published), and the roster itself lists the signer as admin with that key.
    pub fn verify_first(self, signer_key: &VerifyingKey) -> Result<Roster, Error> {
        let signer = self.signer();
        if self.unverified().admin_key(signer)? != signer_key {
            return Err(Error::KeyChanged { user: signer });
        }
        self.verify(signer_key)
    }

    /// A change within the epoch of `trusted`: signed by an admin of `trusted`, with the key `trusted` lists.
    pub fn verify_change(self, trusted: &Roster) -> Result<Roster, Error> {
        let claimed = self.unverified();
        if claimed.space_id != trusted.space_id || claimed.epoch != trusted.epoch {
            return Err(Error::WrongSpace);
        }
        let key = *trusted.admin_key(self.signer())?;
        self.verify(&key)
    }
}

/// Announcement of a new epoch, encrypted to the previous epoch's recipient and signed by an admin.
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

    pub fn encode(&self, signer: &UserKeys) -> Result<Vec<u8>, Error> {
        self.validate()?;
        let mut w = record::Writer::new(Self::KIND);
        w.field("space-id", &self.space_id.to_string())?;
        w.field("from-epoch", &self.from.0.to_string())?;
        w.field("to-epoch", &self.to.0.to_string())?;
        w.field("to-recipient-sha256", &self.to_fingerprint.to_string())?;
        for user in &self.removed {
            w.field("removed", &user.to_string())?;
        }
        w.finish_signed(signer.user_id(), signer.signing_key())
    }

    pub fn decode(bytes: &[u8]) -> Result<Signed<Self>, Error> {
        record::decode_signed(bytes, Self::KIND, |r| {
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
            rotation.validate()?;
            Ok(rotation)
        })
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

    pub fn seal(&self, previous: &SpaceKey, signer: &UserKeys) -> Result<Vec<u8>, Error> {
        if previous.space_id != self.space_id || previous.epoch != self.from {
            return Err(Error::WrongSpace);
        }
        previous.seal(&self.encode(signer)?)
    }

    pub fn open(sealed: &[u8], previous: &SpaceKey) -> Result<Signed<Self>, Error> {
        let rotation = Self::decode(&previous.open(sealed, MAX_RECORD_BYTES)?)?;
        let claimed = rotation.unverified();
        if claimed.space_id != previous.space_id || claimed.from != previous.epoch {
            return Err(Error::WrongSpace);
        }
        Ok(rotation)
    }

    /// Checks that a verified grant carries the identity this rotation announced.
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

impl Signed<Rotation> {
    /// `trusted` is the roster of the `from` epoch; the signer must be an admin there and not removed.
    pub fn verify_against(self, trusted: &Roster) -> Result<Rotation, Error> {
        let claimed = self.unverified();
        if claimed.space_id != trusted.space_id || claimed.from != trusted.epoch {
            return Err(Error::WrongSpace);
        }
        let signer = self.signer();
        if claimed.removed.binary_search(&signer).is_ok() {
            return Err(Error::NotAuthorized);
        }
        let key = *trusted.admin_key(signer)?;
        self.verify(&key)
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
///
/// `actor` signs the rotation record, every grant and the new roster, and must be an admin of `roster`.
pub fn rotate(
    previous: &SpaceKey,
    roster: &Roster,
    removed: &[UserId],
    actor: &UserKeys,
) -> Result<RotationOutput, Error> {
    if roster.space_id != previous.space_id || roster.epoch != previous.epoch {
        return Err(Error::WrongSpace);
    }
    let mut removed = removed.to_vec();
    removed.sort();
    removed.dedup();
    if removed.binary_search(&actor.user_id()).is_ok()
        || roster.admin_key(actor.user_id())? != &actor.verifying_key()
    {
        return Err(Error::NotAuthorized);
    }
    let key = SpaceKey::generate(previous.space_id, previous.epoch.next()?);
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
    let grants = next_roster
        .members
        .iter()
        .map(|m| {
            let grant = Grant {
                granted_to: m.user_id,
                key: key.clone(),
            };
            Ok((m.user_id, grant.seal(actor, &m.grant_recipient)?))
        })
        .collect::<Result<_, Error>>()?;
    Ok(RotationOutput {
        rotation: rotation.seal(previous, actor)?,
        roster: next_roster.seal(&key, actor)?,
        grants,
        key,
    })
}

/// What a remaining member takes from a verified rotation.
#[derive(Debug)]
pub struct AcceptedRotation {
    pub key: SpaceKey,
    pub roster: Roster,
    pub rotation: Rotation,
    pub signer: UserId,
}

/// Accepts a rotation without asking the person (format §3.4).
///
/// `previous` and `trusted` are the epoch-`n` key and the roster this device already accepted for it. The
/// rotation, the grant and the epoch-`n + 1` roster must all be signed by the same admin of `trusted`; the
/// grant's identity must match the announced fingerprint; the new roster must list this person and none of
/// the removed members.
pub fn accept_rotation(
    previous: &SpaceKey,
    trusted: &Roster,
    rotation: &[u8],
    grant: &[u8],
    roster: &[u8],
    keys: &UserKeys,
) -> Result<AcceptedRotation, Error> {
    if trusted.space_id != previous.space_id || trusted.epoch != previous.epoch {
        return Err(Error::WrongSpace);
    }
    let rotation = Rotation::open(rotation, previous)?;
    let signer = rotation.signer();
    let rotation = rotation.verify_against(trusted)?;
    let signer_key = *trusted.admin_key(signer)?;

    let grant = Grant::open(grant, keys)?;
    if grant.signer() != signer {
        return Err(Error::NotAuthorized);
    }
    let key = rotation.accept(grant.verify(&signer_key)?)?;

    let roster = Roster::open(roster, &key)?;
    if roster.signer() != signer {
        return Err(Error::NotAuthorized);
    }
    let roster = roster.verify(&signer_key)?;
    if roster
        .members
        .iter()
        .any(|m| rotation.removed.binary_search(&m.user_id).is_ok())
    {
        return Err(Error::NotAuthorized);
    }
    if roster.member(keys.user_id()).is_none() {
        return Err(Error::WrongUser);
    }
    Ok(AcceptedRotation {
        key,
        roster,
        rotation,
        signer,
    })
}
