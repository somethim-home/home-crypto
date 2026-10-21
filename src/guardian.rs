//! Guardian access to a kid's identity (format §9).
//!
//! A kid's identity is wrapped in one age file to three kinds of recipient: the kid's *passphrase key* (an
//! X25519 identity that only the kid's passphrase unlocks), the kid's recovery recipient, and the grant
//! recipient of every guardian. The owner is always a guardian; the owner can add the kid's parents. A
//! guardian unlocks the kid's identity with their own key, and with it the kid's keyring and everything the
//! kid can read, including spaces the kid joins later.
//!
//! The wrap is a signed record ([`GuardianWrap`]), signed by the owner or by the kid's own key. Each new wrap
//! names the hash and epoch of the one before, and members accept it only under the rules of
//! [`Signed::<GuardianWrap>::verify_successor`], so the server can neither add a guardian nor swap the
//! identity.

use std::fmt;

use age::secrecy::{ExposeSecret, SecretString};
use age::x25519;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::identity::{RecoveryKey, ScryptCost, UserKeys};
use crate::ids::{SpaceId, UserId, from_hex, from_hex_vec, to_hex};
use crate::keyring::{Keyring, Trust};
use crate::record::{self, MAX_RECORD_BYTES, parse_u64, strictly_sorted};
use crate::sign::{Signed, VerifyingKey};
use crate::space::{self, Fingerprint, Member, Roster, RotationOutput};
use crate::{Error, agefile};

/// Most guardians one kid can have; bounds the size of the wrap.
pub const MAX_GUARDIANS: usize = 32;
/// Largest wrapped identity file accepted inside a wrap (the real size is well under 4 KiB).
const MAX_IDENTITY_FILE: usize = 64 * 1024;

/// A person's two public keys, as published next to their account and pinned on first use.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PersonKey {
    pub user_id: UserId,
    pub grant_recipient: x25519::Recipient,
    pub verifying_key: VerifyingKey,
}

impl PersonKey {
    pub fn of(keys: &UserKeys) -> Self {
        Self {
            user_id: keys.user_id(),
            grant_recipient: keys.grant_recipient(),
            verifying_key: keys.verifying_key(),
        }
    }

    /// The person fingerprint (safety number) of format §1.
    pub fn fingerprint(&self) -> Fingerprint {
        Fingerprint::of_person(self.user_id, &self.grant_recipient, &self.verifying_key)
    }

    fn line(&self) -> String {
        format!(
            "{} {} {}",
            self.user_id, self.grant_recipient, self.verifying_key
        )
    }

    fn parse(id: &str, recipient: &str, key: &str) -> Result<Self, Error> {
        Ok(Self {
            user_id: UserId::from_hex(id)?,
            grant_recipient: record::parse_recipient(recipient)?,
            verifying_key: VerifyingKey::parse(key)?,
        })
    }

    fn parse_line(line: &str) -> Result<Self, Error> {
        let mut parts = line.split(' ');
        match (parts.next(), parts.next(), parts.next(), parts.next()) {
            (Some(id), Some(recipient), Some(key), None) => Self::parse(id, recipient, key),
            _ => Err(Error::Malformed("person line")),
        }
    }
}

impl From<&Member> for PersonKey {
    fn from(m: &Member) -> Self {
        Self {
            user_id: m.user_id,
            grant_recipient: m.grant_recipient.clone(),
            verifying_key: m.verifying_key,
        }
    }
}

/// One guardian line of a wrap: who, who added them, and when (client time, untrusted).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Guardian {
    pub key: PersonKey,
    pub added_by: UserId,
    /// Milliseconds since the Unix epoch, as reported by the client that added the guardian.
    pub added_at: u64,
}

impl Guardian {
    fn line(&self) -> String {
        format!("{} {} {}", self.key.line(), self.added_by, self.added_at)
    }

    fn parse_line(line: &str) -> Result<Self, Error> {
        let mut parts = line.split(' ');
        match (
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
        ) {
            (Some(id), Some(recipient), Some(key), Some(by), Some(at), None) => Ok(Self {
                key: PersonKey::parse(id, recipient, key)?,
                added_by: UserId::from_hex(by)?,
                added_at: parse_u64(at)?,
            }),
            _ => Err(Error::Malformed("guardian line")),
        }
    }
}

/// Whether guardians may still unlock the kid's identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Access {
    Active,
    /// Ended by the kid (age of majority); final.
    Ended,
}

impl Access {
    fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Ended => "ended",
        }
    }

    fn parse(text: &str) -> Result<Self, Error> {
        match text {
            "active" => Ok(Self::Active),
            "ended" => Ok(Self::Ended),
            _ => Err(Error::Malformed("guardian-access")),
        }
    }
}

/// SHA-256 of a complete signed wrap record (every byte, including the signature line).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct WrapDigest(pub [u8; 32]);

impl WrapDigest {
    fn of(bytes: &[u8]) -> Self {
        Self(Sha256::digest(bytes).into())
    }

    fn parse(text: &str) -> Result<Self, Error> {
        from_hex(text).map(Self)
    }
}

impl fmt::Display for WrapDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&to_hex(&self.0))
    }
}

impl fmt::Debug for WrapDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "WrapDigest({self})")
    }
}

/// The signed guardian wrap of one kid (format §9.3).
///
/// Obtained only by decoding and verifying ([`GuardianWrap::decode`] and the `verify_*` methods of
/// `Signed<GuardianWrap>`) or from an operation of this module, so a value of this type is always a wrap
/// whose signature was checked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuardianWrap {
    kid: PersonKey,
    owner: UserId,
    epoch: u64,
    previous: Option<WrapDigest>,
    access: Access,
    passphrase_fingerprint: Fingerprint,
    guardians: Vec<Guardian>,
    identity: Vec<u8>,
    digest: WrapDigest,
}

impl GuardianWrap {
    const KIND: &str = "v3/guardian-wrap";

    /// The kid's current public keys; they change when the kid's identity is rotated.
    pub fn kid(&self) -> &PersonKey {
        &self.kid
    }

    pub fn owner(&self) -> UserId {
        self.owner
    }

    /// Starts at 1 and increases by one with every new wrap of this kid.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn previous(&self) -> Option<WrapDigest> {
        self.previous
    }

    pub fn access(&self) -> Access {
        self.access
    }

    /// Fingerprint of the kid's passphrase-key recipient (format §9.1).
    pub fn passphrase_fingerprint(&self) -> Fingerprint {
        self.passphrase_fingerprint
    }

    /// Current guardians, sorted by user id; empty once access has ended.
    pub fn guardians(&self) -> &[Guardian] {
        &self.guardians
    }

    pub fn guardian(&self, user: UserId) -> Option<&Guardian> {
        self.guardians.iter().find(|g| g.key.user_id == user)
    }

    /// The wrapped identity: an age file to the passphrase key, the recovery recipient and every guardian.
    pub fn identity_file(&self) -> &[u8] {
        &self.identity
    }

    /// SHA-256 of this record, named by the next wrap's `previous-sha256`.
    pub fn digest(&self) -> WrapDigest {
        self.digest
    }

    fn validate(&self, signer: UserId) -> Result<(), Error> {
        if self.guardians.len() > MAX_GUARDIANS
            || !strictly_sorted(&self.guardians, |g| g.key.user_id)
        {
            return Err(Error::Malformed(
                "guardians must be sorted, unique and at most 32",
            ));
        }
        if self.owner == self.kid.user_id || self.guardian(self.kid.user_id).is_some() {
            return Err(Error::Malformed("a kid cannot be their own guardian"));
        }
        match self.access {
            Access::Active if self.guardian(self.owner).is_none() => {
                return Err(Error::Malformed("the owner is always a guardian"));
            }
            Access::Ended if !self.guardians.is_empty() => {
                return Err(Error::Malformed("an ended wrap lists no guardians"));
            }
            _ => {}
        }
        if self.epoch == 0 || (self.epoch == 1) != self.previous.is_none() {
            return Err(Error::Malformed(
                "epoch 1 has no previous wrap; later epochs have one",
            ));
        }
        if self.identity.is_empty() || self.identity.len() > MAX_IDENTITY_FILE {
            return Err(Error::Malformed("identity file size"));
        }
        let signer_ok =
            signer == self.kid.user_id || (signer == self.owner && self.access == Access::Active);
        if !signer_ok {
            return Err(Error::NotAuthorized);
        }
        Ok(())
    }

    fn write(&self, w: &mut record::Writer) -> Result<(), Error> {
        w.field("kid", &self.kid.line())?;
        w.field("owner", &self.owner.to_string())?;
        w.field("epoch", &self.epoch.to_string())?;
        w.field(
            "previous-sha256",
            &self
                .previous
                .map_or_else(|| "none".to_owned(), |d| d.to_string()),
        )?;
        w.field("guardian-access", self.access.as_str())?;
        w.field(
            "passphrase-recipient-sha256",
            &self.passphrase_fingerprint.to_string(),
        )?;
        for g in &self.guardians {
            w.field("guardian", &g.line())?;
        }
        w.field("identity", &to_hex(&self.identity))
    }

    fn encode(&self, signer: &UserKeys) -> Result<Vec<u8>, Error> {
        self.validate(signer.user_id())?;
        let mut w = record::Writer::new(Self::KIND);
        self.write(&mut w)?;
        w.finish_signed(signer.user_id(), signer.signing_key())
    }

    /// The record up to and including `signed-by`: the bytes the signature covers. For fuzzing and tests:
    /// decoding then calling this must give back the input without its last line.
    #[doc(hidden)]
    pub fn signed_bytes(&self, signer: UserId) -> Result<Vec<u8>, Error> {
        let mut w = record::Writer::new(Self::KIND);
        self.write(&mut w)?;
        w.field("signed-by", &signer.to_string())?;
        w.finish()
    }

    /// Parses a wrap; the signature is checked by the `verify_*` methods of the result.
    pub fn decode(bytes: &[u8]) -> Result<Signed<Self>, Error> {
        let digest = WrapDigest::of(bytes);
        let signed = record::decode_signed(bytes, Self::KIND, |r| {
            let kid = PersonKey::parse_line(r.field("kid")?)?;
            let owner = UserId::from_hex(r.field("owner")?)?;
            let epoch = parse_u64(r.field("epoch")?)?;
            let previous = match r.field("previous-sha256")? {
                "none" => None,
                hex => Some(WrapDigest::parse(hex)?),
            };
            let access = Access::parse(r.field("guardian-access")?)?;
            let passphrase_fingerprint =
                Fingerprint(from_hex(r.field("passphrase-recipient-sha256")?)?);
            let guardians = r
                .repeated("guardian")?
                .into_iter()
                .map(Guardian::parse_line)
                .collect::<Result<Vec<_>, Error>>()?;
            let identity = from_hex_vec(r.field("identity")?, MAX_IDENTITY_FILE)?;
            Ok(Self {
                kid,
                owner,
                epoch,
                previous,
                access,
                passphrase_fingerprint,
                guardians,
                identity,
                digest,
            })
        })?;
        signed.unverified().validate(signed.signer())?;
        Ok(signed)
    }

    /// The checks every successor must pass, whoever signed it.
    fn follows(&self, next: &Self) -> Result<(), Error> {
        let follows = next.kid.user_id == self.kid.user_id
            && next.owner == self.owner
            && Some(next.epoch) == self.epoch.checked_add(1)
            && next.previous == Some(self.digest);
        if follows {
            Ok(())
        } else {
            Err(Error::NotSuccessor)
        }
    }
}

impl Signed<GuardianWrap> {
    /// The key the record lists for its own signer: the owner's guardian line or the kid's key.
    fn listed_key(&self) -> Result<VerifyingKey, Error> {
        let wrap = self.unverified();
        let signer = self.signer();
        if signer == wrap.kid.user_id {
            Ok(wrap.kid.verifying_key)
        } else if signer == wrap.owner {
            wrap.guardian(signer)
                .map(|g| g.key.verifying_key)
                .ok_or(Error::NotAuthorized)
        } else {
            Err(Error::NotAuthorized)
        }
    }

    /// The first wrap a device accepts for a kid: signed by the owner or the kid, with `signer_key` (pinned,
    /// or the published key on first use), and listing that same key for the signer. See
    /// [`Keyring::verify_guardian_wrap`] for the pin check.
    pub fn verify_first(self, signer_key: &VerifyingKey) -> Result<GuardianWrap, Error> {
        if self.listed_key()? != *signer_key {
            return Err(Error::KeyChanged {
                user: self.signer(),
            });
        }
        self.verify(signer_key)
    }

    /// Verified against the key the record itself lists for its signer. Only for a kid's device that has
    /// just opened the wrapped identity with its own passphrase key or recovery identity (format §9.6).
    fn verify_self(self) -> Result<GuardianWrap, Error> {
        let key = self.listed_key()?;
        self.verify(&key)
    }

    /// The next wrap after `trusted` (format §9.4), for any change except the end of guardian access:
    ///
    /// - it has the same kid and owner, the next epoch, and names `trusted`'s hash;
    /// - signed by the **owner**, with the key `trusted` lists for them: guardians may be added (added by
    ///   the owner) or removed, and the kid's identity may be replaced (rotation); the owner stays a
    ///   guardian with the same key; every guardian that stays keeps the same line;
    /// - signed by the **kid**, with the kid key of `trusted` (the kid's device, or a guardian acting with the
    ///   kid's identity): the kid's keys stay the same, every guardian of `trusted` stays with the same line,
    ///   and new guardians are added by the kid or by a guardian of `trusted`;
    /// - after the end of access, only the kid signs, keys and guardians (none) stay, access stays ended.
    pub fn verify_successor(self, trusted: &GuardianWrap) -> Result<GuardianWrap, Error> {
        let next = self.unverified();
        trusted.follows(next)?;
        let signer = self.signer();
        let key = match (trusted.access, next.access) {
            (Access::Ended, Access::Active) => return Err(Error::AccessEnded),
            (Access::Active, Access::Ended) => return Err(Error::NotAuthorized),
            (Access::Ended, Access::Ended) => {
                if signer != trusted.kid.user_id || next.kid != trusted.kid {
                    return Err(Error::NotAuthorized);
                }
                trusted.kid.verifying_key
            }
            (Access::Active, Access::Active) if signer == trusted.owner => {
                let owner_line = trusted
                    .guardian(trusted.owner)
                    .ok_or(Error::NotAuthorized)?;
                if next.guardian(trusted.owner) != Some(owner_line) {
                    return Err(Error::NotAuthorized);
                }
                for g in &next.guardians {
                    let allowed = match trusted.guardian(g.key.user_id) {
                        Some(kept) => kept == g,
                        None => g.added_by == trusted.owner,
                    };
                    if !allowed {
                        return Err(Error::NotAuthorized);
                    }
                }
                owner_line.key.verifying_key
            }
            (Access::Active, Access::Active) if signer == trusted.kid.user_id => {
                if next.kid != trusted.kid
                    || trusted
                        .guardians
                        .iter()
                        .any(|g| next.guardian(g.key.user_id) != Some(g))
                {
                    return Err(Error::NotAuthorized);
                }
                let added_ok = next.guardians.iter().all(|g| {
                    trusted.guardian(g.key.user_id).is_some()
                        || g.added_by == trusted.kid.user_id
                        || trusted.guardian(g.added_by).is_some()
                });
                if !added_ok {
                    return Err(Error::NotAuthorized);
                }
                trusted.kid.verifying_key
            }
            (Access::Active, Access::Active) => return Err(Error::NotAuthorized),
        };
        self.verify(&key)
    }

    /// The wrap that ends guardian access after `trusted` (format §9.7), with its `guardian-end` record.
    ///
    /// The end record must be signed by the kid key of `trusted` and name both wraps' hashes and the kid's
    /// new keys; the new wrap lists no guardians, carries a new kid identity, and is signed by that new key.
    pub fn verify_end(
        self,
        trusted: &GuardianWrap,
        end: Signed<GuardianEnd>,
    ) -> Result<(GuardianWrap, GuardianEnd), Error> {
        if trusted.access == Access::Ended {
            return Err(Error::AccessEnded);
        }
        let next = self.unverified();
        trusted.follows(next)?;
        if next.access != Access::Ended
            || self.signer() != trusted.kid.user_id
            || end.signer() != trusted.kid.user_id
            || next.kid.verifying_key == trusted.kid.verifying_key
            || next.kid.grant_recipient == trusted.kid.grant_recipient
        {
            return Err(Error::NotAuthorized);
        }
        let end = end.verify(&trusted.kid.verifying_key)?;
        let matches = end.kid == trusted.kid.user_id
            && end.owner == trusted.owner
            && end.from_epoch == trusted.epoch
            && end.from == trusted.digest
            && end.to == next.digest
            && end.new_kid == next.kid;
        if !matches {
            return Err(Error::NotSuccessor);
        }
        let key = next.kid.verifying_key;
        Ok((self.verify(&key)?, end))
    }
}

/// The signed "guardian access ended" record (format §9.7), signed by the kid's key from before the end.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuardianEnd {
    pub kid: UserId,
    pub owner: UserId,
    /// Epoch of the last wrap with guardians.
    pub from_epoch: u64,
    pub from: WrapDigest,
    /// Hash of the ended wrap (epoch `from_epoch + 1`).
    pub to: WrapDigest,
    /// The kid's new public keys, known to no guardian.
    pub new_kid: PersonKey,
    /// Milliseconds since the Unix epoch, client time.
    pub ended_at: u64,
}

impl GuardianEnd {
    const KIND: &str = "v3/guardian-end";

    fn write(&self, w: &mut record::Writer) -> Result<(), Error> {
        if self.new_kid.user_id != self.kid {
            return Err(Error::WrongUser);
        }
        w.field("kid", &self.kid.to_string())?;
        w.field("owner", &self.owner.to_string())?;
        w.field("from-epoch", &self.from_epoch.to_string())?;
        w.field("from-sha256", &self.from.to_string())?;
        w.field("to-sha256", &self.to.to_string())?;
        w.field("new-kid", &self.new_kid.line())?;
        w.field("ended-at", &self.ended_at.to_string())
    }

    fn encode(&self, signer: &UserKeys) -> Result<Vec<u8>, Error> {
        if signer.user_id() != self.kid {
            return Err(Error::NotAuthorized);
        }
        let mut w = record::Writer::new(Self::KIND);
        self.write(&mut w)?;
        w.finish_signed(signer.user_id(), signer.signing_key())
    }

    /// See [`GuardianWrap::signed_bytes`].
    #[doc(hidden)]
    pub fn signed_bytes(&self, signer: UserId) -> Result<Vec<u8>, Error> {
        let mut w = record::Writer::new(Self::KIND);
        self.write(&mut w)?;
        w.field("signed-by", &signer.to_string())?;
        w.finish()
    }

    pub fn decode(bytes: &[u8]) -> Result<Signed<Self>, Error> {
        let signed = record::decode_signed(bytes, Self::KIND, |r| {
            let end = Self {
                kid: UserId::from_hex(r.field("kid")?)?,
                owner: UserId::from_hex(r.field("owner")?)?,
                from_epoch: parse_u64(r.field("from-epoch")?)?,
                from: WrapDigest::parse(r.field("from-sha256")?)?,
                to: WrapDigest::parse(r.field("to-sha256")?)?,
                new_kid: PersonKey::parse_line(r.field("new-kid")?)?,
                ended_at: parse_u64(r.field("ended-at")?)?,
            };
            if end.new_kid.user_id != end.kid || end.from_epoch == 0 {
                return Err(Error::Malformed("guardian-end fields"));
            }
            Ok(end)
        })?;
        if signed.signer() != signed.unverified().kid {
            return Err(Error::NotAuthorized);
        }
        Ok(signed)
    }
}

/// The kid's passphrase key (format §9.1): an X25519 identity sealed with the kid's passphrase only.
///
/// The wrapped identity is encrypted to its recipient, so a guardian can re-wrap the kid's identity (even a
/// new one) for the kid's passphrase without knowing the passphrase.
pub struct PassphraseKey {
    kid: UserId,
    identity: x25519::Identity,
    access: Access,
}

impl PassphraseKey {
    const KIND: &str = "v3/passphrase-key";

    fn generate(kid: UserId, access: Access) -> Self {
        Self {
            kid,
            identity: x25519::Identity::generate(),
            access,
        }
    }

    pub fn kid(&self) -> UserId {
        self.kid
    }

    /// `ended` only when written by the kid at the end of guardian access, with a passphrase no guardian
    /// knows; an ended wrap is accepted only with such a key.
    pub fn access(&self) -> Access {
        self.access
    }

    pub fn recipient(&self) -> x25519::Recipient {
        self.identity.to_public()
    }

    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>, Error> {
        let mut w = record::Writer::new(Self::KIND);
        w.field("user-id", &self.kid.to_string())?;
        w.field(
            "passphrase-identity",
            self.identity.to_string().expose_secret(),
        )?;
        w.field("guardian-access", self.access.as_str())?;
        w.finish().map(Zeroizing::new)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = record::Reader::new(bytes, Self::KIND)?;
        let key = Self {
            kid: UserId::from_hex(r.field("user-id")?)?,
            identity: record::parse_identity(r.field("passphrase-identity")?)?,
            access: Access::parse(r.field("guardian-access")?)?,
        };
        r.finish()?;
        Ok(key)
    }

    /// `passphrase-key.age`: an age file to a scrypt passphrase recipient only.
    fn seal(&self, passphrase: SecretString, cost: ScryptCost) -> Result<Vec<u8>, Error> {
        let mut recipient = age::scrypt::Recipient::new(passphrase);
        recipient.set_work_factor(cost.log_n());
        agefile::encrypt(&recipient, &self.encode()?)
    }

    pub fn open(
        sealed: &[u8],
        passphrase: SecretString,
        max_cost: ScryptCost,
        expected: UserId,
    ) -> Result<Self, Error> {
        let mut identity = age::scrypt::Identity::new(passphrase);
        identity.set_max_work_factor(max_cost.log_n());
        let identities: [&dyn age::Identity; 1] = [&identity];
        let plaintext = agefile::decrypt_secret(identities.into_iter(), sealed, MAX_RECORD_BYTES)?;
        let key = Self::decode(&plaintext)?;
        if key.kid != expected {
            return Err(Error::WrongUser);
        }
        Ok(key)
    }
}

/// A kid's unlocked identity, with the passphrase-key recipient needed to re-wrap it.
///
/// Lives in memory only: the secret keys inside are zeroed on drop by `x25519-dalek` and `ed25519-dalek`,
/// and the decrypted record buffers by [`Zeroizing`]. It has no `Debug`.
#[derive(Clone)]
pub struct KidIdentity {
    keys: UserKeys,
    passphrase_recipient: x25519::Recipient,
}

impl KidIdentity {
    const KIND: &str = "v3/wrapped-identity";

    pub fn keys(&self) -> &UserKeys {
        &self.keys
    }

    pub fn into_keys(self) -> UserKeys {
        self.keys
    }

    pub fn person(&self) -> PersonKey {
        PersonKey::of(&self.keys)
    }

    pub fn passphrase_fingerprint(&self) -> Fingerprint {
        Fingerprint::of(&self.passphrase_recipient)
    }

    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>, Error> {
        let mut w = record::Writer::new(Self::KIND);
        self.keys.write_fields(&mut w)?;
        w.field(
            "passphrase-recipient",
            &self.passphrase_recipient.to_string(),
        )?;
        w.finish().map(Zeroizing::new)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = record::Reader::new(bytes, Self::KIND)?;
        let identity = Self {
            keys: UserKeys::read_fields(&mut r)?,
            passphrase_recipient: record::parse_recipient(r.field("passphrase-recipient")?)?,
        };
        r.finish()?;
        Ok(identity)
    }

    /// One age file to the passphrase key, the recovery recipient and every guardian's grant recipient.
    fn seal(&self, guardians: &[Guardian]) -> Result<Vec<u8>, Error> {
        let mut recipients: Vec<&dyn age::Recipient> =
            vec![&self.passphrase_recipient, self.keys.recovery_recipient()];
        recipients.extend(
            guardians
                .iter()
                .map(|g| &g.key.grant_recipient as &dyn age::Recipient),
        );
        agefile::encrypt_to_all(recipients.into_iter(), &self.encode()?)
    }

    fn open(wrap: &GuardianWrap, identity: &dyn age::Identity) -> Result<Self, Error> {
        let plaintext =
            agefile::decrypt_secret(std::iter::once(identity), &wrap.identity, MAX_RECORD_BYTES)?;
        let kid = Self::decode(&plaintext)?;
        kid.matches(wrap)?;
        Ok(kid)
    }

    /// The identity is the one the signed wrap announces.
    fn matches(&self, wrap: &GuardianWrap) -> Result<(), Error> {
        if self.keys.user_id() != wrap.kid.user_id {
            return Err(Error::WrongUser);
        }
        if self.person() != wrap.kid || self.passphrase_fingerprint() != wrap.passphrase_fingerprint
        {
            return Err(Error::RecipientMismatch);
        }
        Ok(())
    }

    /// Unlocks on any device of the kid with the passphrase (format §9.6).
    ///
    /// `wrap` is the current wrap from the server, `passphrase_key` the kid's `passphrase-key.age`. The wrap
    /// must name this passphrase key; an ended wrap is accepted only with a passphrase key written at the end
    /// of access, and a passphrase key written at the end refuses a wrap that still has guardians. After
    /// unlocking, open the kid's keyring and call [`Keyring::pin_guardian_wrap`] to check the owner's and
    /// guardians' keys against the kid's pins.
    pub fn unlock_with_passphrase(
        wrap: &[u8],
        passphrase_key: &[u8],
        passphrase: SecretString,
        max_cost: ScryptCost,
        expected: UserId,
    ) -> Result<(Self, GuardianWrap), Error> {
        let key = PassphraseKey::open(passphrase_key, passphrase, max_cost, expected)?;
        let wrap = Self::decode_own(wrap, expected)?;
        if Fingerprint::of(&key.recipient()) != wrap.passphrase_fingerprint {
            return Err(Error::RecipientMismatch);
        }
        match (key.access, wrap.access) {
            (Access::Ended, Access::Active) => return Err(Error::AccessEnded),
            (Access::Active, Access::Ended) => return Err(Error::NotAuthorized),
            _ => {}
        }
        let kid = Self::open(&wrap, &key.identity)?;
        Ok((kid, wrap))
    }

    /// Unlocks on any device of the kid with the printed recovery key (format §9.6).
    pub fn unlock_with_recovery(
        wrap: &[u8],
        recovery: &RecoveryKey,
        expected: UserId,
    ) -> Result<(Self, GuardianWrap), Error> {
        let wrap = Self::decode_own(wrap, expected)?;
        let kid = Self::open(&wrap, recovery.identity())?;
        Ok((kid, wrap))
    }

    fn decode_own(wrap: &[u8], expected: UserId) -> Result<GuardianWrap, Error> {
        let wrap = GuardianWrap::decode(wrap)?;
        if wrap.unverified().kid.user_id != expected {
            return Err(Error::WrongUser);
        }
        wrap.verify_self()
    }
}

/// Unlocks a kid's identity with a guardian's own key (format §9.5).
///
/// `wrap` is a wrap this device verified ([`Keyring::verify_guardian_wrap`], `verify_successor`). The
/// result holds the kid's keys in memory only; with them open the kid's keyring
/// ([`Keyring::open`]) to reach every space the kid is in, and the kid's grant inbox.
pub fn unlock_as_guardian(wrap: &GuardianWrap, guardian: &UserKeys) -> Result<KidIdentity, Error> {
    if wrap.access == Access::Ended {
        return Err(Error::AccessEnded);
    }
    match wrap.guardian(guardian.user_id()) {
        Some(g) if g.key.grant_recipient == guardian.grant_recipient() => {}
        _ => return Err(Error::NotGuardian),
    }
    KidIdentity::open(wrap, guardian.grant_identity())
}

/// A new wrap: upload it with compare-and-swap on the epoch; `state` is what this device now trusts.
pub struct Rewrap {
    pub wrap: Vec<u8>,
    pub state: GuardianWrap,
}

fn sign(mut draft: GuardianWrap, signer: &UserKeys) -> Result<Rewrap, Error> {
    let wrap = draft.encode(signer)?;
    draft.digest = WrapDigest::of(&wrap);
    Ok(Rewrap { wrap, state: draft })
}

fn draft(
    kid: &KidIdentity,
    owner: UserId,
    previous: Option<&GuardianWrap>,
    access: Access,
    guardians: Vec<Guardian>,
) -> Result<GuardianWrap, Error> {
    let epoch = match previous {
        None => 1,
        Some(p) => p.epoch.checked_add(1).ok_or(Error::Overflow)?,
    };
    Ok(GuardianWrap {
        kid: kid.person(),
        owner,
        epoch,
        previous: previous.map(|p| p.digest),
        access,
        passphrase_fingerprint: kid.passphrase_fingerprint(),
        identity: kid.seal(&guardians)?,
        guardians,
        digest: WrapDigest([0; 32]),
    })
}

/// The identity must be the one `trusted` wraps.
fn check_kid(trusted: &GuardianWrap, kid: &KidIdentity) -> Result<(), Error> {
    kid.matches(trusted)
}

/// Everything the owner's device uploads when a kid starts using Files (format §9.4, first wrap).
pub struct KidSetup {
    pub kid: KidIdentity,
    /// Shown once and printed; never stored.
    pub recovery: RecoveryKey,
    /// `passphrase-key.age`.
    pub passphrase_key: Vec<u8>,
    pub wrap: Rewrap,
    /// The kid's empty keyring (version 1), with pins for the kid, the owner and the parents.
    pub keyring: Vec<u8>,
}

/// Creates a kid's identity, wrapped to the passphrase the kid typed, a new recovery key and every
/// guardian: the owner (always) and `parents`. Signed by the owner.
///
/// The caller has checked each parent's keys against the owner's pins (or pinned them on first use after
/// comparing fingerprints).
pub fn setup_kid(
    kid_id: UserId,
    owner: &UserKeys,
    parents: &[PersonKey],
    passphrase: SecretString,
    cost: ScryptCost,
    now: u64,
) -> Result<KidSetup, Error> {
    let (keys, recovery) = UserKeys::generate(kid_id)?;
    let passphrase_key = PassphraseKey::generate(kid_id, Access::Active);
    let kid = KidIdentity {
        keys,
        passphrase_recipient: passphrase_key.recipient(),
    };
    let wrap = wrap_first(&kid, owner, parents, now)?;
    let mut keyring = Keyring::new(kid_id);
    keyring.pin_guardian_wrap(&wrap.state)?;
    let keyring = keyring.seal(&kid.keys)?;
    Ok(KidSetup {
        passphrase_key: passphrase_key.seal(passphrase, cost)?,
        recovery,
        wrap,
        keyring,
        kid,
    })
}

/// The first wrap (epoch 1) of an identity, to the owner and `parents`, signed by the owner. [`setup_kid`]
/// uses it for a new identity; on its own it serves known-answer vectors, or starting a new chain for an
/// existing kid identity, which every follower must then accept as a first wrap again.
pub fn wrap_first(
    kid: &KidIdentity,
    owner: &UserKeys,
    parents: &[PersonKey],
    now: u64,
) -> Result<Rewrap, Error> {
    let mut guardians: Vec<Guardian> = std::iter::once(PersonKey::of(owner))
        .chain(parents.iter().cloned())
        .map(|key| Guardian {
            key,
            added_by: owner.user_id(),
            added_at: now,
        })
        .collect();
    guardians.sort_by_key(|g| g.key.user_id);
    sign(
        draft(kid, owner.user_id(), None, Access::Active, guardians)?,
        owner,
    )
}

/// Re-wraps the kid's identity to one more guardian.
///
/// `actor` is the owner (signs as owner), the kid (signs with the kid's key), or a current guardian (signs
/// with the kid's key from `kid`, and is recorded as `added-by`). The caller has checked `guardian`'s keys
/// against its pins.
pub fn add_guardian(
    trusted: &GuardianWrap,
    kid: &KidIdentity,
    actor: &UserKeys,
    guardian: PersonKey,
    now: u64,
) -> Result<Rewrap, Error> {
    if trusted.access == Access::Ended {
        return Err(Error::AccessEnded);
    }
    check_kid(trusted, kid)?;
    let id = guardian.user_id;
    if trusted.guardian(id).is_some() || id == trusted.kid.user_id {
        return Err(Error::Malformed("already a guardian, or the kid"));
    }
    let actor_id = actor.user_id();
    let acting_guardian = trusted
        .guardian(actor_id)
        .is_some_and(|g| g.key.verifying_key == actor.verifying_key());
    let signer = if actor_id == trusted.owner && acting_guardian {
        actor
    } else if actor_id == trusted.kid.user_id || acting_guardian {
        kid.keys()
    } else {
        return Err(Error::NotAuthorized);
    };
    let mut guardians = trusted.guardians.clone();
    guardians.push(Guardian {
        key: guardian,
        added_by: actor_id,
        added_at: now,
    });
    guardians.sort_by_key(|g| g.key.user_id);
    sign(
        draft(kid, trusted.owner, Some(trusted), trusted.access, guardians)?,
        signer,
    )
}

/// The kid's device changes the passphrase: a new passphrase key, and a re-wrap signed by the kid.
pub struct PassphraseChange {
    pub kid: KidIdentity,
    pub passphrase_key: Vec<u8>,
    pub wrap: Rewrap,
}

pub fn change_passphrase(
    trusted: &GuardianWrap,
    kid: &KidIdentity,
    passphrase: SecretString,
    cost: ScryptCost,
) -> Result<PassphraseChange, Error> {
    check_kid(trusted, kid)?;
    let key = PassphraseKey::generate(trusted.kid.user_id, trusted.access);
    let kid = KidIdentity {
        keys: kid.keys.clone(),
        passphrase_recipient: key.recipient(),
    };
    let wrap = sign(
        draft(
            &kid,
            trusted.owner,
            Some(trusted),
            trusted.access,
            trusted.guardians.clone(),
        )?,
        kid.keys(),
    )?;
    Ok(PassphraseChange {
        passphrase_key: key.seal(passphrase, cost)?,
        kid,
        wrap,
    })
}

/// The kid's device replaces the recovery key: the identity's recovery recipient changes (its public keys
/// do not), and the re-wrap is signed by the kid.
pub struct RecoveryChange {
    /// Shown once and printed.
    pub recovery: RecoveryKey,
    pub kid: KidIdentity,
    pub wrap: Rewrap,
}

pub fn new_recovery_key(
    trusted: &GuardianWrap,
    kid: &KidIdentity,
) -> Result<RecoveryChange, Error> {
    check_kid(trusted, kid)?;
    let mut keys = kid.keys.clone();
    let recovery = keys.new_recovery_key();
    let kid = KidIdentity {
        keys,
        passphrase_recipient: kid.passphrase_recipient.clone(),
    };
    let wrap = sign(
        draft(
            &kid,
            trusted.owner,
            Some(trusted),
            trusted.access,
            trusted.guardians.clone(),
        )?,
        kid.keys(),
    )?;
    Ok(RecoveryChange {
        recovery,
        kid,
        wrap,
    })
}

/// What happens to one space of the kid when the kid's identity is rotated.
pub enum SpaceChange {
    /// Someone who loses access could read this space only through the kid: it moves to a new epoch
    /// (upload the rotation, roster and grants; then re-encrypt its objects, format §6.3).
    Rotated {
        space_id: SpaceId,
        output: RotationOutput,
    },
    /// Everyone who loses access is a member anyway: only the kid's member line changes to the new keys
    /// (upload as a roster change within the epoch, format §3.1).
    RosterUpdated { space_id: SpaceId, roster: Vec<u8> },
}

/// A space the actor cannot change: neither the owner nor the kid is an admin of it, or its trusted roster
/// was not supplied. An admin of the space must update the kid's line and, if `needs_rotation`, rotate it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingSpace {
    pub space_id: SpaceId,
    pub needs_rotation: bool,
}

/// Everything uploaded when a kid's identity is rotated (a guardian removed, or access ended).
pub struct IdentityRotation {
    /// The new identity; the old one keeps working only for old data.
    pub kid: KidIdentity,
    /// A new recovery key to print, if one was made.
    pub recovery: Option<RecoveryKey>,
    /// A new `passphrase-key.age` (end of access only).
    pub passphrase_key: Option<Vec<u8>>,
    pub wrap: Rewrap,
    /// The signed `guardian-end` record (end of access only).
    pub end: Option<Vec<u8>>,
    /// Publish these as the kid's keys (a key change other people's clients see).
    pub published: PersonKey,
    /// The kid's keyring for the new identity: every space key the kid had, the new epochs, and the pins.
    pub keyring: Vec<u8>,
    pub spaces: Vec<SpaceChange>,
    pub pending: Vec<PendingSpace>,
}

/// Moves every space of the kid to the kid's new keys, rotating those `cut_off` people could read only
/// through the kid. Signs as the first of `signers` that is an admin of the space's roster.
fn rekey_spaces(
    old: &UserKeys,
    new: &UserKeys,
    signers: &[&UserKeys],
    cut_off: &[UserId],
    old_ring: &Keyring,
    rosters: &[Roster],
) -> Result<(Keyring, Vec<SpaceChange>, Vec<PendingSpace>), Error> {
    if old_ring.user_id() != old.user_id() {
        return Err(Error::WrongUser);
    }
    let kid = old.user_id();
    let mut ring = old_ring.clone();
    ring.replace_pin(kid, new.verifying_key());
    let mut changes = Vec::new();
    let mut pending = Vec::new();
    for space_id in old_ring.spaces() {
        let Some(latest) = old_ring.latest(space_id) else {
            continue;
        };
        let roster = rosters
            .iter()
            .find(|r| r.space_id == space_id && r.epoch == latest.epoch());
        let needs_rotation = roster.is_none_or(|r| cut_off.iter().any(|g| r.member(*g).is_none()));
        let target = roster.and_then(|r| {
            let member = r.member(kid)?;
            let signer = signers.iter().find(|s| {
                r.admin_key(s.user_id())
                    .is_ok_and(|key| *key == s.verifying_key())
            })?;
            Some((r, member, *signer))
        });
        let Some((roster, member, signer)) = target else {
            pending.push(PendingSpace {
                space_id,
                needs_rotation,
            });
            continue;
        };
        let updated = Member {
            user_id: kid,
            role: member.role,
            grant_recipient: new.grant_recipient(),
            verifying_key: new.verifying_key(),
        };
        if needs_rotation {
            let output = space::rotate_updating(latest, roster, &[], &[updated], signer)?;
            ring.insert(output.key.clone());
            changes.push(SpaceChange::Rotated { space_id, output });
        } else {
            let roster = roster.with_member(updated)?.seal(latest, signer)?;
            changes.push(SpaceChange::RosterUpdated { space_id, roster });
        }
    }
    Ok((ring, changes, pending))
}

/// Removes a guardian (format §9.5): rotates the kid's identity, re-wraps it to the remaining guardians,
/// carries every space key to the new identity, and re-keys the spaces the removed guardian could read only
/// through the kid. Signed by the owner, who must hold the kid's identity (as a guardian).
///
/// `kid_keyring` is the kid's keyring opened with the old identity, and `rosters` the trusted roster of the
/// latest epoch of each of the kid's spaces. With `new_recovery_key`, the kid also gets a new recovery key
/// (recommended when the removed guardian ever saw the printed one).
pub fn remove_guardian(
    trusted: &GuardianWrap,
    kid: &KidIdentity,
    owner: &UserKeys,
    removed: UserId,
    kid_keyring: &Keyring,
    rosters: &[Roster],
    new_recovery_key: bool,
) -> Result<IdentityRotation, Error> {
    if trusted.access == Access::Ended {
        return Err(Error::AccessEnded);
    }
    check_kid(trusted, kid)?;
    let owner_line = trusted
        .guardian(trusted.owner)
        .ok_or(Error::NotAuthorized)?;
    if owner.user_id() != trusted.owner || owner_line.key.verifying_key != owner.verifying_key() {
        return Err(Error::NotAuthorized);
    }
    if removed == trusted.owner {
        return Err(Error::NotAuthorized);
    }
    if trusted.guardian(removed).is_none() {
        return Err(Error::NotGuardian);
    }
    let mut keys = kid.keys.rotated()?;
    let recovery = new_recovery_key.then(|| keys.new_recovery_key());
    let new_kid = KidIdentity {
        keys,
        passphrase_recipient: kid.passphrase_recipient.clone(),
    };
    let guardians: Vec<Guardian> = trusted
        .guardians
        .iter()
        .filter(|g| g.key.user_id != removed)
        .cloned()
        .collect();
    let wrap = sign(
        draft(
            &new_kid,
            trusted.owner,
            Some(trusted),
            Access::Active,
            guardians,
        )?,
        owner,
    )?;
    let (mut ring, spaces, pending) = rekey_spaces(
        &kid.keys,
        &new_kid.keys,
        &[owner, &kid.keys],
        &[removed],
        kid_keyring,
        rosters,
    )?;
    ring.pin_guardian_wrap(&wrap.state)?;
    Ok(IdentityRotation {
        published: new_kid.person(),
        keyring: ring.seal(&new_kid.keys)?,
        kid: new_kid,
        recovery,
        passphrase_key: None,
        wrap,
        end: None,
        spaces,
        pending,
    })
}

/// Ends guardian access (format §9.7), on the kid's device with a passphrase only the kid knows: a new
/// identity, a new passphrase key marked `ended`, a new recovery key, a wrap without guardians signed by the
/// new key, a `guardian-end` record signed by the kid's old key, and the kid's spaces re-keyed so no former
/// guardian can read them through the kid any more. The owner does not take part.
pub fn end_guardian_access(
    trusted: &GuardianWrap,
    kid: &KidIdentity,
    passphrase: SecretString,
    cost: ScryptCost,
    kid_keyring: &Keyring,
    rosters: &[Roster],
    now: u64,
) -> Result<IdentityRotation, Error> {
    if trusted.access == Access::Ended {
        return Err(Error::AccessEnded);
    }
    check_kid(trusted, kid)?;
    let mut keys = kid.keys.rotated()?;
    let recovery = keys.new_recovery_key();
    let passphrase_key = PassphraseKey::generate(trusted.kid.user_id, Access::Ended);
    let new_kid = KidIdentity {
        keys,
        passphrase_recipient: passphrase_key.recipient(),
    };
    let wrap = sign(
        draft(
            &new_kid,
            trusted.owner,
            Some(trusted),
            Access::Ended,
            Vec::new(),
        )?,
        &new_kid.keys,
    )?;
    let end = GuardianEnd {
        kid: trusted.kid.user_id,
        owner: trusted.owner,
        from_epoch: trusted.epoch,
        from: trusted.digest,
        to: wrap.state.digest,
        new_kid: new_kid.person(),
        ended_at: now,
    }
    .encode(&kid.keys)?;
    let former: Vec<UserId> = trusted.guardians.iter().map(|g| g.key.user_id).collect();
    let (mut ring, spaces, pending) = rekey_spaces(
        &kid.keys,
        &new_kid.keys,
        &[&kid.keys],
        &former,
        kid_keyring,
        rosters,
    )?;
    ring.pin_guardian_wrap(&wrap.state)?;
    Ok(IdentityRotation {
        published: new_kid.person(),
        keyring: ring.seal(&new_kid.keys)?,
        kid: new_kid,
        recovery: Some(recovery),
        passphrase_key: Some(passphrase_key.seal(passphrase, cost)?),
        wrap,
        end: Some(end),
        spaces,
        pending,
    })
}

impl Keyring {
    /// Verifies a kid's wrap seen for the first time against the pinned key of its signer (owner or kid), or
    /// `published` on first use. A published key that differs from the pin is [`Error::KeyChanged`].
    pub fn verify_guardian_wrap(
        &self,
        wrap: Signed<GuardianWrap>,
        published: &VerifyingKey,
    ) -> Result<(GuardianWrap, Trust), Error> {
        let trust = self.check_pin(wrap.signer(), published)?;
        Ok((wrap.verify_first(published)?, trust))
    }

    /// Pins the kid's key and every guardian's key of an accepted wrap, or none if any conflicts with a pin.
    pub fn pin_guardian_wrap(&mut self, wrap: &GuardianWrap) -> Result<(), Error> {
        let people = || std::iter::once(&wrap.kid).chain(wrap.guardians.iter().map(|g| &g.key));
        for p in people() {
            self.check_pin(p.user_id, &p.verifying_key)?;
        }
        for p in people() {
            self.replace_pin(p.user_id, p.verifying_key);
        }
        Ok(())
    }

    /// Moves the pins from `trusted` to `next`, a wrap verified with `verify_successor` or `verify_end`
    /// against `trusted`. When the kid's identity was rotated, the kid's pin moves to the new key, which
    /// the owner (removal) or the kid's previous key (end) vouched for; any other key change is refused.
    pub fn follow_guardian_wrap(
        &mut self,
        trusted: &GuardianWrap,
        next: &GuardianWrap,
    ) -> Result<(), Error> {
        trusted.follows(next)?;
        let kid = trusted.kid.user_id;
        if next.kid.verifying_key != trusted.kid.verifying_key {
            self.check_pin(kid, &trusted.kid.verifying_key)?;
            for g in &next.guardians {
                self.check_pin(g.key.user_id, &g.key.verifying_key)?;
            }
            self.replace_pin(kid, next.kid.verifying_key);
        }
        self.pin_guardian_wrap(next)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn person(byte: u8) -> UserKeys {
        UserKeys::generate(UserId([byte; 16])).unwrap().0
    }

    fn cheap() -> ScryptCost {
        ScryptCost::new(10).unwrap()
    }

    struct Fixture {
        alice: UserKeys,
        bob: UserKeys,
        setup: KidSetup,
    }

    fn fixture() -> Fixture {
        let alice = person(0xa1);
        let bob = person(0xb0);
        let setup = setup_kid(
            UserId([0xc0; 16]),
            &alice,
            &[PersonKey::of(&bob)],
            SecretString::from("kid".to_owned()),
            cheap(),
            1_000,
        )
        .unwrap();
        Fixture { alice, bob, setup }
    }

    fn signed(draft: GuardianWrap, signer: &UserKeys) -> Signed<GuardianWrap> {
        GuardianWrap::decode(&sign(draft, signer).unwrap().wrap).unwrap()
    }

    #[test]
    fn person_lines_and_guardian_lines_round_trip() {
        let keys = person(7);
        let p = PersonKey::of(&keys);
        assert_eq!(PersonKey::parse_line(&p.line()).unwrap(), p);
        let g = Guardian {
            key: p,
            added_by: UserId([1; 16]),
            added_at: 1_760_000_000_000,
        };
        assert_eq!(Guardian::parse_line(&g.line()).unwrap(), g);
        assert!(Guardian::parse_line(&format!("{} 01", g.key.line())).is_err());
        assert!(Guardian::parse_line(&format!("{} extra", g.line())).is_err());
        assert!(Access::parse("Active").is_err());
    }

    #[test]
    fn the_kid_key_cannot_remove_guardians_or_replace_the_identity() {
        let f = fixture();
        let trusted = &f.setup.wrap.state;
        let kid = &f.setup.kid;
        let without_bob: Vec<Guardian> = trusted
            .guardians
            .iter()
            .filter(|g| g.key.user_id != f.bob.user_id())
            .cloned()
            .collect();
        let removal = draft(
            kid,
            trusted.owner,
            Some(trusted),
            Access::Active,
            without_bob,
        )
        .unwrap();
        assert!(matches!(
            signed(removal.clone(), kid.keys()).verify_successor(trusted),
            Err(Error::NotAuthorized)
        ));
        signed(removal, &f.alice).verify_successor(trusted).unwrap();

        let rotated = KidIdentity {
            keys: kid.keys.rotated().unwrap(),
            passphrase_recipient: kid.passphrase_recipient.clone(),
        };
        let swap = draft(
            &rotated,
            trusted.owner,
            Some(trusted),
            Access::Active,
            trusted.guardians.clone(),
        )
        .unwrap();
        assert!(matches!(
            signed(swap.clone(), kid.keys()).verify_successor(trusted),
            Err(Error::NotAuthorized)
        ));
        assert!(matches!(
            signed(swap.clone(), &rotated.keys).verify_successor(trusted),
            Err(Error::NotAuthorized)
        ));
        signed(swap, &f.alice).verify_successor(trusted).unwrap();
    }

    #[test]
    fn owner_changes_keep_existing_lines_and_the_owner() {
        let f = fixture();
        let trusted = &f.setup.wrap.state;
        let kid = &f.setup.kid;
        let dave = PersonKey::of(&person(0xd0));
        let with = |guardians: Vec<Guardian>| {
            let mut g = guardians;
            g.sort_by_key(|g| g.key.user_id);
            draft(kid, trusted.owner, Some(trusted), Access::Active, g).unwrap()
        };

        let mut added_by_kid = trusted.guardians.clone();
        added_by_kid.push(Guardian {
            key: dave.clone(),
            added_by: kid.keys.user_id(),
            added_at: 5,
        });
        assert!(matches!(
            signed(with(added_by_kid.clone()), &f.alice).verify_successor(trusted),
            Err(Error::NotAuthorized)
        ));
        signed(with(added_by_kid), kid.keys())
            .verify_successor(trusted)
            .unwrap();

        let mut backdated = trusted.guardians.clone();
        for g in &mut backdated {
            if g.key.user_id == f.bob.user_id() {
                g.added_at = 0;
            }
        }
        assert!(matches!(
            signed(with(backdated), &f.alice).verify_successor(trusted),
            Err(Error::NotAuthorized)
        ));

        let mut new_owner_key = trusted.guardians.clone();
        let other = person(0xa1);
        for g in &mut new_owner_key {
            if g.key.user_id == f.alice.user_id() {
                g.key = PersonKey::of(&other);
            }
        }
        assert!(matches!(
            signed(with(new_owner_key), &other).verify_successor(trusted),
            Err(Error::BadSignature | Error::NotAuthorized)
        ));
    }

    #[test]
    fn successors_must_name_the_trusted_wrap() {
        let f = fixture();
        let trusted = &f.setup.wrap.state;
        let kid = &f.setup.kid;
        let base = || {
            draft(
                kid,
                trusted.owner,
                Some(trusted),
                Access::Active,
                trusted.guardians.clone(),
            )
            .unwrap()
        };
        let mut skip = base();
        skip.epoch += 1;
        assert!(matches!(
            signed(skip, &f.alice).verify_successor(trusted),
            Err(Error::NotSuccessor)
        ));
        let mut fork = base();
        fork.previous = Some(WrapDigest([1; 32]));
        assert!(matches!(
            signed(fork, &f.alice).verify_successor(trusted),
            Err(Error::NotSuccessor)
        ));
        let replay = GuardianWrap::decode(&f.setup.wrap.wrap).unwrap();
        assert!(matches!(
            replay.verify_successor(trusted),
            Err(Error::NotSuccessor)
        ));

        let ended = draft(kid, trusted.owner, Some(trusted), Access::Ended, Vec::new()).unwrap();
        assert!(matches!(
            signed(ended, kid.keys()).verify_successor(trusted),
            Err(Error::NotAuthorized)
        ));
    }

    #[test]
    fn only_the_owner_or_the_kid_can_sign() {
        let f = fixture();
        let text = String::from_utf8(f.setup.wrap.wrap.clone()).unwrap();
        let as_bob = text.replace(
            &format!("signed-by: {}", f.alice.user_id()),
            &format!("signed-by: {}", f.bob.user_id()),
        );
        assert!(matches!(
            GuardianWrap::decode(as_bob.as_bytes()),
            Err(Error::NotAuthorized)
        ));
        let mut wrap = f.setup.wrap.state.clone();
        wrap.epoch = 2;
        wrap.previous = Some(WrapDigest([0; 32]));
        assert!(matches!(wrap.encode(&f.bob), Err(Error::NotAuthorized)));
    }

    #[test]
    fn the_wrapped_file_opens_only_for_its_recipients() {
        let f = fixture();
        let wrap = &f.setup.wrap.state;
        for g in [&f.alice, &f.bob] {
            let kid = KidIdentity::open(wrap, g.grant_identity()).unwrap();
            assert_eq!(kid.person(), wrap.kid);
        }
        assert!(matches!(
            KidIdentity::open(wrap, person(0xd0).grant_identity()),
            Err(Error::Decrypt(_))
        ));
        let impostor = person(0xb0);
        assert!(matches!(
            unlock_as_guardian(wrap, &impostor),
            Err(Error::NotGuardian)
        ));
    }
}
