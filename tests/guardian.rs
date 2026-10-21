//! Guardian access (format §9): the owner and the kid's parents unlock the kid's identity with their own keys.

use home_crypto::guardian::{
    self, Access, GuardianEnd, GuardianWrap, KidIdentity, PendingSpace, PersonKey, SpaceChange,
};
use home_crypto::identity::{RecoveryKey, ScryptCost, UserKeys};
use home_crypto::ids::{ObjectId, SpaceId, UserId};
use home_crypto::keyring::{Keyring, Trust};
use home_crypto::object::{self, ContentInfo, ObjectReader};
use home_crypto::space::{self, Epoch, Grant, Member, Role, Roster, RotationOutput, SpaceKey};
use home_crypto::{Error, ExposeSecret, SecretString};

const KID: UserId = UserId([0xc0; 16]);
const NOW: u64 = 1_760_000_000_000;

fn pass(s: &str) -> SecretString {
    SecretString::from(s.to_owned())
}

fn cheap() -> ScryptCost {
    ScryptCost::new(10).unwrap()
}

fn person(byte: u8) -> UserKeys {
    UserKeys::generate(UserId([byte; 16])).unwrap().0
}

fn put(key: &SpaceKey, id: ObjectId, content: &[u8]) -> (Vec<u8>, ContentInfo) {
    object::encrypt(key, id, content, Vec::new()).unwrap()
}

fn get<'a>(
    keys: impl IntoIterator<Item = &'a SpaceKey>,
    id: ObjectId,
    sealed: &[u8],
    info: &ContentInfo,
) -> Result<Vec<u8>, Error> {
    ObjectReader::open(keys, id, sealed)?.verify_to_end(Vec::new(), info)
}

/// The grant identity of `keys`, as an age identity, to try raw decryption with.
fn grant_identity(keys: &UserKeys) -> age::x25519::Identity {
    let record = String::from_utf8(keys.encode().unwrap()).unwrap();
    let line = record
        .lines()
        .find_map(|l| l.strip_prefix("grant-identity: "))
        .unwrap();
    line.parse().unwrap()
}

/// Alice is the owner, Bob a parent, Dave an adult who is not a guardian; Carol is the kid.
struct Home {
    alice: UserKeys,
    bob: UserKeys,
    dave: UserKeys,
    setup: guardian::KidSetup,
    /// What the server stores.
    wrap: Vec<u8>,
    passphrase_key: Vec<u8>,
}

fn home() -> Home {
    let alice = person(0xa1);
    let bob = person(0xb0);
    let dave = person(0xd0);
    let setup = guardian::setup_kid(
        KID,
        &alice,
        &[PersonKey::of(&bob)],
        pass("carol's passphrase"),
        cheap(),
        NOW,
    )
    .unwrap();
    Home {
        wrap: setup.wrap.wrap.clone(),
        passphrase_key: setup.passphrase_key.clone(),
        alice,
        bob,
        dave,
        setup,
    }
}

/// A guardian's device: pins the owner, then accepts the first wrap it sees.
fn accept_first(ring: &mut Keyring, wrap: &[u8], published: &UserKeys) -> GuardianWrap {
    let signed = GuardianWrap::decode(wrap).unwrap();
    let (wrap, _) = ring
        .verify_guardian_wrap(signed, &published.verifying_key())
        .unwrap();
    ring.pin_guardian_wrap(&wrap).unwrap();
    wrap
}

fn kid_unlock(h: &Home) -> (KidIdentity, GuardianWrap) {
    KidIdentity::unlock_with_passphrase(
        &h.wrap,
        &h.passphrase_key,
        pass("carol's passphrase"),
        cheap(),
        KID,
    )
    .unwrap()
}

struct KidSpaces {
    private: SpaceKey,
    private_roster: Roster,
    family: SpaceKey,
    family_roster: Roster,
    ring: Keyring,
    sealed_ring: Vec<u8>,
}

/// Carol's private space (Carol admin) and the Family space (Alice admin, Bob write, Carol read).
fn kid_spaces(h: &Home, kid: &KidIdentity) -> KidSpaces {
    let private = SpaceKey::generate(SpaceId([0x01; 16]), Epoch::FIRST);
    let private_roster = Roster {
        space_id: private.space_id(),
        epoch: Epoch::FIRST,
        name: "Carol".into(),
        members: vec![Member::of(kid.keys(), Role::Admin)],
    };
    let family = SpaceKey::generate(SpaceId([0x02; 16]), Epoch::FIRST);
    let mut members = vec![
        Member::of(&h.alice, Role::Admin),
        Member::of(&h.bob, Role::Write),
        Member::of(kid.keys(), Role::Read),
    ];
    members.sort_by_key(|m| m.user_id);
    let family_roster = Roster {
        space_id: family.space_id(),
        epoch: Epoch::FIRST,
        name: "Family".into(),
        members,
    };
    let mut ring = Keyring::open(&h.setup.keyring, kid.keys(), 0).unwrap();
    ring.insert(private.clone());
    ring.insert(family.clone());
    let sealed_ring = ring.seal(kid.keys()).unwrap();
    KidSpaces {
        private,
        private_roster,
        family,
        family_roster,
        ring,
        sealed_ring,
    }
}

#[test]
fn setup_wraps_to_the_passphrase_the_recovery_key_and_every_guardian() {
    let h = home();
    let (kid, wrap) = kid_unlock(&h);
    assert_eq!(kid.person(), PersonKey::of(h.setup.kid.keys()));
    assert_eq!(wrap, h.setup.wrap.state);
    assert_eq!(wrap.epoch(), 1);
    assert_eq!(wrap.access(), Access::Active);
    assert_eq!(wrap.owner(), h.alice.user_id());
    let ids: Vec<UserId> = wrap.guardians().iter().map(|g| g.key.user_id).collect();
    assert_eq!(ids, vec![h.alice.user_id(), h.bob.user_id()]);
    assert!(
        wrap.guardians()
            .iter()
            .all(|g| g.added_by == h.alice.user_id() && g.added_at == NOW)
    );

    let (by_recovery, _) =
        KidIdentity::unlock_with_recovery(&h.wrap, &h.setup.recovery, KID).unwrap();
    assert_eq!(
        by_recovery.encode().unwrap().as_slice(),
        kid.encode().unwrap().as_slice()
    );
    assert!(matches!(
        KidIdentity::unlock_with_passphrase(
            &h.wrap,
            &h.passphrase_key,
            pass("guess"),
            cheap(),
            KID
        ),
        Err(Error::Decrypt(_))
    ));
    assert!(matches!(
        KidIdentity::unlock_with_recovery(&h.wrap, &h.setup.recovery, UserId([9; 16])),
        Err(Error::WrongUser)
    ));
    let stranger = RecoveryKey::parse(
        UserKeys::generate(KID)
            .unwrap()
            .1
            .to_secret_string()
            .expose_secret(),
    )
    .unwrap();
    assert!(KidIdentity::unlock_with_recovery(&h.wrap, &stranger, KID).is_err());

    // The kid's keyring pins the owner, the parents and the kid; the wrap agrees with them.
    let mut ring = Keyring::open(&h.setup.keyring, kid.keys(), 0).unwrap();
    assert_eq!(
        ring.pinned(h.alice.user_id()),
        Some(&h.alice.verifying_key())
    );
    assert_eq!(ring.pinned(KID), Some(&kid.keys().verifying_key()));
    ring.pin_guardian_wrap(&wrap).unwrap();
}

#[test]
fn a_guardian_reads_the_kids_spaces_including_ones_joined_after_the_wrap() {
    let h = home();
    let mut bob_ring = Keyring::new(h.bob.user_id());
    bob_ring
        .pin(h.alice.user_id(), h.alice.verifying_key())
        .unwrap();
    let trusted = accept_first(&mut bob_ring, &h.wrap, &h.alice);
    assert_eq!(
        bob_ring.pinned(KID),
        Some(&h.setup.kid.keys().verifying_key())
    );

    // The kid's device: private space, then a space created by someone else after the wrap.
    let (kid, _) = kid_unlock(&h);
    let s = kid_spaces(&h, &kid);
    let diary = ObjectId([0x10; 16]);
    let (diary_ct, diary_info) = put(&s.private, diary, b"dear diary");

    let club = SpaceKey::generate(SpaceId([0x03; 16]), Epoch::FIRST);
    let coach = person(0xe0);
    let invite = Grant {
        granted_to: KID,
        key: club.clone(),
    }
    .seal(&coach, &kid.keys().grant_recipient())
    .unwrap();
    let mut ring = Keyring::open(&s.sealed_ring, kid.keys(), 2).unwrap();
    let (grant, trust) = ring
        .verify_invitation(
            Grant::open(&invite, kid.keys()).unwrap(),
            &coach.verifying_key(),
        )
        .unwrap();
    assert_eq!(trust, Trust::FirstUse);
    ring.pin(coach.user_id(), coach.verifying_key()).unwrap();
    ring.insert(grant.key);
    let latest_ring = ring.seal(kid.keys()).unwrap();
    let schedule = ObjectId([0x11; 16]);
    let (schedule_ct, schedule_info) = put(&club, schedule, b"training at 5");

    // Bob, with only his own key and what the server stores.
    let carol = guardian::unlock_as_guardian(&trusted, &h.bob).unwrap();
    let carol_ring = Keyring::open(&latest_ring, carol.keys(), 0).unwrap();
    assert_eq!(carol_ring.spaces().len(), 3);
    assert_eq!(
        get(
            carol_ring.space_keys(s.private.space_id()),
            diary,
            &diary_ct,
            &diary_info
        )
        .unwrap(),
        b"dear diary"
    );
    assert_eq!(
        get(
            carol_ring.space_keys(club.space_id()),
            schedule,
            &schedule_ct,
            &schedule_info
        )
        .unwrap(),
        b"training at 5"
    );
    // Grants still waiting in Carol's inbox open too.
    assert!(Grant::open(&invite, carol.keys()).is_ok());

    // The owner can do the same.
    let alice_view = guardian::unlock_as_guardian(&trusted, &h.alice).unwrap();
    assert_eq!(alice_view.person(), kid.person());
}

#[test]
fn a_non_guardian_cannot_unlock_the_kid() {
    let h = home();
    let wrap = &h.setup.wrap.state;
    assert!(matches!(
        guardian::unlock_as_guardian(wrap, &h.dave),
        Err(Error::NotGuardian)
    ));
    // Claiming Bob's user id with other keys does not help.
    let fake_bob = UserKeys::generate(h.bob.user_id()).unwrap().0;
    assert!(matches!(
        guardian::unlock_as_guardian(wrap, &fake_bob),
        Err(Error::NotGuardian)
    ));
    // Nor does decrypting the wrapped file directly.
    for outsider in [&h.dave, &fake_bob] {
        assert!(age::decrypt(&grant_identity(outsider), wrap.identity_file()).is_err());
    }
    assert!(age::decrypt(&grant_identity(&h.bob), wrap.identity_file()).is_ok());
}

#[test]
fn forged_unsigned_or_server_edited_wraps_are_rejected() {
    let h = home();
    let mut bob_ring = Keyring::new(h.bob.user_id());
    bob_ring
        .pin(h.alice.user_id(), h.alice.verifying_key())
        .unwrap();
    let trusted = accept_first(&mut bob_ring, &h.wrap, &h.alice);

    // Unsigned.
    let text = String::from_utf8(h.wrap.clone()).unwrap();
    let unsigned = &text[..text.rfind("signature: ").unwrap()];
    assert!(matches!(
        GuardianWrap::decode(unsigned.as_bytes()),
        Err(Error::Unsigned)
    ));

    // The server slips Dave in as a guardian of the genuine wrap.
    let dave = PersonKey::of(&h.dave);
    let dave_line = format!(
        "guardian: {} {} {} {} {NOW}\n",
        dave.user_id,
        dave.grant_recipient,
        dave.verifying_key,
        h.alice.user_id()
    );
    let at = text.find("identity: ").unwrap();
    let edited = format!("{}{dave_line}{}", &text[..at], &text[at..]);
    assert!(matches!(
        GuardianWrap::decode(edited.as_bytes())
            .unwrap()
            .verify_first(&h.alice.verifying_key()),
        Err(Error::BadSignature)
    ));

    // The server signs a wrap of its own in Alice's name.
    let fake_alice = UserKeys::generate(h.alice.user_id()).unwrap().0;
    let forged = guardian::setup_kid(
        KID,
        &fake_alice,
        std::slice::from_ref(&dave),
        pass("x"),
        cheap(),
        NOW,
    )
    .unwrap();
    let signed = GuardianWrap::decode(&forged.wrap.wrap).unwrap();
    assert!(matches!(
        bob_ring.verify_guardian_wrap(signed, &fake_alice.verifying_key()),
        Err(Error::KeyChanged { .. })
    ));
    let signed = GuardianWrap::decode(&forged.wrap.wrap).unwrap();
    assert!(matches!(
        signed.verify_first(&h.alice.verifying_key()),
        Err(Error::KeyChanged { .. })
    ));
    // ...or as the next epoch of the genuine chain.
    let kid = guardian::unlock_as_guardian(&trusted, &h.bob).unwrap();
    let real_next = guardian::add_guardian(&trusted, &kid, &h.alice, dave.clone(), NOW).unwrap();
    let fake_text = String::from_utf8(real_next.wrap.clone()).unwrap();
    let fake_next = format!(
        "{}signature: {}\n",
        &fake_text[..fake_text.rfind("signature: ").unwrap()],
        "00".repeat(64)
    );
    assert!(
        GuardianWrap::decode(fake_next.as_bytes())
            .and_then(|w| w.verify_successor(&trusted))
            .is_err()
    );
    assert!(matches!(
        guardian::add_guardian(&trusted, &kid, &fake_alice, dave.clone(), NOW),
        Err(Error::NotAuthorized)
    ));
    // Dave cannot add himself: he does not hold the kid's identity, and is no guardian.
    assert!(matches!(
        guardian::add_guardian(&trusted, &kid, &h.dave, dave, NOW),
        Err(Error::NotAuthorized)
    ));

    // A wrap for another kid, or one that does not follow the trusted wrap, is refused.
    let next = GuardianWrap::decode(&real_next.wrap)
        .unwrap()
        .verify_successor(&trusted)
        .unwrap();
    assert!(matches!(
        GuardianWrap::decode(&real_next.wrap)
            .unwrap()
            .verify_successor(&next),
        Err(Error::NotSuccessor)
    ));
}

#[test]
fn the_kid_and_current_guardians_can_add_guardians() {
    let h = home();
    let trusted = h.setup.wrap.state.clone();
    let dave = PersonKey::of(&h.dave);

    // Bob (a guardian, not the owner) adds Dave: signed with Carol's key, recorded as added by Bob.
    let carol = guardian::unlock_as_guardian(&trusted, &h.bob).unwrap();
    let by_bob = guardian::add_guardian(&trusted, &carol, &h.bob, dave.clone(), NOW + 1).unwrap();
    let signed = GuardianWrap::decode(&by_bob.wrap).unwrap();
    assert_eq!(signed.signer(), KID);
    let next = signed.verify_successor(&trusted).unwrap();
    assert_eq!(next, by_bob.state);
    let line = next.guardian(h.dave.user_id()).unwrap();
    assert_eq!((line.added_by, line.added_at), (h.bob.user_id(), NOW + 1));
    assert_eq!(next.previous(), Some(trusted.digest()));

    // Dave sees Carol's wrap for the first time, signed by Carol's published key.
    let mut dave_ring = Keyring::new(h.dave.user_id());
    let (seen, trust) = dave_ring
        .verify_guardian_wrap(
            GuardianWrap::decode(&by_bob.wrap).unwrap(),
            &carol.keys().verifying_key(),
        )
        .unwrap();
    assert_eq!(trust, Trust::FirstUse);
    dave_ring.pin_guardian_wrap(&seen).unwrap();
    assert!(guardian::unlock_as_guardian(&seen, &h.dave).is_ok());

    // The kid's own device adds someone too; the owner adds someone as the owner.
    let erin = person(0xe1);
    let by_kid =
        guardian::add_guardian(&next, &carol, carol.keys(), PersonKey::of(&erin), NOW).unwrap();
    let next2 = GuardianWrap::decode(&by_kid.wrap)
        .unwrap()
        .verify_successor(&next)
        .unwrap();
    assert_eq!(next2.guardian(erin.user_id()).unwrap().added_by, KID);
    let fred = person(0xf0);
    let by_owner =
        guardian::add_guardian(&next2, &carol, &h.alice, PersonKey::of(&fred), NOW).unwrap();
    let signed = GuardianWrap::decode(&by_owner.wrap).unwrap();
    assert_eq!(signed.signer(), h.alice.user_id());
    let next3 = signed.verify_successor(&next2).unwrap();
    assert_eq!(next3.guardians().len(), 5);
    assert!(matches!(
        guardian::add_guardian(&next3, &carol, &h.alice, PersonKey::of(&fred), NOW),
        Err(Error::Malformed(_))
    ));

    // Every guardian's key opens the latest wrap; the kid's passphrase still does.
    for g in [&h.alice, &h.bob, &h.dave, &erin, &fred] {
        guardian::unlock_as_guardian(&next3, g).unwrap();
    }
    KidIdentity::unlock_with_passphrase(
        &by_owner.wrap,
        &h.passphrase_key,
        pass("carol's passphrase"),
        cheap(),
        KID,
    )
    .unwrap();
}

#[test]
fn passphrase_and_recovery_changes_are_signed_by_the_kid() {
    let h = home();
    let (carol, trusted) = kid_unlock(&h);
    let change =
        guardian::change_passphrase(&trusted, &carol, pass("new passphrase"), cheap()).unwrap();
    let next = GuardianWrap::decode(&change.wrap.wrap)
        .unwrap()
        .verify_successor(&trusted)
        .unwrap();
    assert_ne!(
        next.passphrase_fingerprint(),
        trusted.passphrase_fingerprint()
    );
    assert!(matches!(
        KidIdentity::unlock_with_passphrase(
            &change.wrap.wrap,
            &h.passphrase_key,
            pass("carol's passphrase"),
            cheap(),
            KID
        ),
        Err(Error::RecipientMismatch)
    ));
    let (again, _) = KidIdentity::unlock_with_passphrase(
        &change.wrap.wrap,
        &change.passphrase_key,
        pass("new passphrase"),
        cheap(),
        KID,
    )
    .unwrap();
    assert_eq!(again.person(), carol.person());
    guardian::unlock_as_guardian(&next, &h.bob).unwrap();

    // A kid who forgot the passphrase: Bob unlocks Carol with his own key and she types a new one.
    let as_bob = guardian::unlock_as_guardian(&next, &h.bob).unwrap();
    let reset = guardian::change_passphrase(&next, &as_bob, pass("reset"), cheap()).unwrap();
    let after_reset = GuardianWrap::decode(&reset.wrap.wrap)
        .unwrap()
        .verify_successor(&next)
        .unwrap();
    KidIdentity::unlock_with_passphrase(
        &reset.wrap.wrap,
        &reset.passphrase_key,
        pass("reset"),
        cheap(),
        KID,
    )
    .unwrap();

    let recovery = guardian::new_recovery_key(&after_reset, &reset.kid).unwrap();
    GuardianWrap::decode(&recovery.wrap.wrap)
        .unwrap()
        .verify_successor(&after_reset)
        .unwrap();
    KidIdentity::unlock_with_recovery(&recovery.wrap.wrap, &recovery.recovery, KID).unwrap();
    assert!(
        KidIdentity::unlock_with_recovery(&recovery.wrap.wrap, &h.setup.recovery, KID).is_err()
    );
}

fn rotation_of(changes: &[SpaceChange], space: SpaceId) -> &RotationOutput {
    changes
        .iter()
        .find_map(|c| match c {
            SpaceChange::Rotated { space_id, output } if *space_id == space => Some(output),
            _ => None,
        })
        .unwrap()
}

fn roster_update_of(changes: &[SpaceChange], space: SpaceId) -> &[u8] {
    changes
        .iter()
        .find_map(|c| match c {
            SpaceChange::RosterUpdated { space_id, roster } if *space_id == space => {
                Some(roster.as_slice())
            }
            _ => None,
        })
        .unwrap()
}

#[test]
fn a_removed_guardian_cannot_open_anything_made_after_the_rotation() {
    let h = home();
    let (carol, _) = kid_unlock(&h);
    let s = kid_spaces(&h, &carol);
    let diary = ObjectId([0x10; 16]);
    let (diary_ct, diary_info) = put(&s.private, diary, b"before");

    // What Bob keeps: the old wrap, Carol's old identity, her old keyring and every key in it.
    let trusted = h.setup.wrap.state.clone();
    let bob_copy = guardian::unlock_as_guardian(&trusted, &h.bob).unwrap();
    let bob_ring_copy = Keyring::open(&s.sealed_ring, bob_copy.keys(), 0).unwrap();
    let bob_old_private = bob_ring_copy.space_keys(s.private.space_id());
    assert_eq!(
        get(bob_old_private.clone(), diary, &diary_ct, &diary_info).unwrap(),
        b"before"
    );

    // Alice removes Bob.
    let as_alice = guardian::unlock_as_guardian(&trusted, &h.alice).unwrap();
    let ring = Keyring::open(&s.sealed_ring, as_alice.keys(), 0).unwrap();
    let rosters = [s.private_roster.clone(), s.family_roster.clone()];
    let out = guardian::remove_guardian(
        &trusted,
        &as_alice,
        &h.alice,
        h.bob.user_id(),
        &ring,
        &rosters,
        true,
    )
    .unwrap();
    assert!(out.pending.is_empty());
    assert_ne!(out.published, trusted.kid().clone());
    assert_eq!(out.spaces.len(), 2);

    // Everyone following the chain sees an owner-signed rotation without Bob.
    let next = GuardianWrap::decode(&out.wrap.wrap)
        .unwrap()
        .verify_successor(&trusted)
        .unwrap();
    assert!(next.guardian(h.bob.user_id()).is_none());
    assert_eq!(next.kid(), &out.published);
    assert!(matches!(
        guardian::unlock_as_guardian(&next, &h.bob),
        Err(Error::NotGuardian)
    ));
    assert!(age::decrypt(&grant_identity(&h.bob), next.identity_file()).is_err());
    let new_carol = guardian::unlock_as_guardian(&next, &h.alice).unwrap();
    assert_eq!(new_carol.person(), out.published);
    assert!(Keyring::open(&out.keyring, bob_copy.keys(), 0).is_err());

    // The private space (Bob was not a member) moved to epoch 2, signed by Carol's old key as its admin.
    let private_rotation = rotation_of(&out.spaces, s.private.space_id());
    let accepted = space::accept_rotation(
        &s.private,
        &s.private_roster,
        &private_rotation.rotation,
        &private_rotation
            .grants
            .iter()
            .find(|(u, _)| *u == KID)
            .unwrap()
            .1,
        &private_rotation.roster,
        new_carol.keys(),
    )
    .unwrap();
    assert_eq!(accepted.key.epoch(), Epoch(2));
    let new_ring = Keyring::open(&out.keyring, new_carol.keys(), 0).unwrap();
    assert_eq!(
        new_ring.latest(s.private.space_id()).unwrap().fingerprint(),
        accepted.key.fingerprint()
    );
    assert_eq!(
        new_ring.pinned(KID),
        Some(&new_carol.keys().verifying_key())
    );

    // New and re-encrypted objects, and a space Carol joins later, are closed to Bob's copies.
    let after = ObjectId([0x12; 16]);
    let (after_ct, after_info) = put(&accepted.key, after, b"after");
    assert!(get(bob_old_private.clone(), after, &after_ct, &after_info).is_err());
    let (reenc, _) = object::reencrypt(
        new_ring.space_keys(s.private.space_id()),
        &accepted.key,
        diary,
        &diary_ct[..],
        Vec::new(),
    )
    .unwrap();
    assert!(get(bob_old_private.clone(), diary, &reenc, &diary_info).is_err());
    assert_eq!(
        get(
            new_ring.space_keys(s.private.space_id()),
            diary,
            &reenc,
            &diary_info
        )
        .unwrap(),
        b"before"
    );
    let later = SpaceKey::generate(SpaceId([0x04; 16]), Epoch::FIRST);
    let invite = Grant {
        granted_to: KID,
        key: later,
    }
    .seal(&h.alice, &new_carol.keys().grant_recipient())
    .unwrap();
    assert!(Grant::open(&invite, bob_copy.keys()).is_err());

    // Family (Bob is a member anyway) keeps its epoch; Alice signs Carol's new line, and members who follow
    // the wrap chain move their pin for Carol.
    let family_roster = Roster::open(
        roster_update_of(&out.spaces, s.family.space_id()),
        &s.family,
    )
    .unwrap()
    .verify_change(&s.family_roster)
    .unwrap();
    assert_eq!(
        family_roster.member(KID).unwrap().verifying_key,
        new_carol.keys().verifying_key()
    );
    let mut bob_ring = Keyring::new(h.bob.user_id());
    bob_ring.pin_members(&s.family_roster).unwrap();
    assert!(matches!(
        bob_ring.clone().pin_members(&family_roster),
        Err(Error::KeyChanged { user }) if user == KID
    ));
    bob_ring.follow_guardian_wrap(&trusted, &next).unwrap();
    bob_ring.pin_members(&family_roster).unwrap();

    // The kid unlocks the new identity with the same passphrase and the new recovery key.
    let (by_pass, _) = KidIdentity::unlock_with_passphrase(
        &out.wrap.wrap,
        &h.passphrase_key,
        pass("carol's passphrase"),
        cheap(),
        KID,
    )
    .unwrap();
    assert_eq!(by_pass.person(), out.published);
    let recovery = out.recovery.as_ref().unwrap();
    KidIdentity::unlock_with_recovery(&out.wrap.wrap, recovery, KID).unwrap();
    assert!(KidIdentity::unlock_with_recovery(&out.wrap.wrap, &h.setup.recovery, KID).is_err());

    // Only the owner removes guardians, and never themselves.
    assert!(matches!(
        guardian::remove_guardian(
            &trusted,
            &bob_copy,
            &h.bob,
            h.alice.user_id(),
            &ring,
            &rosters,
            false
        ),
        Err(Error::NotAuthorized)
    ));
    assert!(matches!(
        guardian::remove_guardian(
            &trusted,
            &as_alice,
            &h.alice,
            h.alice.user_id(),
            &ring,
            &rosters,
            false
        ),
        Err(Error::NotAuthorized)
    ));
    assert!(matches!(
        guardian::remove_guardian(
            &trusted,
            &as_alice,
            &h.alice,
            h.dave.user_id(),
            &ring,
            &rosters,
            false
        ),
        Err(Error::NotGuardian)
    ));
}

#[test]
fn spaces_without_an_admin_at_hand_are_reported_pending() {
    let h = home();
    let (carol, _) = kid_unlock(&h);
    let s = kid_spaces(&h, &carol);
    let trusted = h.setup.wrap.state.clone();
    // No roster supplied for the private space, so it stays pending; Alice updates Family herself.
    let out = guardian::remove_guardian(
        &trusted,
        &carol,
        &h.alice,
        h.bob.user_id(),
        &s.ring,
        std::slice::from_ref(&s.family_roster),
        false,
    )
    .unwrap();
    assert_eq!(
        out.pending,
        vec![PendingSpace {
            space_id: s.private.space_id(),
            needs_rotation: true
        }]
    );
    assert!(out.recovery.is_none());
}

#[test]
fn ending_guardian_access_leaves_an_identity_only_the_kid_knows() {
    let h = home();
    let (carol, trusted) = kid_unlock(&h);
    let s = kid_spaces(&h, &carol);
    let rosters = [s.private_roster.clone(), s.family_roster.clone()];
    let out = guardian::end_guardian_access(
        &trusted,
        &carol,
        pass("grown up"),
        cheap(),
        &s.ring,
        &rosters,
        NOW,
    )
    .unwrap();
    // The private space is re-keyed by Carol; Family needs Alice (its admin) to update Carol's line.
    rotation_of(&out.spaces, s.private.space_id());
    assert_eq!(
        out.pending,
        vec![PendingSpace {
            space_id: s.family.space_id(),
            needs_rotation: false
        }]
    );

    // Guardians verify the end against the wrap they trust and can no longer unlock.
    let end_bytes = out.end.as_ref().unwrap();
    let (ended, end) = GuardianWrap::decode(&out.wrap.wrap)
        .unwrap()
        .verify_end(&trusted, GuardianEnd::decode(end_bytes).unwrap())
        .unwrap();
    assert_eq!(ended.access(), Access::Ended);
    assert!(ended.guardians().is_empty());
    assert_eq!(end.new_kid, out.published);
    assert_eq!((end.from_epoch, end.ended_at), (1, NOW));
    for g in [&h.alice, &h.bob] {
        assert!(matches!(
            guardian::unlock_as_guardian(&ended, g),
            Err(Error::AccessEnded)
        ));
        assert!(age::decrypt(&grant_identity(g), ended.identity_file()).is_err());
    }
    assert!(matches!(
        GuardianWrap::decode(&out.wrap.wrap)
            .unwrap()
            .verify_successor(&trusted),
        Err(Error::NotAuthorized)
    ));
    let mut alice_ring = Keyring::new(h.alice.user_id());
    alice_ring.pin_guardian_wrap(&trusted).unwrap();
    alice_ring.follow_guardian_wrap(&trusted, &ended).unwrap();
    assert_eq!(alice_ring.pinned(KID), Some(&out.published.verifying_key));

    // An end record that names another wrap, or is signed by someone else, is refused.
    let text = String::from_utf8(end_bytes.clone()).unwrap().replace(
        &format!("ended-at: {NOW}"),
        &format!("ended-at: {}", NOW + 1),
    );
    assert!(matches!(
        GuardianWrap::decode(&out.wrap.wrap)
            .unwrap()
            .verify_end(&trusted, GuardianEnd::decode(text.as_bytes()).unwrap()),
        Err(Error::BadSignature)
    ));

    // Only the kid's new passphrase and new recovery key open the new identity.
    let new_key = out.passphrase_key.as_ref().unwrap();
    let (grown, _) = KidIdentity::unlock_with_passphrase(
        &out.wrap.wrap,
        new_key,
        pass("grown up"),
        cheap(),
        KID,
    )
    .unwrap();
    assert_eq!(grown.person(), out.published);
    assert!(matches!(
        KidIdentity::unlock_with_passphrase(
            &out.wrap.wrap,
            &h.passphrase_key,
            pass("carol's passphrase"),
            cheap(),
            KID
        ),
        Err(Error::RecipientMismatch)
    ));
    KidIdentity::unlock_with_recovery(&out.wrap.wrap, out.recovery.as_ref().unwrap(), KID).unwrap();
    assert!(KidIdentity::unlock_with_recovery(&out.wrap.wrap, &h.setup.recovery, KID).is_err());
    let new_ring = Keyring::open(&out.keyring, grown.keys(), 0).unwrap();
    assert_eq!(new_ring.space_keys(s.private.space_id()).len(), 2);
    assert_eq!(new_ring.space_keys(s.family.space_id()).len(), 1);

    // Ended is final: nobody re-adds a guardian, the kid can still change the passphrase.
    assert!(matches!(
        guardian::add_guardian(&ended, &grown, &h.alice, PersonKey::of(&h.bob), NOW),
        Err(Error::AccessEnded)
    ));
    let change = guardian::change_passphrase(&ended, &grown, pass("adult"), cheap()).unwrap();
    let after = GuardianWrap::decode(&change.wrap.wrap)
        .unwrap()
        .verify_successor(&ended)
        .unwrap();
    assert_eq!(after.access(), Access::Ended);
    KidIdentity::unlock_with_passphrase(
        &change.wrap.wrap,
        &change.passphrase_key,
        pass("adult"),
        cheap(),
        KID,
    )
    .unwrap();
}

#[test]
fn a_guardian_cannot_fake_the_end_of_access_to_the_kid() {
    let h = home();
    let trusted = h.setup.wrap.state.clone();
    let (carol, _) = kid_unlock(&h);
    let s = kid_spaces(&h, &carol);
    // Bob holds Carol's identity and "ends" access himself, with a passphrase he chose.
    let bob_copy = guardian::unlock_as_guardian(&trusted, &h.bob).unwrap();
    let rogue = guardian::end_guardian_access(
        &trusted,
        &bob_copy,
        pass("bob's choice"),
        cheap(),
        &s.ring,
        &[],
        NOW,
    )
    .unwrap();
    // The record chain is valid, so other guardians see the end (and who could have made it)...
    GuardianWrap::decode(&rogue.wrap.wrap)
        .unwrap()
        .verify_end(
            &trusted,
            GuardianEnd::decode(rogue.end.as_ref().unwrap()).unwrap(),
        )
        .unwrap();
    // ...but Carol's own passphrase opens neither his passphrase key nor, with her old key, his wrap: she
    // notices at once instead of using an identity Bob knows.
    assert!(matches!(
        KidIdentity::unlock_with_passphrase(
            &rogue.wrap.wrap,
            rogue.passphrase_key.as_ref().unwrap(),
            pass("carol's passphrase"),
            cheap(),
            KID
        ),
        Err(Error::Decrypt(_))
    ));
    assert!(matches!(
        KidIdentity::unlock_with_passphrase(
            &rogue.wrap.wrap,
            &h.passphrase_key,
            pass("carol's passphrase"),
            cheap(),
            KID
        ),
        Err(Error::RecipientMismatch)
    ));
}
