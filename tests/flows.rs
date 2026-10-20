use std::io::{Cursor, Read, Seek, SeekFrom};

use home_crypto::identity::{ScryptCost, UserKeys};
use home_crypto::ids::{ObjectId, SpaceId, UserId};
use home_crypto::keyring::{Keyring, Trust};
use home_crypto::object::{self, ObjectReader};
use home_crypto::space::{
    self, Epoch, Grant, Member, Role, Roster, Rotation, RotationOutput, SpaceKey,
};
use home_crypto::{Error, SecretString, share};

fn pass(s: &str) -> SecretString {
    SecretString::from(s.to_owned())
}

fn cheap() -> ScryptCost {
    ScryptCost::new(10).unwrap()
}

fn person(byte: u8) -> UserKeys {
    UserKeys::generate(UserId([byte; 16])).unwrap().0
}

#[test]
fn identity_unlocks_with_passphrase_or_recovery_only() {
    let user = UserId([1; 16]);
    let (mut keys, recovery) = UserKeys::generate(user).unwrap();
    let sealed_pass = keys
        .seal_with_passphrase(pass("hunter2 hunter2"), cheap())
        .unwrap();
    let sealed_recovery = keys.seal_for_recovery().unwrap();

    let a = UserKeys::unlock_with_passphrase(&sealed_pass, pass("hunter2 hunter2"), cheap(), user)
        .unwrap();
    assert_eq!(a.encode().unwrap(), keys.encode().unwrap());
    assert_eq!(a.verifying_key(), keys.verifying_key());
    assert_eq!(a.fingerprint(), keys.fingerprint());
    let b = UserKeys::unlock_with_recovery(&sealed_recovery, &recovery, user).unwrap();
    assert_eq!(b.encode().unwrap(), keys.encode().unwrap());

    assert!(matches!(
        UserKeys::unlock_with_passphrase(&sealed_pass, pass("wrong"), cheap(), user),
        Err(Error::Decrypt(_))
    ));
    assert!(matches!(
        UserKeys::unlock_with_recovery(&sealed_recovery, &recovery, UserId([2; 16])),
        Err(Error::WrongUser)
    ));
    let too_low = ScryptCost::new(9).unwrap();
    assert!(
        UserKeys::unlock_with_passphrase(&sealed_pass, pass("hunter2 hunter2"), too_low, user)
            .is_err()
    );
    assert!(ScryptCost::new(0).is_err() && ScryptCost::new(31).is_err());

    let new_recovery = keys.new_recovery_key();
    let resealed = keys.seal_for_recovery().unwrap();
    assert!(UserKeys::unlock_with_recovery(&resealed, &recovery, user).is_err());
    UserKeys::unlock_with_recovery(&resealed, &new_recovery, user).unwrap();
}

#[test]
fn person_fingerprint_covers_the_verifying_key() {
    let alice = person(0xa1);
    let impostor = person(0xa1);
    let mut m = Member::of(&alice, Role::Admin);
    assert_eq!(m.fingerprint(), alice.fingerprint());
    m.verifying_key = impostor.verifying_key();
    assert_ne!(m.fingerprint(), alice.fingerprint());
}

#[test]
fn keyring_round_trip_merge_and_rollback() {
    let keys = person(1);
    let space = SpaceId([9; 16]);
    let mut ring = Keyring::new(keys.user_id());
    ring.insert(SpaceKey::generate(space, Epoch(1)));
    ring.insert(SpaceKey::generate(space, Epoch(2)));
    let bob = person(0xb0);
    assert_eq!(
        ring.pin(bob.user_id(), bob.verifying_key()).unwrap(),
        Trust::FirstUse
    );
    let v1 = ring.seal(&keys).unwrap();
    let mut other = Keyring::open(&v1, &keys, 0).unwrap();
    assert_eq!(other.pinned(bob.user_id()), Some(&bob.verifying_key()));
    other.insert(SpaceKey::generate(SpaceId([3; 16]), Epoch(1)));
    let v2 = other.seal(&keys).unwrap();

    let opened = Keyring::open(&v2, &keys, 1).unwrap();
    assert_eq!(opened.version(), 2);
    assert_eq!(opened.space_keys(space).len(), 2);
    assert_eq!(opened.latest(space).unwrap().epoch(), Epoch(2));
    assert_eq!(opened.spaces(), vec![SpaceId([3; 16]), space]);
    assert!(matches!(
        Keyring::open(&v1, &keys, 2),
        Err(Error::Rollback { seen: 2, got: 1 })
    ));

    let stranger = person(1);
    assert!(Keyring::open(&v2, &stranger, 0).is_err());

    let impostor = person(0xb0);
    let mut conflicting = Keyring::new(keys.user_id());
    conflicting
        .pin(bob.user_id(), impostor.verifying_key())
        .unwrap();
    let mut merged = opened.clone();
    assert!(matches!(
        merged.merge(&conflicting),
        Err(Error::KeyChanged { user }) if user == bob.user_id()
    ));
    assert!(matches!(
        merged.pin(bob.user_id(), impostor.verifying_key()),
        Err(Error::KeyChanged { .. })
    ));
    merged.replace_pin(bob.user_id(), impostor.verifying_key());
    assert_eq!(
        merged
            .check_pin(bob.user_id(), &impostor.verifying_key())
            .unwrap(),
        Trust::Pinned
    );
}

struct Family {
    alice: UserKeys,
    bob: UserKeys,
    carol: UserKeys,
    epoch1: SpaceKey,
    roster: Roster,
}

fn family() -> Family {
    let alice = person(0xa1);
    let bob = person(0xb0);
    let carol = person(0xc0);
    let space = SpaceId([7; 16]);
    let epoch1 = SpaceKey::generate(space, Epoch::FIRST);
    let roster = Roster {
        space_id: space,
        epoch: Epoch::FIRST,
        name: "Family".into(),
        members: vec![
            Member::of(&alice, Role::Admin),
            Member::of(&bob, Role::Write),
            Member::of(&carol, Role::Read),
        ],
    };
    Family {
        alice,
        bob,
        carol,
        epoch1,
        roster,
    }
}

fn grant_for(out: &RotationOutput, user: UserId) -> &[u8] {
    &out.grants.iter().find(|(u, _)| *u == user).unwrap().1
}

#[test]
fn invitation_roster_and_valid_rotation_are_accepted() {
    let f = family();
    let sealed_roster = f.roster.seal(&f.epoch1, &f.alice).unwrap();

    let invite = Grant {
        granted_to: f.bob.user_id(),
        key: f.epoch1.clone(),
    }
    .seal(&f.alice, &f.bob.grant_recipient())
    .unwrap();
    let mut bob_ring = Keyring::new(f.bob.user_id());
    let signed = Grant::open(&invite, &f.bob).unwrap();
    assert_eq!(signed.signer(), f.alice.user_id());
    let (grant, trust) = bob_ring
        .verify_invitation(signed, &f.alice.verifying_key())
        .unwrap();
    assert_eq!(trust, Trust::FirstUse);
    assert_eq!(grant.key.fingerprint(), f.epoch1.fingerprint());
    bob_ring
        .pin(f.alice.user_id(), f.alice.verifying_key())
        .unwrap();
    bob_ring.insert(grant.key.clone());
    assert!(Grant::open(&invite, &f.carol).is_err());

    let roster = Roster::open(&sealed_roster, &grant.key)
        .unwrap()
        .verify_first(bob_ring.pinned(f.alice.user_id()).unwrap())
        .unwrap();
    assert_eq!(roster, f.roster);
    bob_ring.pin_members(&roster).unwrap();

    let out = space::rotate(&f.epoch1, &roster, &[f.carol.user_id()], &f.alice).unwrap();
    assert_eq!(out.key.epoch(), Epoch(2));
    assert_eq!(out.grants.len(), 2);
    let accepted = space::accept_rotation(
        &f.epoch1,
        &roster,
        &out.rotation,
        grant_for(&out, f.bob.user_id()),
        &out.roster,
        &f.bob,
    )
    .unwrap();
    assert_eq!(accepted.signer, f.alice.user_id());
    assert_eq!(accepted.rotation.removed, vec![f.carol.user_id()]);
    assert_eq!(accepted.key.fingerprint(), out.key.fingerprint());
    assert!(accepted.roster.member(f.carol.user_id()).is_none());
    bob_ring.pin_members(&accepted.roster).unwrap();
    assert!(
        out.grants
            .iter()
            .all(|(_, g)| Grant::open(g, &f.carol).is_err())
    );
    assert!(matches!(
        Roster::open(&out.roster, &f.epoch1),
        Err(Error::Decrypt(_))
    ));
}

#[test]
fn forged_grant_by_the_server_is_refused() {
    let f = family();
    let mut bob_ring = Keyring::new(f.bob.user_id());
    bob_ring
        .pin(f.alice.user_id(), f.alice.verifying_key())
        .unwrap();
    let server = UserKeys::generate(f.alice.user_id()).unwrap().0;
    let rogue_space = SpaceKey::generate(SpaceId([0xee; 16]), Epoch::FIRST);
    let forged = Grant {
        granted_to: f.bob.user_id(),
        key: rogue_space.clone(),
    }
    .seal(&server, &f.bob.grant_recipient())
    .unwrap();

    let signed = Grant::open(&forged, &f.bob).unwrap();
    assert_eq!(signed.signer(), f.alice.user_id());
    assert!(matches!(
        bob_ring.verify_invitation(signed, &server.verifying_key()),
        Err(Error::KeyChanged { .. })
    ));
    let signed = Grant::open(&forged, &f.bob).unwrap();
    assert!(matches!(
        bob_ring.verify_invitation(signed, &f.alice.verifying_key()),
        Err(Error::BadSignature)
    ));

    let unsigned = format!(
        "home-crypto/v2/grant\nspace-id: {}\nepoch: 1\ngranted-to: {}\nspace-identity: {}\nsigned-by: {}\n",
        rogue_space.space_id(),
        f.bob.user_id(),
        home_crypto::ExposeSecret::expose_secret(&share::to_url("x", &rogue_space))
            .split_once("#v1:")
            .unwrap()
            .1,
        f.alice.user_id(),
    );
    let sealed = age::encrypt(&f.bob.grant_recipient(), unsigned.as_bytes()).unwrap();
    assert!(matches!(Grant::open(&sealed, &f.bob), Err(Error::Unsigned)));

    let first_contact = Keyring::new(f.bob.user_id());
    let signed = Grant::open(&forged, &f.bob).unwrap();
    let (_, trust) = first_contact
        .verify_invitation(signed, &server.verifying_key())
        .unwrap();
    assert_eq!(trust, Trust::FirstUse);
    assert_ne!(server.fingerprint(), f.alice.fingerprint());
}

#[test]
fn a_member_cannot_forward_a_grant_to_someone_else() {
    let f = family();
    let invite = Grant {
        granted_to: f.bob.user_id(),
        key: f.epoch1.clone(),
    }
    .seal(&f.alice, &f.bob.grant_recipient())
    .unwrap();
    // What Bob would re-encrypt: Alice's signed grant to him, now addressed to Carol's recipient.
    let grant = Grant::open(&invite, &f.bob)
        .unwrap()
        .verify(&f.alice.verifying_key())
        .unwrap();
    let forwarded = Grant {
        granted_to: grant.granted_to,
        key: grant.key,
    }
    .seal(&f.alice, &f.carol.grant_recipient())
    .unwrap();
    assert!(matches!(
        Grant::open(&forwarded, &f.carol),
        Err(Error::WrongUser)
    ));
}

#[test]
fn removed_member_and_server_cannot_forge_a_rotation() {
    let f = family();
    let genuine = space::rotate(&f.epoch1, &f.roster, &[f.carol.user_id()], &f.alice).unwrap();

    // Carol signs with her own key: she is in the trusted roster, but not an admin.
    let mut carol_roster = f.roster.clone();
    carol_roster.members[2].role = Role::Admin;
    let own = space::rotate(&f.epoch1, &carol_roster, &[f.alice.user_id()], &f.carol).unwrap();
    assert!(matches!(
        space::accept_rotation(
            &f.epoch1,
            &f.roster,
            &own.rotation,
            grant_for(&own, f.bob.user_id()),
            &own.roster,
            &f.bob,
        ),
        Err(Error::NotAuthorized)
    ));

    // Carol and the server claim Alice as the signer without Alice's signing key.
    let fake_alice = UserKeys::generate(f.alice.user_id()).unwrap().0;
    let mut fake_roster = f.roster.clone();
    fake_roster.members[0].verifying_key = fake_alice.verifying_key();
    let forged = space::rotate(&f.epoch1, &fake_roster, &[f.carol.user_id()], &fake_alice).unwrap();
    assert!(matches!(
        space::accept_rotation(
            &f.epoch1,
            &f.roster,
            &forged.rotation,
            grant_for(&forged, f.bob.user_id()),
            &forged.roster,
            &f.bob,
        ),
        Err(Error::BadSignature)
    ));

    // The genuine rotation record with a grant and roster for a key Carol controls.
    let carol_key = SpaceKey::generate(f.epoch1.space_id(), Epoch(2));
    let carol_grant = Grant {
        granted_to: f.bob.user_id(),
        key: carol_key.clone(),
    }
    .seal(&f.carol, &f.bob.grant_recipient())
    .unwrap();
    assert!(matches!(
        space::accept_rotation(
            &f.epoch1,
            &f.roster,
            &genuine.rotation,
            &carol_grant,
            &genuine.roster,
            &f.bob,
        ),
        Err(Error::NotAuthorized)
    ));
    let fake_grant = Grant {
        granted_to: f.bob.user_id(),
        key: carol_key,
    }
    .seal(&fake_alice, &f.bob.grant_recipient())
    .unwrap();
    assert!(matches!(
        space::accept_rotation(
            &f.epoch1,
            &f.roster,
            &genuine.rotation,
            &fake_grant,
            &genuine.roster,
            &f.bob,
        ),
        Err(Error::BadSignature)
    ));

    // A self-signed rotation by a removed admin is refused, and Alice cannot be made to remove herself.
    let self_removal = Rotation {
        space_id: f.epoch1.space_id(),
        from: Epoch(1),
        to: Epoch(2),
        to_fingerprint: genuine.key.fingerprint(),
        removed: vec![f.alice.user_id()],
    }
    .seal(&f.epoch1, &f.alice)
    .unwrap();
    assert!(matches!(
        Rotation::open(&self_removal, &f.epoch1)
            .unwrap()
            .verify_against(&f.roster),
        Err(Error::NotAuthorized)
    ));
    assert!(matches!(
        space::rotate(&f.epoch1, &f.roster, &[f.alice.user_id()], &f.alice),
        Err(Error::NotAuthorized)
    ));
}

#[test]
fn members_authenticate_each_others_roster_changes() {
    let f = family();
    let dave = person(0xd0);
    let mut added = f.roster.clone();
    added.members.push(Member::of(&dave, Role::Read));

    let by_alice = added.seal(&f.epoch1, &f.alice).unwrap();
    assert_eq!(
        Roster::open(&by_alice, &f.epoch1)
            .unwrap()
            .verify_change(&f.roster)
            .unwrap(),
        added
    );

    let by_bob = added.seal(&f.epoch1, &f.bob).unwrap();
    assert!(matches!(
        Roster::open(&by_bob, &f.epoch1)
            .unwrap()
            .verify_change(&f.roster),
        Err(Error::NotAuthorized)
    ));

    let bob_as_alice = UserKeys::generate(f.alice.user_id()).unwrap().0;
    let forged = added.seal(&f.epoch1, &bob_as_alice).unwrap();
    assert!(matches!(
        Roster::open(&forged, &f.epoch1)
            .unwrap()
            .verify_change(&f.roster),
        Err(Error::BadSignature)
    ));
    assert!(matches!(
        Roster::open(&forged, &f.epoch1)
            .unwrap()
            .verify_first(&f.alice.verifying_key()),
        Err(Error::BadSignature)
    ));

    let mut swapped = f.roster.clone();
    swapped.members[1].verifying_key = dave.verifying_key();
    let swapped = Roster::open(&swapped.seal(&f.epoch1, &f.alice).unwrap(), &f.epoch1)
        .unwrap()
        .verify_change(&f.roster)
        .unwrap();
    let mut ring = Keyring::new(f.carol.user_id());
    ring.pin_members(&f.roster).unwrap();
    assert!(matches!(
        ring.pin_members(&swapped),
        Err(Error::KeyChanged { user }) if user == f.bob.user_id()
    ));
    assert_eq!(ring.pinned(f.bob.user_id()), Some(&f.bob.verifying_key()));
}

#[test]
fn object_round_trip_range_reads_and_swap_detection() {
    let key = SpaceKey::generate(SpaceId([5; 16]), Epoch::FIRST);
    let content: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    let id_a = ObjectId([0xaa; 16]);
    let id_b = ObjectId([0xbb; 16]);
    let (sealed_a, info) = object::encrypt(&key, id_a, &content[..], Vec::new()).unwrap();
    let (sealed_b, _) = object::encrypt(&key, id_b, &b"other"[..], Vec::new()).unwrap();
    assert_eq!(info.size, content.len() as u64);

    let out = ObjectReader::open([&key], id_a, &sealed_a[..])
        .unwrap()
        .verify_to_end(Vec::new(), &info)
        .unwrap();
    assert_eq!(out, content);

    let mut reader = ObjectReader::open([&key], id_a, Cursor::new(&sealed_a)).unwrap();
    for start in [0u64, 1, 65_535, 65_536, 131_000, 199_990] {
        assert_eq!(reader.seek(SeekFrom::Start(start)).unwrap(), start);
        let mut buf = [0u8; 10];
        let n = reader.read(&mut buf).unwrap();
        assert!(n > 0);
        assert_eq!(&buf[..n], &content[start as usize..start as usize + n]);
    }
    assert_eq!(
        reader.seek(SeekFrom::End(-5)).unwrap(),
        content.len() as u64 - 5
    );
    assert!(
        reader
            .seek(SeekFrom::End(-(content.len() as i64) - 1))
            .is_err()
    );

    assert!(matches!(
        ObjectReader::open([&key], id_a, &sealed_b[..]),
        Err(Error::WrongObject)
    ));
    let other = SpaceKey::generate(SpaceId([5; 16]), Epoch(2));
    assert!(ObjectReader::open([&other], id_a, &sealed_a[..]).is_err());

    let mut wrong = info;
    wrong.sha256[0] ^= 1;
    assert!(
        ObjectReader::open([&key], id_a, &sealed_a[..])
            .unwrap()
            .verify_to_end(Vec::new(), &wrong)
            .is_err()
    );

    let mut tampered = sealed_a.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    let mut sink = Vec::new();
    assert!(
        ObjectReader::open([&key], id_a, &tampered[..])
            .unwrap()
            .read_to_end(&mut sink)
            .is_err()
    );
}

#[test]
fn reencrypted_object_is_unreadable_with_the_old_epoch() {
    let old = SpaceKey::generate(SpaceId([5; 16]), Epoch(1));
    let new = SpaceKey::generate(SpaceId([5; 16]), Epoch(2));
    let id = ObjectId([1; 16]);
    let (sealed, info) = object::encrypt(&old, id, &b"holiday photos"[..], Vec::new()).unwrap();
    let (resealed, reinfo) = object::reencrypt([&old], &new, id, &sealed[..], Vec::new()).unwrap();
    assert_eq!(info, reinfo);
    assert!(ObjectReader::open([&old], id, &resealed[..]).is_err());
    let out = ObjectReader::open([&old, &new], id, &resealed[..])
        .unwrap()
        .verify_to_end(Vec::new(), &info)
        .unwrap();
    assert_eq!(out, b"holiday photos");
}

#[test]
fn objects_are_plain_age_files() {
    let key = SpaceKey::generate(SpaceId([5; 16]), Epoch(1));
    let id = ObjectId([3; 16]);
    let (sealed, _) = object::encrypt(&key, id, &b"abc"[..], Vec::new()).unwrap();
    let link = share::to_url("https://files.example/", &key);
    let parsed = share::parse(home_crypto::ExposeSecret::expose_secret(&link)).unwrap();
    assert_eq!(parsed.fingerprint(), key.fingerprint());
    assert_eq!(parsed.space_id(), key.space_id());
    let identity: age::x25519::Identity = home_crypto::ExposeSecret::expose_secret(&link)
        .split_once("#v1:")
        .unwrap()
        .1
        .parse()
        .unwrap();
    let plaintext = age::decrypt(&identity, &sealed).unwrap();
    assert_eq!(&plaintext[..5], b"HCOB\x01");
    assert_eq!(&plaintext[5..21], &id.0);
    assert_eq!(&plaintext[21..], b"abc");
    assert!(share::parse("https://files.example/s/zz#v1:x").is_err());
}
