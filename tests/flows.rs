use std::io::{Cursor, Read, Seek, SeekFrom};

use home_crypto::identity::{ScryptCost, UserKeys};
use home_crypto::ids::{ObjectId, SpaceId, UserId};
use home_crypto::keyring::Keyring;
use home_crypto::object::{self, ObjectReader};
use home_crypto::space::{self, Epoch, Grant, Member, Role, Roster, Rotation, SpaceKey};
use home_crypto::{Error, SecretString, share};

fn pass(s: &str) -> SecretString {
    SecretString::from(s.to_owned())
}

fn cheap() -> ScryptCost {
    ScryptCost::new(10).unwrap()
}

fn member(keys: &UserKeys, role: Role) -> Member {
    Member {
        user_id: keys.user_id(),
        role,
        grant_recipient: keys.grant_recipient(),
    }
}

#[test]
fn identity_unlocks_with_passphrase_or_recovery_only() {
    let user = UserId([1; 16]);
    let (mut keys, recovery) = UserKeys::generate(user);
    let sealed_pass = keys
        .seal_with_passphrase(pass("hunter2 hunter2"), cheap())
        .unwrap();
    let sealed_recovery = keys.seal_for_recovery().unwrap();

    let a = UserKeys::unlock_with_passphrase(&sealed_pass, pass("hunter2 hunter2"), cheap(), user)
        .unwrap();
    assert_eq!(a.encode().unwrap(), keys.encode().unwrap());
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
fn keyring_round_trip_merge_and_rollback() {
    let (keys, _) = UserKeys::generate(UserId([1; 16]));
    let space = SpaceId([9; 16]);
    let mut ring = Keyring::new(keys.user_id());
    ring.insert(SpaceKey::generate(space, Epoch(1)));
    ring.insert(SpaceKey::generate(space, Epoch(2)));
    let v1 = ring.seal(&keys).unwrap();
    let mut other = Keyring::open(&v1, &keys, 0).unwrap();
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

    let (stranger, _) = UserKeys::generate(UserId([1; 16]));
    assert!(Keyring::open(&v2, &stranger, 0).is_err());
}

#[test]
fn add_member_then_remove_with_rotation() {
    let (alice, _) = UserKeys::generate(UserId([0xa1; 16]));
    let (bob, _) = UserKeys::generate(UserId([0xb0; 16]));
    let (carol, _) = UserKeys::generate(UserId([0xc0; 16]));
    let space = SpaceId([7; 16]);
    let epoch1 = SpaceKey::generate(space, Epoch::FIRST);

    let roster = Roster {
        space_id: space,
        epoch: Epoch::FIRST,
        name: "Family".into(),
        members: vec![
            member(&alice, Role::Admin),
            member(&bob, Role::Write),
            member(&carol, Role::Read),
        ],
    };
    let sealed_roster = roster.seal(&epoch1).unwrap();
    assert_eq!(Roster::open(&sealed_roster, &epoch1).unwrap(), roster);

    let invite = Grant {
        granted_by: alice.user_id(),
        key: epoch1.clone(),
    }
    .seal(&bob.grant_recipient())
    .unwrap();
    let accepted = Grant::open(&invite, &bob).unwrap();
    assert_eq!(accepted.key.fingerprint(), epoch1.fingerprint());
    assert!(Grant::open(&invite, &carol).is_err());

    let out = space::rotate(&epoch1, &roster, &[carol.user_id()], alice.user_id()).unwrap();
    assert_eq!(out.key.epoch(), Epoch(2));
    assert_eq!(out.grants.len(), 2);

    let rotation = Rotation::open(&out.rotation, &epoch1).unwrap();
    assert_eq!(rotation.removed, vec![carol.user_id()]);
    let (_, bob_grant) = out
        .grants
        .iter()
        .find(|(u, _)| *u == bob.user_id())
        .unwrap();
    let epoch2 = rotation
        .accept(Grant::open(bob_grant, &bob).unwrap())
        .unwrap();
    assert_eq!(epoch2.fingerprint(), out.key.fingerprint());
    let new_roster = Roster::open(&out.roster, &epoch2).unwrap();
    assert!(new_roster.member(carol.user_id()).is_none());
    assert!(
        out.grants
            .iter()
            .all(|(_, g)| Grant::open(g, &carol).is_err())
    );

    let forged = SpaceKey::generate(space, Epoch(2));
    let forged_grant = Grant {
        granted_by: alice.user_id(),
        key: forged,
    };
    assert!(matches!(
        rotation.accept(forged_grant),
        Err(Error::RecipientMismatch)
    ));
    assert!(matches!(
        Roster::open(&out.roster, &epoch1),
        Err(Error::Decrypt(_))
    ));
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
