//! Signed records: canonical round trip, and any change to the signed bytes is refused.

use home_crypto::identity::UserKeys;
use home_crypto::ids::{SpaceId, UserId};
use home_crypto::space::{Epoch, Fingerprint, Member, Role, Roster, Rotation};
use proptest::prelude::*;

fn roster(name: String, ids: &[u8], admin: &UserKeys) -> Roster {
    let mut members: Vec<Member> = ids
        .iter()
        .map(|b| Member::of(&UserKeys::generate(UserId([*b; 16])).unwrap().0, Role::Read))
        .collect();
    members.push(Member::of(admin, Role::Admin));
    members.sort_by_key(|m| m.user_id);
    members.dedup_by_key(|m| m.user_id);
    Roster {
        space_id: SpaceId([0x5a; 16]),
        epoch: Epoch(3),
        name,
        members,
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn roster_round_trips_and_rejects_any_byte_change(
        name in "[a-zA-Z0-9 ☀é]{1,40}",
        ids in proptest::collection::vec(1u8..=0x9f, 0..5),
        index in any::<prop::sample::Index>(),
        flip in 1u8..=255,
    ) {
        let admin = UserKeys::generate(UserId([0xa0; 16])).unwrap().0;
        let r = roster(name, &ids, &admin);
        let bytes = r.encode(&admin).unwrap();
        let decoded = Roster::decode(&bytes).unwrap().verify_first(&admin.verifying_key()).unwrap();
        prop_assert_eq!(&decoded, &r);
        prop_assert_eq!(decoded.encode(&admin).unwrap(), bytes.clone());

        let mut tampered = bytes.clone();
        let at = index.index(tampered.len());
        tampered[at] ^= flip;
        let accepted = Roster::decode(&tampered)
            .and_then(|s| s.verify(&admin.verifying_key()));
        prop_assert!(accepted.is_err());

        let other = UserKeys::generate(UserId([0xa0; 16])).unwrap().0;
        prop_assert!(Roster::decode(&bytes).unwrap().verify(&other.verifying_key()).is_err());
    }

    #[test]
    fn rotation_signature_covers_every_field(
        removed in proptest::collection::btree_set(any::<[u8; 16]>(), 0..4),
        fingerprint in any::<[u8; 32]>(),
        from in 1u32..1000,
        index in any::<prop::sample::Index>(),
        flip in 1u8..=255,
    ) {
        let admin = UserKeys::generate(UserId([0xa0; 16])).unwrap().0;
        let rotation = Rotation {
            space_id: SpaceId([1; 16]),
            from: Epoch(from),
            to: Epoch(from + 1),
            to_fingerprint: Fingerprint(fingerprint),
            removed: removed.into_iter().map(UserId).collect(),
        };
        let bytes = rotation.encode(&admin).unwrap();
        let decoded = Rotation::decode(&bytes).unwrap().verify(&admin.verifying_key()).unwrap();
        prop_assert_eq!(&decoded, &rotation);

        let mut tampered = bytes;
        let at = index.index(tampered.len());
        tampered[at] ^= flip;
        prop_assert!(
            Rotation::decode(&tampered)
                .and_then(|s| s.verify(&admin.verifying_key()))
                .is_err()
        );
    }
}
