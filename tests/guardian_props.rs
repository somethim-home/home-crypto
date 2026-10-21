//! Guardian wraps: canonical round trip, any byte change refused, and random sequences of changes that every
//! follower verifies step by step.

use home_crypto::guardian::{self, GuardianWrap, KidIdentity, PersonKey};
use home_crypto::identity::{ScryptCost, UserKeys};
use home_crypto::ids::UserId;
use home_crypto::keyring::Keyring;
use home_crypto::{Error, SecretString};
use proptest::prelude::*;

const KID: UserId = UserId([0xc0; 16]);

fn cheap() -> ScryptCost {
    ScryptCost::new(10).unwrap()
}

fn pass(n: u32) -> SecretString {
    SecretString::from(format!("passphrase {n}"))
}

fn adult(byte: u8) -> UserKeys {
    UserKeys::generate(UserId([byte; 16])).unwrap().0
}

#[derive(Clone, Debug)]
enum Op {
    OwnerAdds(usize),
    KidAdds(usize),
    GuardianAdds { by: usize, who: usize },
    OwnerRemoves(usize),
    KidChangesPassphrase,
}

enum Kind {
    KidOrGuardianAdds,
    Other,
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        (0usize..5).prop_map(Op::OwnerAdds),
        (0usize..5).prop_map(Op::KidAdds),
        (0usize..5, 0usize..5).prop_map(|(by, who)| Op::GuardianAdds { by, who }),
        (0usize..5).prop_map(Op::OwnerRemoves),
        Just(Op::KidChangesPassphrase),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]

    #[test]
    fn wrap_round_trips_and_rejects_any_byte_change(
        parents in proptest::collection::btree_set(1u8..0x9f, 0..4),
        now in any::<u64>(),
        index in any::<prop::sample::Index>(),
        flip in 1u8..=255,
    ) {
        let owner = adult(0xa0);
        let parents: Vec<PersonKey> = parents.into_iter().map(|b| PersonKey::of(&adult(b))).collect();
        let setup = guardian::setup_kid(KID, &owner, &parents, pass(0), cheap(), now).unwrap();
        let bytes = &setup.wrap.wrap;
        let signed = GuardianWrap::decode(bytes).unwrap();
        let without_signature = &bytes[..bytes[..bytes.len() - 1].iter().rposition(|&b| b == b'\n').unwrap() + 1];
        prop_assert_eq!(signed.unverified().signed_bytes(signed.signer()).unwrap(), without_signature.to_vec());
        let wrap = signed.verify_first(&owner.verifying_key()).unwrap();
        prop_assert_eq!(&wrap, &setup.wrap.state);
        prop_assert_eq!(wrap.guardians().len(), parents.len() + 1);

        let mut tampered = bytes.clone();
        let at = index.index(tampered.len());
        tampered[at] ^= flip;
        let accepted = GuardianWrap::decode(&tampered).and_then(|s| s.verify_first(&owner.verifying_key()));
        prop_assert!(accepted.is_err());
    }

    #[test]
    fn every_follower_verifies_each_step_and_only_current_guardians_unlock(
        ops in proptest::collection::vec(op(), 1..7),
    ) {
        let owner = adult(0xa0);
        let pool: Vec<UserKeys> = (1..=5u8).map(adult).collect();
        let setup = guardian::setup_kid(KID, &owner, &[PersonKey::of(&pool[0])], pass(0), cheap(), 1).unwrap();
        let mut kid = setup.kid;
        let mut passphrase_key = setup.passphrase_key;
        let mut pass_n = 0u32;
        let mut chain = vec![(setup.wrap.wrap, setup.wrap.state)];
        let mut follower = Keyring::new(owner.user_id());
        follower.pin_guardian_wrap(&chain[0].1).unwrap();

        for (step, op) in ops.into_iter().enumerate() {
            let trusted = chain.last().unwrap().1.clone();
            let now = step as u64 + 2;
            let op_kind = match op {
                Op::KidAdds(_) | Op::GuardianAdds { .. } => Kind::KidOrGuardianAdds,
                _ => Kind::Other,
            };
            let result = match op {
                Op::OwnerAdds(i) => guardian::add_guardian(&trusted, &kid, &owner, PersonKey::of(&pool[i]), now),
                Op::KidAdds(i) => guardian::add_guardian(&trusted, &kid, kid.keys(), PersonKey::of(&pool[i]), now),
                Op::GuardianAdds { by, who } => {
                    guardian::add_guardian(&trusted, &kid, &pool[by], PersonKey::of(&pool[who]), now)
                }
                Op::OwnerRemoves(i) => {
                    let ring = Keyring::new(KID);
                    guardian::remove_guardian(&trusted, &kid, &owner, pool[i].user_id(), &ring, &[], false)
                        .map(|out| {
                            kid = out.kid;
                            out.wrap
                        })
                }
                Op::KidChangesPassphrase => {
                    pass_n += 1;
                    guardian::change_passphrase(&trusted, &kid, pass(pass_n), cheap()).map(|c| {
                        kid = c.kid;
                        passphrase_key = c.passphrase_key;
                        c.wrap
                    })
                }
            };
            let refused_by_rule = matches!(op_kind, Kind::KidOrGuardianAdds);
            let Ok(rewrap) = result else {
                // Refused: adding someone twice, removing a non-guardian, and any addition not by the owner.
                continue;
            };
            prop_assert!(!refused_by_rule, "only the owner may add a guardian");
            let next = GuardianWrap::decode(&rewrap.wrap).unwrap().verify_successor(&trusted).unwrap();
            prop_assert_eq!(&next, &rewrap.state);
            follower.follow_guardian_wrap(&trusted, &next).unwrap();
            if chain.len() >= 2 {
                let older = &chain[chain.len() - 2].1;
                prop_assert!(matches!(
                    GuardianWrap::decode(&rewrap.wrap).unwrap().verify_successor(older),
                    Err(Error::NotSuccessor)
                ));
            }
            chain.push((rewrap.wrap, next));
        }

        let (bytes, latest) = chain.last().unwrap();
        prop_assert!(guardian::unlock_as_guardian(latest, &owner).is_ok());
        for p in &pool {
            let unlocked = guardian::unlock_as_guardian(latest, p);
            prop_assert_eq!(unlocked.is_ok(), latest.guardian(p.user_id()).is_some());
        }
        let (own, _) = KidIdentity::unlock_with_passphrase(bytes, &passphrase_key, pass(pass_n), cheap(), KID).unwrap();
        prop_assert_eq!(own.person(), kid.person());
        prop_assert_eq!(follower.pinned(KID), Some(&kid.keys().verifying_key()));
    }
}
