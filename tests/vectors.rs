//! Known-answer vectors under `tests/vectors/`; see the README there for how they were made.

use std::path::PathBuf;

use home_crypto::identity::{RecoveryKey, ScryptCost, UserKeys};
use home_crypto::ids::{DeviceId, ObjectId, SpaceId, UserId};
use home_crypto::keyring::Keyring;
use home_crypto::manifest::{Change, FileEntry, ManifestPath, ManifestState, SegmentKind};
use home_crypto::object::{self, ContentInfo, ObjectReader};
use home_crypto::space::{Epoch, Fingerprint, Grant, Member, Role, Roster, Rotation, SpaceKey};
use home_crypto::{ExposeSecret, SecretString, share};

const GRANT_KEY: &str =
    "AGE-SECRET-KEY-1XSVD55EPS638H74LSQGVCJGJKJPEY8CNU38SS9SYH4FMZDKQKEJSTJ67GQ";
const KEYRING_KEY: &str =
    "AGE-SECRET-KEY-1R60J7HSQYVS544ZQJZG3V2N468VCNN3VJJDS736RUVA0ZPR4YUPS59WDNX";
const RECOVERY_KEY: &str =
    "AGE-SECRET-KEY-1SDWSC7G75K4GQUEAVJZ3JNN2478VYWK2JZC8JGYCE90H2VM3ZJKQS8X745";
const EPOCH1_KEY: &str =
    "AGE-SECRET-KEY-18T09KJ9EH53K7E2R40KRPUCZ0US04TM6LRNJAHWDZLM5PWYLLSKSPFGH3T";
const EPOCH2_KEY: &str =
    "AGE-SECRET-KEY-1F52ZUHDNH9UR8D26ZJTKZG86X6KYYRESZMT2E6FH64VTAZCJY4SQM8YALN";
const BOB_GRANT_KEY: &str =
    "AGE-SECRET-KEY-17FV7E7M6FXFRNTMCTF2M7E5PUVEKZC4325UDZDZHZP6ZV3T8XQZQAQLSF3";
const PASSPHRASE: &str = "correct horse battery staple";
const ALICE: UserId = UserId([0xa1; 16]);
const BOB: UserId = UserId([0xb0; 16]);
const SPACE: SpaceId = SpaceId([0x5a; 16]);
const OBJECT: ObjectId = ObjectId([0x0b; 16]);

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors")
}

fn read(name: &str) -> Vec<u8> {
    std::fs::read(dir().join(name)).unwrap()
}

fn recipient_of(secret: &str) -> age::x25519::Recipient {
    secret.parse::<age::x25519::Identity>().unwrap().to_public()
}

struct Fixtures {
    alice: UserKeys,
    recovery: RecoveryKey,
    epoch1: SpaceKey,
    epoch2: SpaceKey,
    keyring: Keyring,
    grant: Grant,
    roster: Roster,
    rotation: Rotation,
    content: Vec<u8>,
    manifest: ManifestState,
}

fn fixtures() -> Fixtures {
    let record = format!(
        "home-crypto/v1/user-identity\nuser-id: {ALICE}\ngrant-identity: {GRANT_KEY}\n\
         keyring-identity: {KEYRING_KEY}\nrecovery-recipient: {}\n",
        recipient_of(RECOVERY_KEY)
    );
    let alice = UserKeys::decode(record.as_bytes()).unwrap();
    let epoch1 = SpaceKey::parse(SPACE, Epoch(1), EPOCH1_KEY).unwrap();
    let epoch2 = SpaceKey::parse(SPACE, Epoch(2), EPOCH2_KEY).unwrap();
    let keyring_record = format!(
        "home-crypto/v1/keyring\nuser-id: {ALICE}\nversion: 3\nspace: {SPACE} 1 {EPOCH1_KEY}\n\
         space: {SPACE} 2 {EPOCH2_KEY}\n"
    );
    let keyring = Keyring::decode(keyring_record.as_bytes()).unwrap();
    let roster = Roster {
        space_id: SPACE,
        epoch: Epoch(1),
        name: "Family photos ☀".into(),
        members: vec![
            Member {
                user_id: ALICE,
                role: Role::Admin,
                grant_recipient: alice.grant_recipient(),
            },
            Member {
                user_id: BOB,
                role: Role::Read,
                grant_recipient: recipient_of(BOB_GRANT_KEY),
            },
        ],
    };
    let rotation = Rotation {
        space_id: SPACE,
        from: Epoch(1),
        to: Epoch(2),
        to_fingerprint: epoch2.fingerprint(),
        removed: vec![BOB],
    };
    let content: Vec<u8> = (0..70_000u32)
        .map(|i| (i.wrapping_mul(31) % 256) as u8)
        .collect();
    let mut manifest = ManifestState::new(SPACE);
    let d1 = DeviceId([0xd1; 16]);
    let d2 = DeviceId([0xd2; 16]);
    let info = content_info(&content);
    manifest
        .record(
            d1,
            ManifestPath::new("photos").unwrap(),
            Change::Dir {
                mtime: 1_760_000_000_000,
            },
        )
        .unwrap();
    manifest
        .record(
            d1,
            ManifestPath::new("photos/beach.jpg").unwrap(),
            Change::File(FileEntry {
                mtime: 1_760_000_001_000,
                size: info.size,
                object_id: OBJECT,
                content_sha256: info.sha256,
            }),
        )
        .unwrap();
    let mut other = manifest.clone();
    manifest
        .record(d1, ManifestPath::new("notes.txt").unwrap(), Change::Delete)
        .unwrap();
    manifest
        .record(
            d1,
            ManifestPath::new("photos/beach.jpg").unwrap(),
            Change::File(FileEntry {
                mtime: 1_760_000_003_000,
                size: info.size,
                object_id: OBJECT,
                content_sha256: info.sha256,
            }),
        )
        .unwrap();
    other
        .record(
            d2,
            ManifestPath::new("photos/beach.jpg").unwrap(),
            Change::File(FileEntry {
                mtime: 1_760_000_002_000,
                size: 0,
                object_id: ObjectId([0x0c; 16]),
                content_sha256: [0xee; 32],
            }),
        )
        .unwrap();
    manifest.merge(&other).unwrap();
    Fixtures {
        recovery: RecoveryKey::parse(RECOVERY_KEY).unwrap(),
        grant: Grant {
            granted_by: ALICE,
            key: epoch1.clone(),
        },
        alice,
        epoch1,
        epoch2,
        keyring,
        roster,
        rotation,
        content,
        manifest,
    }
}

fn content_info(content: &[u8]) -> ContentInfo {
    use sha2::Digest;
    ContentInfo {
        size: content.len() as u64,
        sha256: sha2::Sha256::digest(content).into(),
    }
}

fn plaintexts(f: &Fixtures) -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("user-identity.txt", f.alice.encode().unwrap()),
        ("keyring.txt", f.keyring.encode().unwrap()),
        ("grant.txt", f.grant.encode().unwrap()),
        ("roster.txt", f.roster.encode().unwrap()),
        ("rotation.txt", f.rotation.encode().unwrap()),
        (
            "manifest-snapshot.bin",
            f.manifest.encode(SegmentKind::Snapshot).unwrap(),
        ),
        (
            "share-link.txt",
            format!(
                "{}\n",
                share::to_url("https://files.home.example", &f.epoch1).expose_secret()
            )
            .into_bytes(),
        ),
        (
            "fingerprints.txt",
            format!(
                "epoch1 {} {}\nepoch2 {} {}\n",
                f.epoch1.fingerprint(),
                f.epoch1.fingerprint().safety_number(),
                f.epoch2.fingerprint(),
                f.epoch2.fingerprint().safety_number()
            )
            .into_bytes(),
        ),
    ]
}

#[test]
fn deterministic_plaintexts_match_byte_for_byte() {
    let f = fixtures();
    for (name, bytes) in plaintexts(&f) {
        assert_eq!(read(name), bytes, "{name}");
    }
    assert_eq!(read("object-content.bin"), f.content);
}

#[test]
fn committed_ciphertexts_decrypt_to_the_plaintexts() {
    let f = fixtures();
    let pass = SecretString::from(PASSPHRASE.to_owned());
    let cost = ScryptCost::new(10).unwrap();
    let unlocked =
        UserKeys::unlock_with_passphrase(&read("identity.passphrase.age"), pass, cost, ALICE)
            .unwrap();
    assert_eq!(unlocked.encode().unwrap(), read("user-identity.txt"));
    let recovered =
        UserKeys::unlock_with_recovery(&read("identity.recovery.age"), &f.recovery, ALICE).unwrap();
    assert_eq!(recovered.encode().unwrap(), read("user-identity.txt"));

    let keyring = Keyring::open(&read("keyring.age"), &f.alice, 3).unwrap();
    assert_eq!(keyring.encode().unwrap(), read("keyring.txt"));

    let bob = UserKeys::decode(
        format!(
            "home-crypto/v1/user-identity\nuser-id: {BOB}\ngrant-identity: {BOB_GRANT_KEY}\n\
             keyring-identity: {KEYRING_KEY}\nrecovery-recipient: {}\n",
            recipient_of(RECOVERY_KEY)
        )
        .as_bytes(),
    )
    .unwrap();
    let grant = Grant::open(&read("grant.age"), &bob).unwrap();
    assert_eq!(grant.encode().unwrap(), read("grant.txt"));

    assert_eq!(
        Roster::open(&read("roster.age"), &f.epoch1)
            .unwrap()
            .encode()
            .unwrap(),
        read("roster.txt")
    );
    let rotation = Rotation::open(&read("rotation.age"), &f.epoch1).unwrap();
    assert_eq!(rotation.encode().unwrap(), read("rotation.txt"));
    assert_eq!(
        rotation.to_fingerprint,
        Fingerprint::of(&f.epoch2.recipient())
    );

    let content = ObjectReader::open([&f.epoch1, &f.epoch2], OBJECT, &read("object.age")[..])
        .unwrap()
        .verify_to_end(Vec::new(), &content_info(&f.content))
        .unwrap();
    assert_eq!(content, f.content);

    let (kind, manifest) = ManifestState::open(
        &read("manifest-snapshot.age"),
        SPACE,
        [&f.epoch1, &f.epoch2],
    )
    .unwrap();
    assert_eq!(kind, SegmentKind::Snapshot);
    assert_eq!(manifest, f.manifest);
    assert_eq!(manifest.view().conflicts.len(), 1);
}

/// Rewrites every vector; ciphertexts change on each run because age draws fresh randomness.
#[test]
#[ignore = "run explicitly to regenerate tests/vectors"]
fn regenerate() {
    let f = fixtures();
    let write = |name: &str, bytes: &[u8]| std::fs::write(dir().join(name), bytes).unwrap();
    for (name, bytes) in plaintexts(&f) {
        write(name, &bytes);
    }
    write("object-content.bin", &f.content);
    let pass = SecretString::from(PASSPHRASE.to_owned());
    write(
        "identity.passphrase.age",
        &f.alice
            .seal_with_passphrase(pass, ScryptCost::new(10).unwrap())
            .unwrap(),
    );
    write(
        "identity.recovery.age",
        &f.alice.seal_for_recovery().unwrap(),
    );
    write("keyring.age", &seal_at_version_three(&f.keyring, &f.alice));
    write(
        "grant.age",
        &f.grant.seal(&recipient_of(BOB_GRANT_KEY)).unwrap(),
    );
    write("roster.age", &f.roster.seal(&f.epoch1).unwrap());
    write("rotation.age", &f.rotation.seal(&f.epoch1).unwrap());
    let (object, _) = object::encrypt(&f.epoch1, OBJECT, &f.content[..], Vec::new()).unwrap();
    write("object.age", &object);
    write(
        "manifest-snapshot.age",
        &f.manifest.seal(SegmentKind::Snapshot, &f.epoch2).unwrap(),
    );
}

/// `Keyring::seal` increments the version, so seal from version 2 to store version 3.
fn seal_at_version_three(keyring: &Keyring, keys: &UserKeys) -> Vec<u8> {
    let text = String::from_utf8(keyring.encode().unwrap())
        .unwrap()
        .replace("version: 3\n", "version: 2\n");
    let mut lower = Keyring::decode(text.as_bytes()).unwrap();
    let sealed = lower.seal(keys).unwrap();
    assert_eq!(lower.version(), 3);
    sealed
}
