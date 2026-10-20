use home_crypto::Error;
use home_crypto::ids::{DeviceId, ObjectId, SpaceId};
use home_crypto::manifest::{Change, FileEntry, ManifestPath, ManifestState, SegmentKind};
use home_crypto::space::{Epoch, SpaceKey};

const SPACE: SpaceId = SpaceId([7; 16]);
const D1: DeviceId = DeviceId([1; 16]);
const D2: DeviceId = DeviceId([2; 16]);

fn file(n: u8) -> Change {
    Change::File(FileEntry {
        mtime: i64::from(n) * 1000,
        size: u64::from(n),
        object_id: ObjectId([n; 16]),
        content_sha256: [n; 32],
    })
}

fn path(p: &str) -> ManifestPath {
    ManifestPath::new(p).unwrap()
}

#[test]
fn concurrent_writes_produce_one_winner_and_a_conflict_until_resolved() {
    let mut a = ManifestState::new(SPACE);
    a.record(D1, path("docs/a.txt"), file(1)).unwrap();
    let mut b = a.clone();
    a.record(D1, path("docs/a.txt"), file(2)).unwrap();
    b.record(D2, path("docs/a.txt"), file(3)).unwrap();

    let mut ab = a.clone();
    ab.merge(&b).unwrap();
    let mut ba = b.clone();
    ba.merge(&a).unwrap();
    assert_eq!(ab, ba);
    let view = ab.view();
    assert_eq!(view.entries[&path("docs/a.txt")].change, file(3));
    assert_eq!(view.conflicts.len(), 1);
    assert_eq!(
        view.conflicts[0].file,
        match file(2) {
            Change::File(f) => f,
            _ => unreachable!(),
        }
    );

    ab.record(D1, path("docs/a.txt"), file(4)).unwrap();
    let view = ab.view();
    assert!(view.conflicts.is_empty());
    assert_eq!(view.entries[&path("docs/a.txt")].change, file(4));
}

#[test]
fn delete_and_dirs() {
    let mut s = ManifestState::new(SPACE);
    s.record(D1, path("empty"), Change::Dir { mtime: 5 })
        .unwrap();
    s.record(D1, path("x"), file(1)).unwrap();
    s.record(D1, path("x"), Change::Delete).unwrap();
    let view = s.view();
    assert_eq!(view.entries.len(), 1);
    assert_eq!(
        view.entries[&path("empty")].change,
        Change::Dir { mtime: 5 }
    );
    assert_eq!(path("a/b/c.txt").name(), "c.txt");
}

#[test]
fn compaction_keeps_the_view_and_old_segments_stay_pruned() {
    let mut s = ManifestState::new(SPACE);
    let first = s.record(D1, path("x"), file(1)).unwrap();
    s.record(D1, path("x"), file(2)).unwrap();
    let before = s.view();
    s.compact();
    assert_eq!(s.ops().count(), 1);
    assert_eq!(s.view(), before);
    let old_log = ManifestState::log_segment(SPACE, [first]).unwrap();
    s.merge(&old_log).unwrap();
    assert_eq!(s.ops().count(), 1);
    assert_eq!(s.view(), before);
}

#[test]
fn paths_are_validated() {
    for bad in ["", "/a", "a/", "a//b", ".", "a/../b", "a/./b", "a\0b"] {
        assert!(ManifestPath::new(bad).is_err(), "{bad:?}");
    }
    assert!(ManifestPath::new("x".repeat(256)).is_err());
    assert!(ManifestPath::new(format!("{}/b", "x".repeat(255))).is_ok());
}

#[test]
fn equivocation_and_wrong_space_are_rejected() {
    let mut a = ManifestState::new(SPACE);
    let mut b = ManifestState::new(SPACE);
    a.record(D1, path("x"), file(1)).unwrap();
    b.record(D1, path("x"), file(2)).unwrap();
    assert!(matches!(a.merge(&b), Err(Error::Equivocation)));
    assert!(matches!(
        a.merge(&ManifestState::new(SpaceId([8; 16]))),
        Err(Error::WrongSpace)
    ));
}

#[test]
fn sealed_segments_round_trip_with_any_epoch_key() {
    let mut s = ManifestState::new(SPACE);
    s.record(D1, path("photos/2026/beach.jpg"), file(9))
        .unwrap();
    let e1 = SpaceKey::generate(SPACE, Epoch(1));
    let e2 = SpaceKey::generate(SPACE, Epoch(2));
    let sealed = s.seal(SegmentKind::Snapshot, &e2).unwrap();
    let (kind, opened) = ManifestState::open(&sealed, SPACE, [&e1, &e2]).unwrap();
    assert_eq!(kind, SegmentKind::Snapshot);
    assert_eq!(opened, s);
    assert!(ManifestState::open(&sealed, SPACE, [&e1]).is_err());
    assert!(matches!(
        ManifestState::open(&sealed, SpaceId([8; 16]), [&e2]),
        Err(Error::Decrypt(_))
    ));
}

#[test]
fn decoder_rejects_non_canonical_input() {
    let mut s = ManifestState::new(SPACE);
    s.record(D1, path("a"), file(1)).unwrap();
    s.record(D2, path("b"), file(2)).unwrap();
    let bytes = s.encode(SegmentKind::Log).unwrap();
    let (_, decoded) = ManifestState::decode(&bytes).unwrap();
    assert_eq!(decoded, s);

    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(ManifestState::decode(&trailing).is_err());
    assert!(ManifestState::decode(&bytes[..bytes.len() - 1]).is_err());
    let mut bad_version = bytes.clone();
    bad_version[4] = 2;
    assert!(ManifestState::decode(&bad_version).is_err());
    let mut huge_count = bytes.clone();
    let ops_len_at = 4 + 1 + 1 + 16 + 4 + 2 * 24;
    huge_count[ops_len_at..ops_len_at + 4].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(ManifestState::decode(&huge_count).is_err());
}
