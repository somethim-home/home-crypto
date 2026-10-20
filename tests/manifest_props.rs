use home_crypto::ids::{DeviceId, ObjectId, SpaceId};
use home_crypto::manifest::{Change, FileEntry, ManifestPath, ManifestState, SegmentKind};
use proptest::prelude::*;

const SPACE: SpaceId = SpaceId([7; 16]);
const DEVICES: usize = 3;
const PATHS: [&str; 3] = ["a", "a/b", "c.txt"];

#[derive(Clone, Debug)]
enum Action {
    Write {
        device: usize,
        path: usize,
        change: u8,
        n: u8,
    },
    Sync {
        from: usize,
        to: usize,
    },
    Compact {
        device: usize,
    },
    Deliver {
        to: usize,
        log: prop::sample::Index,
    },
}

fn action() -> impl Strategy<Value = Action> {
    prop_oneof![
        4 => (0..DEVICES, 0..PATHS.len(), 0u8..3, any::<u8>())
            .prop_map(|(device, path, change, n)| Action::Write { device, path, change, n }),
        3 => (0..DEVICES, 0..DEVICES).prop_map(|(from, to)| Action::Sync { from, to }),
        1 => (0..DEVICES).prop_map(|device| Action::Compact { device }),
        2 => (0..DEVICES, any::<prop::sample::Index>()).prop_map(|(to, log)| Action::Deliver { to, log }),
    ]
}

fn change(kind: u8, n: u8) -> Change {
    match kind {
        0 => Change::Delete,
        1 => Change::Dir {
            mtime: i64::from(n),
        },
        _ => Change::File(FileEntry {
            mtime: i64::from(n),
            size: u64::from(n),
            object_id: ObjectId([n; 16]),
            content_sha256: [n; 32],
        }),
    }
}

/// Device states after the history, plus every op as its own log segment; `Deliver` merges a
/// single earlier segment out of causal order.
fn simulate(actions: &[Action]) -> (Vec<ManifestState>, Vec<ManifestState>) {
    let mut states = vec![ManifestState::new(SPACE); DEVICES];
    let mut logs = Vec::new();
    for action in actions {
        match action.clone() {
            Action::Write {
                device,
                path,
                change: kind,
                n,
            } => {
                let op = states[device]
                    .record(
                        DeviceId([device as u8 + 1; 16]),
                        ManifestPath::new(PATHS[path]).unwrap(),
                        change(kind, n),
                    )
                    .unwrap();
                logs.push(ManifestState::log_segment(SPACE, [op]).unwrap());
            }
            Action::Sync { from, to } => {
                let source = states[from].clone();
                states[to].merge(&source).unwrap();
            }
            Action::Compact { device } => states[device].compact(),
            Action::Deliver { to, log } => {
                if !logs.is_empty() {
                    let segment: &ManifestState = &logs[log.index(logs.len())];
                    states[to].merge(segment).unwrap();
                }
            }
        }
    }
    (states, logs)
}

fn merged(a: &ManifestState, b: &ManifestState) -> ManifestState {
    let mut out = a.clone();
    out.merge(b).unwrap();
    out
}

fn compacted(s: &ManifestState) -> ManifestState {
    let mut out = s.clone();
    out.compact();
    out
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn merge_is_commutative_associative_idempotent(actions in prop::collection::vec(action(), 0..60)) {
        let (s, _) = simulate(&actions);
        for a in &s {
            prop_assert_eq!(&merged(a, a), a);
            for b in &s {
                prop_assert_eq!(merged(a, b), merged(b, a));
            }
        }
        prop_assert_eq!(merged(&merged(&s[0], &s[1]), &s[2]), merged(&s[0], &merged(&s[1], &s[2])));
    }

    #[test]
    fn compaction_preserves_every_later_view(actions in prop::collection::vec(action(), 0..60)) {
        let (s, logs) = simulate(&actions);
        for a in &s {
            prop_assert_eq!(compacted(a).view(), a.view());
            for b in &s {
                prop_assert_eq!(merged(&compacted(a), b).view(), merged(a, b).view());
            }
            let mut full = a.clone();
            let mut small = compacted(a);
            for log in &logs {
                full.merge(log).unwrap();
                small.merge(log).unwrap();
            }
            prop_assert_eq!(small.view(), full.view());
        }
    }

    #[test]
    fn all_devices_converge(actions in prop::collection::vec(action(), 0..60)) {
        let (s, logs) = simulate(&actions);
        let forward = merged(&merged(&s[0], &s[1]), &s[2]);
        let backward = merged(&merged(&s[2], &s[1]), &s[0]);
        prop_assert_eq!(forward.view(), backward.view());
        let mut from_logs = ManifestState::new(SPACE);
        for log in logs.iter().rev() {
            from_logs.merge(log).unwrap();
        }
        prop_assert_eq!(from_logs.view(), forward.view());
    }

    #[test]
    fn encoding_round_trips(actions in prop::collection::vec(action(), 0..60)) {
        let (s, _) = simulate(&actions);
        for state in &s {
            let bytes = state.encode(SegmentKind::Snapshot).unwrap();
            let (kind, decoded) = ManifestState::decode(&bytes).unwrap();
            prop_assert_eq!(kind, SegmentKind::Snapshot);
            prop_assert_eq!(&decoded, state);
        }
    }

    #[test]
    fn accepted_mutations_reencode_identically(
        actions in prop::collection::vec(action(), 1..30),
        flips in prop::collection::vec((any::<prop::sample::Index>(), any::<u8>()), 0..4),
        cut in any::<prop::sample::Index>(),
        truncate in any::<bool>(),
    ) {
        let (s, _) = simulate(&actions);
        let mut bytes = s[0].encode(SegmentKind::Log).unwrap();
        for (at, value) in flips {
            let i = at.index(bytes.len());
            bytes[i] = value;
        }
        if truncate {
            bytes.truncate(cut.index(bytes.len() + 1));
        }
        if let Ok((kind, state)) = ManifestState::decode(&bytes) {
            prop_assert_eq!(state.encode(kind).unwrap(), bytes);
        }
    }

    #[test]
    fn arbitrary_bytes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..512)) {
        if let Ok((kind, state)) = ManifestState::decode(&bytes) {
            prop_assert_eq!(state.encode(kind).unwrap(), bytes);
        }
    }
}
