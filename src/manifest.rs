//! The per-space encrypted manifest (format §7): an operation set with deterministic merge.

use std::collections::{BTreeMap, BTreeSet};

use crate::binary::Reader;
use crate::ids::{DeviceId, ObjectId, SpaceId};
use crate::space::SpaceKey;
use crate::{Error, agefile};

pub const MAX_SEGMENT_BYTES: usize = 64 << 20;
const MAGIC: &[u8; 4] = b"HCMF";
const VERSION: u8 = 1;
const MAX_PATH: usize = 4096;
const MAX_PATH_SEGMENT: usize = 255;
const OP_ID_LEN: usize = 24;
const MIN_OP_LEN: usize = OP_ID_LEN + 8 + 2 + 2 + 1 + 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OpId {
    pub device: DeviceId,
    pub seq: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileEntry {
    pub mtime: i64,
    pub size: u64,
    pub object_id: ObjectId,
    pub content_sha256: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Change {
    Delete,
    Dir { mtime: i64 },
    File(FileEntry),
}

/// A validated relative path; compared bytewise, so clients normalise to NFC before creating one.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ManifestPath(String);

impl ManifestPath {
    pub fn new(path: impl Into<String>) -> Result<Self, Error> {
        let path = path.into();
        let valid = !path.is_empty()
            && path.len() <= MAX_PATH
            && path.split('/').all(|segment| {
                !segment.is_empty()
                    && segment.len() <= MAX_PATH_SEGMENT
                    && segment != "."
                    && segment != ".."
                    && !segment.contains('\0')
            });
        if valid {
            Ok(Self(path))
        } else {
            Err(Error::Malformed("path"))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn name(&self) -> &str {
        self.0.rsplit('/').next().unwrap_or(&self.0)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Op {
    pub id: OpId,
    pub lamport: u64,
    /// Heads on the same path the writer saw; sorted, unique.
    pub replaces: Vec<OpId>,
    pub path: ManifestPath,
    pub change: Change,
}

impl Op {
    fn validate(&self) -> Result<(), Error> {
        if self.id.seq == 0 || self.lamport == 0 {
            return Err(Error::Malformed("seq and lamport start at 1"));
        }
        if !crate::record::strictly_sorted(&self.replaces, |id| *id) {
            return Err(Error::Malformed("replaces must be sorted and unique"));
        }
        if self.replaces.contains(&self.id) || self.replaces.iter().any(|r| r.seq == 0) {
            return Err(Error::Malformed("invalid replaces entry"));
        }
        Ok(())
    }

    fn order_key(&self) -> (u64, OpId) {
        (self.lamport, self.id)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SegmentKind {
    Log,
    Snapshot,
}

/// A present path in the view; `change` is never `Delete`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub op: OpId,
    pub change: Change,
}

/// A losing concurrent file write, shown as a conflict copy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Conflict {
    pub path: ManifestPath,
    pub op: OpId,
    pub file: FileEntry,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct View {
    pub entries: BTreeMap<ManifestPath, Entry>,
    pub conflicts: Vec<Conflict>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManifestState {
    space_id: SpaceId,
    frontier: BTreeMap<DeviceId, u64>,
    ops: BTreeMap<OpId, Op>,
}

impl ManifestState {
    pub fn new(space_id: SpaceId) -> Self {
        Self {
            space_id,
            frontier: BTreeMap::new(),
            ops: BTreeMap::new(),
        }
    }

    /// A log segment holding exactly `ops`, to be merged by other devices.
    pub fn log_segment(
        space_id: SpaceId,
        ops: impl IntoIterator<Item = Op>,
    ) -> Result<Self, Error> {
        let mut state = Self::new(space_id);
        for op in ops {
            op.validate()?;
            if state.ops.insert(op.id, op).is_some() {
                return Err(Error::Malformed("duplicate operation"));
            }
        }
        Ok(state)
    }

    pub fn space_id(&self) -> SpaceId {
        self.space_id
    }

    pub fn frontier(&self) -> &BTreeMap<DeviceId, u64> {
        &self.frontier
    }

    pub fn ops(&self) -> impl Iterator<Item = &Op> {
        self.ops.values()
    }

    fn covered(&self, id: &OpId) -> bool {
        id.seq <= self.frontier.get(&id.device).copied().unwrap_or(0)
    }

    fn pruned(&self, id: &OpId) -> bool {
        self.covered(id) && !self.ops.contains_key(id)
    }

    fn extend_frontier(&mut self) {
        let devices: BTreeSet<DeviceId> = self.ops.keys().map(|id| id.device).collect();
        for device in devices {
            let mut seq = self.frontier.get(&device).copied().unwrap_or(0);
            while let Some(next) = seq.checked_add(1) {
                if !self.ops.contains_key(&OpId { device, seq: next }) {
                    break;
                }
                seq = next;
            }
            if seq > 0 {
                self.frontier.insert(device, seq);
            }
        }
    }

    pub fn merge(&mut self, other: &ManifestState) -> Result<(), Error> {
        if other.space_id != self.space_id {
            return Err(Error::WrongSpace);
        }
        for (id, op) in &other.ops {
            if self.ops.get(id).is_some_and(|mine| mine != op) {
                return Err(Error::Equivocation);
            }
        }
        let mut ops: BTreeMap<OpId, Op> = BTreeMap::new();
        for (id, op) in &self.ops {
            if !other.pruned(id) {
                ops.insert(*id, op.clone());
            }
        }
        for (id, op) in &other.ops {
            if !self.pruned(id) {
                ops.entry(*id).or_insert_with(|| op.clone());
            }
        }
        for (device, seq) in &other.frontier {
            let slot = self.frontier.entry(*device).or_insert(0);
            *slot = (*slot).max(*seq);
        }
        self.ops = ops;
        self.extend_frontier();
        Ok(())
    }

    fn superseded(&self) -> BTreeSet<OpId> {
        let mut out = BTreeSet::new();
        for op in self.ops.values() {
            for r in &op.replaces {
                if self.ops.get(r).is_some_and(|target| target.path == op.path) {
                    out.insert(*r);
                }
            }
        }
        out
    }

    fn heads(&self) -> BTreeMap<&ManifestPath, Vec<&Op>> {
        let superseded = self.superseded();
        let mut heads: BTreeMap<&ManifestPath, Vec<&Op>> = BTreeMap::new();
        for op in self.ops.values() {
            if !superseded.contains(&op.id) {
                heads.entry(&op.path).or_default().push(op);
            }
        }
        heads
    }

    pub fn view(&self) -> View {
        let mut view = View::default();
        for (path, mut heads) in self.heads() {
            heads.sort_by_key(|op| op.order_key());
            let Some(winner) = heads.pop() else { continue };
            if winner.change != Change::Delete {
                view.entries.insert(
                    path.clone(),
                    Entry {
                        op: winner.id,
                        change: winner.change.clone(),
                    },
                );
            }
            for loser in heads {
                if let Change::File(file) = &loser.change {
                    view.conflicts.push(Conflict {
                        path: path.clone(),
                        op: loser.id,
                        file: file.clone(),
                    });
                }
            }
        }
        view
    }

    /// Appends a change by `device` on top of the current view and returns the new op for a log segment.
    pub fn record(
        &mut self,
        device: DeviceId,
        path: ManifestPath,
        change: Change,
    ) -> Result<Op, Error> {
        let last_seq = self
            .ops
            .range(
                OpId { device, seq: 0 }..=OpId {
                    device,
                    seq: u64::MAX,
                },
            )
            .next_back()
            .map(|(id, _)| id.seq)
            .unwrap_or(0)
            .max(self.frontier.get(&device).copied().unwrap_or(0));
        let max_lamport = self.ops.values().map(|op| op.lamport).max().unwrap_or(0);
        let mut replaces: Vec<OpId> = self
            .heads()
            .get(&path)
            .map(|ops| ops.iter().map(|op| op.id).collect())
            .unwrap_or_default();
        replaces.sort();
        let op = Op {
            id: OpId {
                device,
                seq: last_seq.checked_add(1).ok_or(Error::Overflow)?,
            },
            lamport: max_lamport.checked_add(1).ok_or(Error::Overflow)?,
            replaces,
            path,
            change,
        };
        op.validate()?;
        self.ops.insert(op.id, op.clone());
        self.extend_frontier();
        Ok(op)
    }

    /// Drops ops that can never be heads again; the view of any later merge is unchanged.
    pub fn compact(&mut self) {
        let mut removable: BTreeSet<OpId> = self
            .superseded()
            .into_iter()
            .filter(|id| self.covered(id))
            .collect();
        loop {
            let blocked: Vec<OpId> = removable
                .iter()
                .filter(|id| {
                    self.ops.get(id).is_some_and(|op| {
                        op.replaces
                            .iter()
                            .any(|r| !removable.contains(r) && !self.pruned(r))
                    })
                })
                .copied()
                .collect();
            if blocked.is_empty() {
                break;
            }
            for id in blocked {
                removable.remove(&id);
            }
        }
        self.ops.retain(|id, _| !removable.contains(id));
    }

    pub fn encode(&self, kind: SegmentKind) -> Result<Vec<u8>, Error> {
        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        out.push(VERSION);
        out.push(match kind {
            SegmentKind::Log => 1,
            SegmentKind::Snapshot => 2,
        });
        out.extend_from_slice(&self.space_id.0);
        let frontier_len = u32::try_from(self.frontier.len()).map_err(|_| Error::TooLarge)?;
        out.extend_from_slice(&frontier_len.to_be_bytes());
        for (device, seq) in &self.frontier {
            if *seq == 0 {
                return Err(Error::Malformed("frontier seq starts at 1"));
            }
            out.extend_from_slice(&device.0);
            out.extend_from_slice(&seq.to_be_bytes());
        }
        let ops_len = u32::try_from(self.ops.len()).map_err(|_| Error::TooLarge)?;
        out.extend_from_slice(&ops_len.to_be_bytes());
        for op in self.ops.values() {
            op.validate()?;
            encode_op_id(&mut out, &op.id);
            out.extend_from_slice(&op.lamport.to_be_bytes());
            let replaces_len = u16::try_from(op.replaces.len()).map_err(|_| Error::TooLarge)?;
            out.extend_from_slice(&replaces_len.to_be_bytes());
            for r in &op.replaces {
                encode_op_id(&mut out, r);
            }
            let path = op.path.as_str().as_bytes();
            let path_len = u16::try_from(path.len()).map_err(|_| Error::TooLarge)?;
            out.extend_from_slice(&path_len.to_be_bytes());
            out.extend_from_slice(path);
            match &op.change {
                Change::Delete => out.push(0),
                Change::Dir { mtime } => {
                    out.push(1);
                    out.extend_from_slice(&mtime.to_be_bytes());
                }
                Change::File(file) => {
                    out.push(2);
                    out.extend_from_slice(&file.mtime.to_be_bytes());
                    out.extend_from_slice(&file.size.to_be_bytes());
                    out.extend_from_slice(&file.object_id.0);
                    out.extend_from_slice(&file.content_sha256);
                }
            }
        }
        if out.len() > MAX_SEGMENT_BYTES {
            return Err(Error::TooLarge);
        }
        Ok(out)
    }

    /// Strict, canonical parser: every accepted input re-encodes to the same bytes.
    pub fn decode(bytes: &[u8]) -> Result<(SegmentKind, Self), Error> {
        if bytes.len() > MAX_SEGMENT_BYTES {
            return Err(Error::TooLarge);
        }
        let mut r = Reader::new(bytes);
        if r.take(4)? != MAGIC || r.u8()? != VERSION {
            return Err(Error::Malformed("manifest magic or version"));
        }
        let kind = match r.u8()? {
            1 => SegmentKind::Log,
            2 => SegmentKind::Snapshot,
            _ => return Err(Error::Malformed("segment kind")),
        };
        let mut state = Self::new(SpaceId(r.array()?));

        let frontier_len = usize::try_from(r.u32()?).map_err(|_| Error::TooLarge)?;
        for _ in 0..r.count(frontier_len, OP_ID_LEN)? {
            let device = DeviceId(r.array()?);
            let seq = r.u64()?;
            if seq == 0 {
                return Err(Error::Malformed("frontier seq starts at 1"));
            }
            if state
                .frontier
                .last_key_value()
                .is_some_and(|(d, _)| *d >= device)
            {
                return Err(Error::Malformed("frontier must be sorted and unique"));
            }
            state.frontier.insert(device, seq);
        }

        let ops_len = usize::try_from(r.u32()?).map_err(|_| Error::TooLarge)?;
        for _ in 0..r.count(ops_len, MIN_OP_LEN)? {
            let id = decode_op_id(&mut r)?;
            let lamport = r.u64()?;
            let replaces_len = usize::from(r.u16()?);
            let replaces = (0..r.count(replaces_len, OP_ID_LEN)?)
                .map(|_| decode_op_id(&mut r))
                .collect::<Result<Vec<_>, _>>()?;
            let path_len = usize::from(r.u16()?);
            let path = std::str::from_utf8(r.take(path_len)?)
                .map_err(|_| Error::Malformed("path utf-8"))?;
            let path = ManifestPath::new(path)?;
            let change = match r.u8()? {
                0 => Change::Delete,
                1 => Change::Dir { mtime: r.i64()? },
                2 => Change::File(FileEntry {
                    mtime: r.i64()?,
                    size: r.u64()?,
                    object_id: ObjectId(r.array()?),
                    content_sha256: r.array()?,
                }),
                _ => return Err(Error::Malformed("change tag")),
            };
            let op = Op {
                id,
                lamport,
                replaces,
                path,
                change,
            };
            op.validate()?;
            if state
                .ops
                .last_key_value()
                .is_some_and(|(last, _)| *last >= id)
            {
                return Err(Error::Malformed("ops must be sorted and unique"));
            }
            state.ops.insert(id, op);
        }
        r.finish()?;
        Ok((kind, state))
    }

    pub fn seal(&self, kind: SegmentKind, key: &SpaceKey) -> Result<Vec<u8>, Error> {
        if key.space_id() != self.space_id {
            return Err(Error::WrongSpace);
        }
        key.seal(&self.encode(kind)?)
    }

    /// `keys` are all epochs of the space held in the keyring.
    pub fn open<'a>(
        sealed: &[u8],
        space_id: SpaceId,
        keys: impl IntoIterator<Item = &'a SpaceKey>,
    ) -> Result<(SegmentKind, Self), Error> {
        let identities: Vec<&dyn age::Identity> = keys
            .into_iter()
            .filter(|k| k.space_id() == space_id)
            .map(|k| k.identity() as &dyn age::Identity)
            .collect();
        let plaintext = agefile::decrypt(identities.into_iter(), sealed, MAX_SEGMENT_BYTES)?;
        let (kind, state) = Self::decode(&plaintext)?;
        if state.space_id != space_id {
            return Err(Error::WrongSpace);
        }
        Ok((kind, state))
    }
}

fn encode_op_id(out: &mut Vec<u8>, id: &OpId) {
    out.extend_from_slice(&id.device.0);
    out.extend_from_slice(&id.seq.to_be_bytes());
}

fn decode_op_id(r: &mut Reader<'_>) -> Result<OpId, Error> {
    Ok(OpId {
        device: DeviceId(r.array()?),
        seq: r.u64()?,
    })
}
