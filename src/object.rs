//! File objects (format §6): an age file to the space recipient whose plaintext starts with the object id.

use std::io::{self, Read, Seek, SeekFrom, Write};

use sha2::{Digest, Sha256};

use crate::Error;
use crate::ids::ObjectId;
use crate::space::SpaceKey;

const MAGIC: &[u8; 4] = b"HCOB";
const VERSION: u8 = 1;
pub const PREFIX_LEN: u64 = 21;

fn prefix(object_id: ObjectId) -> [u8; PREFIX_LEN as usize] {
    let mut out = [0u8; PREFIX_LEN as usize];
    let (head, id) = out.split_at_mut(5);
    head.copy_from_slice(&[MAGIC[0], MAGIC[1], MAGIC[2], MAGIC[3], VERSION]);
    id.copy_from_slice(&object_id.0);
    out
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ContentInfo {
    pub size: u64,
    pub sha256: [u8; 32],
}

/// Encrypts `content` to the space recipient, returning the writer and the content's size and hash.
pub fn encrypt<R: Read, W: Write>(
    key: &SpaceKey,
    object_id: ObjectId,
    mut content: R,
    output: W,
) -> Result<(W, ContentInfo), Error> {
    let recipient = key.recipient();
    let encryptor =
        age::Encryptor::with_recipients(std::iter::once(&recipient as &dyn age::Recipient))?;
    let mut writer = encryptor.wrap_output(output)?;
    writer.write_all(&prefix(object_id))?;
    let mut hasher = Sha256::new();
    let mut size: u64 = 0;
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = match content.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        };
        let chunk = buf.get(..n).ok_or(Error::Overflow)?;
        hasher.update(chunk);
        writer.write_all(chunk)?;
        size = size.checked_add(n as u64).ok_or(Error::Overflow)?;
    }
    let output = writer.finish()?;
    Ok((
        output,
        ContentInfo {
            size,
            sha256: hasher.finalize().into(),
        },
    ))
}

/// Decrypts an object's content; seekable when the input is, with positions relative to the content.
pub struct ObjectReader<R> {
    inner: age::stream::StreamReader<R>,
}

impl<R: Read> ObjectReader<R> {
    /// `keys` are all epochs of the space held in the keyring.
    pub fn open<'a>(
        keys: impl IntoIterator<Item = &'a SpaceKey>,
        object_id: ObjectId,
        input: R,
    ) -> Result<Self, Error> {
        let decryptor = age::Decryptor::new(input)?;
        let identities: Vec<&dyn age::Identity> = keys
            .into_iter()
            .map(|k| k.identity() as &dyn age::Identity)
            .collect();
        let mut inner = decryptor.decrypt(identities.into_iter())?;
        let mut found = [0u8; PREFIX_LEN as usize];
        inner.read_exact(&mut found).map_err(|e| match e.kind() {
            io::ErrorKind::UnexpectedEof => Error::Malformed("object prefix"),
            _ => Error::Io(e),
        })?;
        if found.get(..5) != prefix(object_id).get(..5) {
            return Err(Error::Malformed("object prefix"));
        }
        if found != prefix(object_id) {
            return Err(Error::WrongObject);
        }
        Ok(Self { inner })
    }

    /// Reads the rest of the content and checks it against the manifest entry.
    pub fn verify_to_end<W: Write>(
        mut self,
        mut out: W,
        expected: &ContentInfo,
    ) -> Result<W, Error> {
        let mut hasher = Sha256::new();
        let mut size: u64 = 0;
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let n = match self.inner.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e.into()),
            };
            let chunk = buf.get(..n).ok_or(Error::Overflow)?;
            hasher.update(chunk);
            out.write_all(chunk)?;
            size = size.checked_add(n as u64).ok_or(Error::Overflow)?;
        }
        let actual = ContentInfo {
            size,
            sha256: hasher.finalize().into(),
        };
        if actual != *expected {
            return Err(Error::Malformed(
                "content does not match the manifest entry",
            ));
        }
        Ok(out)
    }
}

impl<R: Read> Read for ObjectReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

impl<R: Read + Seek> Seek for ObjectReader<R> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let target = match pos {
            SeekFrom::Start(n) => SeekFrom::Start(n.checked_add(PREFIX_LEN).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "seek position overflows")
            })?),
            other => other,
        };
        let before = self.inner.stream_position()?;
        let absolute = self.inner.seek(target)?;
        if absolute < PREFIX_LEN {
            self.inner.seek(SeekFrom::Start(before))?;
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek before the start of the content",
            ));
        }
        Ok(absolute - PREFIX_LEN)
    }
}

/// Re-encrypts an object to a new epoch, keeping its id (format §6.3: the age crate cannot re-wrap headers).
pub fn reencrypt<'a, R: Read, W: Write>(
    old_keys: impl IntoIterator<Item = &'a SpaceKey>,
    new_key: &SpaceKey,
    object_id: ObjectId,
    input: R,
    output: W,
) -> Result<(W, ContentInfo), Error> {
    let reader = ObjectReader::open(old_keys, object_id, input)?;
    encrypt(new_key, object_id, reader, output)
}
