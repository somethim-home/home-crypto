use std::io::Read;

use crate::Error;

pub(crate) fn encrypt(recipient: &dyn age::Recipient, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
    let encryptor = age::Encryptor::with_recipients(std::iter::once(recipient))?;
    let mut out = Vec::with_capacity(plaintext.len().saturating_add(256));
    let mut writer = encryptor.wrap_output(&mut out)?;
    std::io::Write::write_all(&mut writer, plaintext)?;
    writer.finish()?;
    Ok(out)
}

pub(crate) fn decrypt<'a>(
    identities: impl Iterator<Item = &'a dyn age::Identity>,
    ciphertext: &[u8],
    limit: usize,
) -> Result<Vec<u8>, Error> {
    let decryptor = age::Decryptor::new_buffered(ciphertext)?;
    let reader = decryptor.decrypt(identities)?;
    let cap = u64::try_from(limit)
        .map_err(|_| Error::Overflow)?
        .saturating_add(1);
    let mut out = Vec::new();
    reader.take(cap).read_to_end(&mut out)?;
    if out.len() > limit {
        return Err(Error::TooLarge);
    }
    Ok(out)
}
