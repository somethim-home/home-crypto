//! External share links (format §4): the space identity travels in the URL fragment.

use age::secrecy::{ExposeSecret, SecretString};

use crate::Error;
use crate::ids::SpaceId;
use crate::record;
use crate::space::{Epoch, SpaceKey};

const FRAGMENT_PREFIX: &str = "v1:";

/// Builds `<base>/s/<space-id>#v1:<identity>`; the fragment never reaches the server.
pub fn to_url(base: &str, key: &SpaceKey) -> SecretString {
    SecretString::from(format!(
        "{}/s/{}#{FRAGMENT_PREFIX}{}",
        base.trim_end_matches('/'),
        key.space_id(),
        key.identity_string().expose_secret()
    ))
}

pub fn parse(url: &str) -> Result<SpaceKey, Error> {
    let (location, fragment) = url
        .split_once('#')
        .ok_or(Error::Malformed("share link without fragment"))?;
    let identity = fragment
        .strip_prefix(FRAGMENT_PREFIX)
        .ok_or(Error::Malformed("share link version"))?;
    let space = location
        .rsplit_once("/s/")
        .map(|(_, id)| id)
        .ok_or(Error::Malformed("share link path"))?;
    Ok(SpaceKey::from_identity(
        SpaceId::from_hex(space)?,
        Epoch::FIRST,
        record::parse_identity(identity)?,
    ))
}
