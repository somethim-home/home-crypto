//! Random 16-byte identifiers, written as 32 lowercase hex characters.

use std::fmt;

use crate::Error;

pub(crate) fn random_bytes<const N: usize>() -> Result<[u8; N], Error> {
    let mut bytes = [0u8; N];
    getrandom::getrandom(&mut bytes).map_err(|_| Error::Random)?;
    Ok(bytes)
}

pub(crate) fn to_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        for nibble in [byte >> 4, byte & 0x0f] {
            out.push(char::from(
                DIGITS.get(usize::from(nibble)).copied().unwrap_or(b'0'),
            ));
        }
    }
    out
}

pub(crate) fn from_hex<const N: usize>(text: &str) -> Result<[u8; N], Error> {
    fn nibble(c: u8) -> Result<u8, Error> {
        match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(c - b'a' + 10),
            _ => Err(Error::Malformed("hex digit")),
        }
    }
    if text.len() != N * 2 {
        return Err(Error::Malformed("hex length"));
    }
    let mut out = [0u8; N];
    for (slot, pair) in out.iter_mut().zip(text.as_bytes().chunks_exact(2)) {
        if let [hi, lo] = pair {
            *slot = (nibble(*hi)? << 4) | nibble(*lo)?;
        }
    }
    Ok(out)
}

macro_rules! id_type {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(pub [u8; 16]);

        impl $name {
            pub fn random() -> Result<Self, Error> {
                random_bytes().map(Self)
            }

            pub fn from_hex(text: &str) -> Result<Self, Error> {
                from_hex(text).map(Self)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&to_hex(&self.0))
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", stringify!($name), to_hex(&self.0))
            }
        }
    };
}

id_type!(UserId);
id_type!(SpaceId);
id_type!(
    /// A file object; random, never derived from content.
    ObjectId
);
id_type!(
    /// One installation of a client, the author of manifest operations.
    DeviceId
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trip_and_strictness() {
        let id = SpaceId([0xab; 16]);
        assert_eq!(SpaceId::from_hex(&id.to_string()).unwrap(), id);
        assert!(SpaceId::from_hex(&"AB".repeat(16)).is_err());
        assert!(SpaceId::from_hex("ab").is_err());
    }
}
