//! Canonical line-based text records (format §1.1).

use crate::Error;

pub(crate) const MAX_RECORD_BYTES: usize = 1 << 20;
const PREFIX: &str = "home-crypto/v1/";

fn valid_value(value: &str) -> bool {
    !value.is_empty() && !value.chars().any(|c| c.is_control())
}

pub(crate) struct Writer {
    out: String,
}

impl Writer {
    pub(crate) fn new(kind: &str) -> Self {
        Self {
            out: format!("{PREFIX}{kind}\n"),
        }
    }

    pub(crate) fn field(&mut self, key: &str, value: &str) -> Result<(), Error> {
        if !valid_value(value) {
            return Err(Error::Malformed("record value"));
        }
        self.out.push_str(key);
        self.out.push_str(": ");
        self.out.push_str(value);
        self.out.push('\n');
        Ok(())
    }

    pub(crate) fn finish(self) -> Result<Vec<u8>, Error> {
        if self.out.len() > MAX_RECORD_BYTES {
            return Err(Error::TooLarge);
        }
        Ok(self.out.into_bytes())
    }
}

pub(crate) struct Reader<'a> {
    lines: std::iter::Peekable<std::str::Split<'a, char>>,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(bytes: &'a [u8], kind: &str) -> Result<Self, Error> {
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(Error::TooLarge);
        }
        let text = std::str::from_utf8(bytes).map_err(|_| Error::Malformed("record utf-8"))?;
        let body = text
            .strip_suffix('\n')
            .ok_or(Error::Malformed("record must end with a newline"))?;
        let mut lines = body.split('\n').peekable();
        let header = lines.next().ok_or(Error::Malformed("record type"))?;
        if header.strip_prefix(PREFIX) != Some(kind) {
            return Err(Error::Malformed("record type"));
        }
        Ok(Self { lines })
    }

    fn split(line: &str) -> Option<(&str, &str)> {
        line.split_once(": ")
    }

    pub(crate) fn field(&mut self, key: &str) -> Result<&'a str, Error> {
        let line = self.lines.next().ok_or(Error::Malformed("missing field"))?;
        match Self::split(line) {
            Some((k, v)) if k == key && valid_value(v) => Ok(v),
            _ => Err(Error::Malformed("unexpected field")),
        }
    }

    pub(crate) fn repeated(&mut self, key: &str) -> Result<Vec<&'a str>, Error> {
        let mut values = Vec::new();
        while let Some(line) = self.lines.peek() {
            match Self::split(line) {
                Some((k, _)) if k == key => {}
                _ => break,
            }
            values.push(self.field(key)?);
        }
        Ok(values)
    }

    pub(crate) fn finish(mut self) -> Result<(), Error> {
        match self.lines.next() {
            None => Ok(()),
            Some(_) => Err(Error::Malformed("unexpected trailing field")),
        }
    }
}

/// Requires strictly increasing keys, which gives both sorting and uniqueness.
pub(crate) fn strictly_sorted<T, K: Ord>(items: &[T], key: impl Fn(&T) -> K) -> bool {
    items.windows(2).all(|w| match w {
        [a, b] => key(a) < key(b),
        _ => true,
    })
}

pub(crate) fn parse_u64(text: &str) -> Result<u64, Error> {
    let canonical =
        text == "0" || (!text.starts_with('0') && text.bytes().all(|b| b.is_ascii_digit()));
    if !canonical {
        return Err(Error::Malformed("decimal number"));
    }
    text.parse().map_err(|_| Error::Malformed("decimal number"))
}

pub(crate) fn parse_identity(text: &str) -> Result<age::x25519::Identity, Error> {
    use age::secrecy::ExposeSecret;
    let identity: age::x25519::Identity =
        text.parse().map_err(|_| Error::Malformed("age identity"))?;
    if identity.to_string().expose_secret() != text {
        return Err(Error::Malformed("age identity not canonical"));
    }
    Ok(identity)
}

pub(crate) fn parse_recipient(text: &str) -> Result<age::x25519::Recipient, Error> {
    let recipient: age::x25519::Recipient = text
        .parse()
        .map_err(|_| Error::Malformed("age recipient"))?;
    if recipient.to_string() != text {
        return Err(Error::Malformed("age recipient not canonical"));
    }
    Ok(recipient)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_canonical_records() {
        let ok = b"home-crypto/v1/t\na: 1\nb: x\nb: y\n";
        let mut r = Reader::new(ok, "t").unwrap();
        assert_eq!(r.field("a").unwrap(), "1");
        assert_eq!(r.repeated("b").unwrap(), ["x", "y"]);
        r.finish().unwrap();

        for bad in [
            &b"home-crypto/v1/t\na: 1"[..],
            b"home-crypto/v1/t\na: 1\n\n",
            b"home-crypto/v1/t\na: 1\r\n",
            b"home-crypto/v1/u\na: 1\n",
            b"home-crypto/v1/t\na:  1\n\x01",
        ] {
            let parsed = Reader::new(bad, "t").and_then(|mut r| {
                r.field("a")?;
                r.finish()
            });
            assert!(parsed.is_err(), "{bad:?}");
        }
        assert!(parse_u64("01").is_err());
        assert!(parse_u64("+1").is_err());
        assert_eq!(parse_u64("0").unwrap(), 0);
    }
}
