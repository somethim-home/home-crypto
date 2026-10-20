use crate::Error;

pub(crate) struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Self { rest: bytes }
    }

    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let (head, tail) = self
            .rest
            .split_at_checked(n)
            .ok_or(Error::Malformed("truncated"))?;
        self.rest = tail;
        Ok(head)
    }

    pub(crate) fn array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        self.take(N)?
            .try_into()
            .map_err(|_| Error::Malformed("truncated"))
    }

    pub(crate) fn u8(&mut self) -> Result<u8, Error> {
        self.array::<1>().map(|[b]| b)
    }

    pub(crate) fn u16(&mut self) -> Result<u16, Error> {
        self.array().map(u16::from_be_bytes)
    }

    pub(crate) fn u32(&mut self) -> Result<u32, Error> {
        self.array().map(u32::from_be_bytes)
    }

    pub(crate) fn u64(&mut self) -> Result<u64, Error> {
        self.array().map(u64::from_be_bytes)
    }

    pub(crate) fn i64(&mut self) -> Result<i64, Error> {
        self.array().map(i64::from_be_bytes)
    }

    /// Rejects counts that cannot fit in the remaining input before anything is allocated.
    pub(crate) fn count(&mut self, n: usize, min_item_len: usize) -> Result<usize, Error> {
        match n.checked_mul(min_item_len) {
            Some(needed) if needed <= self.rest.len() => Ok(n),
            _ => Err(Error::Malformed("count exceeds input")),
        }
    }

    pub(crate) fn finish(self) -> Result<(), Error> {
        if self.rest.is_empty() {
            Ok(())
        } else {
            Err(Error::Malformed("trailing bytes"))
        }
    }
}
