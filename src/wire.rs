//! Byte-level encoding shared by the protocol and the on-disk state.
//!
//! Little-endian, length-prefixed, no self-description. Both ends are the same
//! program at the same protocol version — the handshake sees to that — so there
//! is nothing to negotiate field by field, and a format that cannot be
//! mis-parsed into something plausible is worth more here than one that can be
//! read by other tools.

use std::fmt;

/// Everything that can go wrong reading a frame or a state file.
#[derive(Debug, PartialEq)]
pub enum DecodeError {
    /// The buffer ended in the middle of a field.
    Truncated,
    /// A length prefix exceeded what the field is allowed to hold.
    TooLong { field: &'static str, len: usize },
    /// A tag or discriminant with no meaning at this protocol version.
    BadTag { field: &'static str, tag: u8 },
    /// A byte string that had to be UTF-8 and was not.
    BadUtf8,
    /// A path that is not usable as a relative path inside the sync root.
    BadPath(String),
    /// Trailing bytes after a complete message.
    Trailing(usize),
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecodeError::Truncated => write!(f, "truncated"),
            DecodeError::TooLong { field, len } => write!(f, "{field} too long ({len} bytes)"),
            DecodeError::BadTag { field, tag } => write!(f, "unknown {field} tag {tag:#04x}"),
            DecodeError::BadUtf8 => write!(f, "invalid utf-8"),
            DecodeError::BadPath(p) => write!(f, "unusable path {p:?}"),
            DecodeError::Trailing(n) => write!(f, "{n} trailing bytes"),
        }
    }
}

impl std::error::Error for DecodeError {}

/// Ceiling on any single length-prefixed string. Paths are the longest thing
/// here and no filesystem allows one this big; the cap exists so a corrupt
/// prefix cannot make us try to allocate gigabytes.
pub const MAX_STR: usize = 64 * 1024;

pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    pub fn new() -> Self {
        Writer { buf: Vec::new() }
    }

    pub fn with_capacity(n: usize) -> Self {
        Writer {
            buf: Vec::with_capacity(n),
        }
    }

    pub fn u8(&mut self, v: u8) -> &mut Self {
        self.buf.push(v);
        self
    }

    pub fn u16(&mut self, v: u16) -> &mut Self {
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }

    pub fn u32(&mut self, v: u32) -> &mut Self {
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }

    pub fn u64(&mut self, v: u64) -> &mut Self {
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }

    pub fn i64(&mut self, v: i64) -> &mut Self {
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }

    pub fn bool(&mut self, v: bool) -> &mut Self {
        self.u8(v as u8)
    }

    /// A `u32`-prefixed byte string.
    pub fn bytes(&mut self, v: &[u8]) -> &mut Self {
        self.u32(v.len() as u32);
        self.buf.extend_from_slice(v);
        self
    }

    pub fn str(&mut self, v: &str) -> &mut Self {
        self.bytes(v.as_bytes())
    }

    /// Raw bytes with no prefix, for fields whose length is already known.
    pub fn raw(&mut self, v: &[u8]) -> &mut Self {
        self.buf.extend_from_slice(v);
        self
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    pub fn finish(self) -> Vec<u8> {
        self.buf
    }
}

impl Default for Writer {
    fn default() -> Self {
        Writer::new()
    }
}

pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        if self.pos + n > self.buf.len() {
            return Err(DecodeError::Truncated);
        }
        let out = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }

    pub fn u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.take(1)?[0])
    }

    pub fn u16(&mut self) -> Result<u16, DecodeError> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }

    pub fn u32(&mut self) -> Result<u32, DecodeError> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }

    pub fn u64(&mut self) -> Result<u64, DecodeError> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }

    pub fn i64(&mut self) -> Result<i64, DecodeError> {
        Ok(i64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }

    pub fn bool(&mut self) -> Result<bool, DecodeError> {
        Ok(self.u8()? != 0)
    }

    pub fn bytes(&mut self, field: &'static str) -> Result<&'a [u8], DecodeError> {
        let len = self.u32()? as usize;
        if len > MAX_STR {
            return Err(DecodeError::TooLong { field, len });
        }
        self.take(len)
    }

    pub fn str(&mut self, field: &'static str) -> Result<&'a str, DecodeError> {
        std::str::from_utf8(self.bytes(field)?).map_err(|_| DecodeError::BadUtf8)
    }

    pub fn string(&mut self, field: &'static str) -> Result<String, DecodeError> {
        Ok(self.str(field)?.to_string())
    }

    pub fn raw(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        self.take(n)
    }

    /// Read a `u32` count, rejecting anything that could not possibly be backed
    /// by the bytes remaining. `min_item` is the smallest number of bytes one
    /// item can occupy, so a bogus count cannot cause a huge `reserve`.
    pub fn count(&mut self, field: &'static str, min_item: usize) -> Result<usize, DecodeError> {
        let n = self.u32()? as usize;
        if min_item > 0 && n.saturating_mul(min_item) > self.remaining() {
            return Err(DecodeError::TooLong { field, len: n });
        }
        Ok(n)
    }

    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    /// Assert the message was consumed exactly. Trailing bytes mean the two ends
    /// disagree about the format, which is worth an error rather than a shrug.
    pub fn finish(self) -> Result<(), DecodeError> {
        match self.remaining() {
            0 => Ok(()),
            n => Err(DecodeError::Trailing(n)),
        }
    }
}
