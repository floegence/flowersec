use std::{convert::TryInto, fmt};

use bytes::{Buf, BufMut};
use thiserror::Error;

use crate::quic_proto::coding::{self, Codec, UnexpectedEnd};

#[cfg(any())]
use arbitrary::Arbitrary;

/// An integer less than 2^62
///
/// Values of this type are suitable for encoding as QUIC variable-length integer.
// It would be neat if we could express to Rust that the top two bits are available for use as enum
// discriminants
#[derive(Default, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub(crate) struct VarInt(pub(crate) u64);

impl VarInt {
    /// The largest representable value
    pub(crate) const MAX: Self = Self((1 << 62) - 1);
    /// The largest encoded value length
    pub(crate) const MAX_SIZE: usize = 8;

    /// Construct a `VarInt` infallibly
    pub(crate) const fn from_u32(x: u32) -> Self {
        Self(x as u64)
    }

    /// Succeeds iff `x` < 2^62
    pub(crate) fn from_u64(x: u64) -> Result<Self, VarIntBoundsExceeded> {
        if x < 2u64.pow(62) {
            Ok(Self(x))
        } else {
            Err(VarIntBoundsExceeded)
        }
    }

    /// Construct from an internal offset whose protocol invariant bounds it.
    pub(crate) const fn from_u64_bounded(x: u64) -> Self {
        assert!(x < (1 << 62), "QUIC varint exceeds its wire bound");
        Self(x)
    }

    /// Extract the integer value
    pub(crate) const fn into_inner(self) -> u64 {
        self.0
    }

    /// Compute the number of bytes needed to encode this value
    pub(crate) const fn size(self) -> usize {
        let x = self.0;
        if x < 2u64.pow(6) {
            1
        } else if x < 2u64.pow(14) {
            2
        } else if x < 2u64.pow(30) {
            4
        } else if x < 2u64.pow(62) {
            8
        } else {
            panic!("malformed VarInt");
        }
    }
}

impl From<VarInt> for u64 {
    fn from(x: VarInt) -> Self {
        x.0
    }
}

impl From<u8> for VarInt {
    fn from(x: u8) -> Self {
        Self(x.into())
    }
}

impl From<u16> for VarInt {
    fn from(x: u16) -> Self {
        Self(x.into())
    }
}

impl From<u32> for VarInt {
    fn from(x: u32) -> Self {
        Self(x.into())
    }
}

impl std::convert::TryFrom<u64> for VarInt {
    type Error = VarIntBoundsExceeded;
    /// Succeeds iff `x` < 2^62
    fn try_from(x: u64) -> Result<Self, VarIntBoundsExceeded> {
        Self::from_u64(x)
    }
}

impl std::convert::TryFrom<u128> for VarInt {
    type Error = VarIntBoundsExceeded;
    /// Succeeds iff `x` < 2^62
    fn try_from(x: u128) -> Result<Self, VarIntBoundsExceeded> {
        Self::from_u64(x.try_into().map_err(|_| VarIntBoundsExceeded)?)
    }
}

impl std::convert::TryFrom<usize> for VarInt {
    type Error = VarIntBoundsExceeded;
    /// Succeeds iff `x` < 2^62
    fn try_from(x: usize) -> Result<Self, VarIntBoundsExceeded> {
        Self::try_from(x as u64)
    }
}

impl fmt::Debug for VarInt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl fmt::Display for VarInt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[cfg(any())]
impl<'arbitrary> Arbitrary<'arbitrary> for VarInt {
    fn arbitrary(u: &mut arbitrary::Unstructured<'arbitrary>) -> arbitrary::Result<Self> {
        Ok(Self(u.int_in_range(0..=Self::MAX.0)?))
    }
}

/// Error returned when constructing a `VarInt` from a value >= 2^62
#[derive(Debug, Copy, Clone, Eq, PartialEq, Error)]
#[error("value too large for varint encoding")]
pub(crate) struct VarIntBoundsExceeded;

impl Codec for VarInt {
    fn decode<B: Buf>(r: &mut B) -> coding::Result<Self> {
        if !r.has_remaining() {
            return Err(UnexpectedEnd);
        }
        let mut buf = [0; 8];
        buf[0] = r.get_u8();
        let tag = buf[0] >> 6;
        buf[0] &= 0b0011_1111;
        let x = match tag {
            0b00 => u64::from(buf[0]),
            0b01 => {
                if r.remaining() < 1 {
                    return Err(UnexpectedEnd);
                }
                r.copy_to_slice(&mut buf[1..2]);
                u64::from(u16::from_be_bytes(buf[..2].try_into().unwrap()))
            }
            0b10 => {
                if r.remaining() < 3 {
                    return Err(UnexpectedEnd);
                }
                r.copy_to_slice(&mut buf[1..4]);
                u64::from(u32::from_be_bytes(buf[..4].try_into().unwrap()))
            }
            0b11 => {
                if r.remaining() < 7 {
                    return Err(UnexpectedEnd);
                }
                r.copy_to_slice(&mut buf[1..8]);
                u64::from_be_bytes(buf)
            }
            _ => unreachable!(),
        };
        Ok(Self(x))
    }

    fn encode<B: BufMut>(&self, w: &mut B) {
        let x = self.0;
        if x < 2u64.pow(6) {
            w.put_u8(x as u8);
        } else if x < 2u64.pow(14) {
            w.put_u16((0b01 << 14) | x as u16);
        } else if x < 2u64.pow(30) {
            w.put_u32((0b10 << 30) | x as u32);
        } else if x < 2u64.pow(62) {
            w.put_u64((0b11 << 62) | x);
        } else {
            unreachable!("malformed VarInt")
        }
    }
}
