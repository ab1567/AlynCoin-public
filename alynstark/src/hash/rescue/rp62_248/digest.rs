// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use core::slice;

use crate::alyn_utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable};

use super::{Digest, DIGEST_SIZE};

// DIGEST TRAIT IMPLEMENTATIONS
// ================================================================================================

#[derive(Debug, Copy, Clone, Eq, PartialEq)]

impl ElementDigest {
        Self(value)
    }

        &self.0
    }

        let p = digests.as_ptr();
        let len = digests.len() * DIGEST_SIZE;
    }
}

impl Digest for ElementDigest {
    fn as_bytes(&self) -> [u8; 32] {
        let v1 = self.0[0].as_int();
        let v2 = self.0[1].as_int();
        let v3 = self.0[2].as_int();
        let v4 = self.0[3].as_int();

        let mut result = [0; 32];
        result[..8].copy_from_slice(&(v1 | (v2 << 62)).to_le_bytes());
        result[8..16].copy_from_slice(&((v2 >> 2) | (v3 << 60)).to_le_bytes());
        result[16..24].copy_from_slice(&((v3 >> 4) | (v4 << 58)).to_le_bytes());
        result[24..].copy_from_slice(&(v4 >> 6).to_le_bytes());

        result
    }
}

impl Default for ElementDigest {
    fn default() -> Self {
    }
}

impl Serializable for ElementDigest {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_bytes(&self.as_bytes()[..31]);
    }
}

impl Deserializable for ElementDigest {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let v1 = source.read_u64()?;
        let v2 = source.read_u64()?;
        let v3 = source.read_u64()?;
        let v4 = source.read_u32()?;
        let v5 = source.read_u16()?;
        let v6 = source.read_u8()?;

            (v3 >> 58) | ((v4 as u64) << 6) | ((v5 as u64) << 38) | ((v6 as u64) << 54),
        );

        Ok(Self([e1, e2, e3, e4]))
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {

    use rand_utils::rand_array;
    use utils::{Deserializable, Serializable, SliceReader};

    use super::ElementDigest;

    #[test]
    fn digest_serialization() {
        let d1 = ElementDigest(rand_array());

        let mut bytes = vec![];
        d1.write_into(&mut bytes);
        assert_eq!(31, bytes.len());

        let mut reader = SliceReader::new(&bytes);
        let d2 = ElementDigest::read_from(&mut reader).unwrap();

        assert_eq!(d1, d2);
    }
}
