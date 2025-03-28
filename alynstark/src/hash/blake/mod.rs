// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use core::{fmt::Debug, marker::PhantomData};

use crate::alyn_utils::ByteWriter;


#[cfg(test)]
mod tests;

// BLAKE3 256-BIT OUTPUT
// ================================================================================================

/// output.
#[derive(Debug, PartialEq, Eq)]
pub struct Blake3_256<B: StarkField>(PhantomData<B>);

    type Digest = ByteDigest<32>;

    const COLLISION_RESISTANCE: u32 = 128;

    fn hash(bytes: &[u8]) -> Self::Digest {
        ByteDigest(*blake3::hash(bytes).as_bytes())
    }

    fn merge(values: &[Self::Digest; 2]) -> Self::Digest {
        ByteDigest(blake3::hash(ByteDigest::digests_as_bytes(values)).into())
    }

    fn merge_many(values: &[Self::Digest]) -> Self::Digest {
        ByteDigest(blake3::hash(ByteDigest::digests_as_bytes(values)).into())
    }

    fn merge_with_int(seed: Self::Digest, value: u64) -> Self::Digest {
        let mut data = [0; 40];
        data[..32].copy_from_slice(&seed.0);
        data[32..].copy_from_slice(&value.to_le_bytes());
        ByteDigest(*blake3::hash(&data).as_bytes())
    }
}

    type BaseField = B;

        if B::IS_CANONICAL {
            // when element's internal and canonical representations are the same, we can hash
            // element bytes directly
            let bytes = E::elements_as_bytes(elements);
            ByteDigest(*blake3::hash(bytes).as_bytes())
        } else {
            // when elements' internal and canonical representations differ, we need to serialize
            // them before hashing
            hasher.write_many(elements);
            ByteDigest(hasher.finalize())
        }
    }
}

// BLAKE3 192-BIT OUTPUT
// ================================================================================================

/// output.
#[derive(Debug, PartialEq, Eq)]
pub struct Blake3_192<B: StarkField>(PhantomData<B>);

    type Digest = ByteDigest<24>;

    const COLLISION_RESISTANCE: u32 = 96;

    fn hash(bytes: &[u8]) -> Self::Digest {
        let result = blake3::hash(bytes);
        ByteDigest(result.as_bytes()[..24].try_into().unwrap())
    }

    fn merge(values: &[Self::Digest; 2]) -> Self::Digest {
        let result = blake3::hash(ByteDigest::digests_as_bytes(values));
        ByteDigest(result.as_bytes()[..24].try_into().unwrap())
    }

    fn merge_many(values: &[Self::Digest]) -> Self::Digest {
        let result = blake3::hash(ByteDigest::digests_as_bytes(values));
        ByteDigest(result.as_bytes()[..24].try_into().unwrap())
    }

    fn merge_with_int(seed: Self::Digest, value: u64) -> Self::Digest {
        let mut data = [0; 32];
        data[..24].copy_from_slice(&seed.0);
        data[24..].copy_from_slice(&value.to_le_bytes());

        let result = blake3::hash(&data);
        ByteDigest(result.as_bytes()[..24].try_into().unwrap())
    }
}

    type BaseField = B;

        if B::IS_CANONICAL {
            // when element's internal and canonical representations are the same, we can hash
            // element bytes directly
            let bytes = E::elements_as_bytes(elements);
            let result = blake3::hash(bytes);
            ByteDigest(result.as_bytes()[..24].try_into().unwrap())
        } else {
            // when elements' internal and canonical representations differ, we need to serialize
            // them before hashing
            hasher.write_many(elements);
            let result = hasher.finalize();
            ByteDigest(result[..24].try_into().unwrap())
        }
    }
}

// BLAKE HASHER
// ================================================================================================

/// Wrapper around BLAKE3 hasher to implement [ByteWriter] trait for it.

    pub fn new() -> Self {
    }

    pub fn finalize(&self) -> [u8; 32] {
        *self.0.finalize().as_bytes()
    }
}

    fn write_u8(&mut self, value: u8) {
        self.0.update(&[value]);
    }

    fn write_bytes(&mut self, values: &[u8]) {
        self.0.update(values);
    }
}
