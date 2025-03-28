#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use core::fmt;
use serde::{Deserialize, Serialize};

use alyn_math::StarkField;
use crate::digest::Digest;
use crate::hash::{Hasher, ElementHasher};

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct ElementDigest<E: StarkField + Serialize + for<'de> Deserialize<'de>>(pub Vec<E>);

impl<E: StarkField + Serialize + for<'de> Deserialize<'de>> fmt::Display for ElementDigest<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ElementDigest({:?})", self.0)
    }
}

impl<E: StarkField + Serialize + for<'de> Deserialize<'de>> AsRef<[u8]> for ElementDigest<E> {
    fn as_ref(&self) -> &[u8] {
        unimplemented!("Conversion to byte slice is not implemented yet")
    }
}

impl<E: StarkField + fmt::Debug + Serialize + for<'de> Deserialize<'de>> Digest for ElementDigest<E> {}

pub struct DefaultElementHasher<E: StarkField + fmt::Debug + Serialize + for<'de> Deserialize<'de>>;

impl<E: StarkField + fmt::Debug + Serialize + for<'de> Deserialize<'de>> Hasher for DefaultElementHasher<E> {
    type Digest = ElementDigest<E>;

    fn hash(_bytes: &[u8]) -> Self::Digest {
        unimplemented!("hash function is not yet implemented")
    }

    fn merge(values: &[Self::Digest; 2]) -> Self::Digest {
        ElementDigest(
            [values[0].0.clone(), values[1].0.clone()].concat()
        )
    }

    fn merge_many(values: &[Self::Digest]) -> Self::Digest {
        let mut combined = Vec::new();
        for v in values.iter() {
            combined.extend_from_slice(&v.0);
        }
        ElementDigest(combined)
    }

    fn merge_with_int(value: Self::Digest, _int: u64) -> Self::Digest {
        ElementDigest(value.0)
    }
}

impl<E: StarkField + fmt::Debug + Serialize + for<'de> Deserialize<'de>> ElementHasher for DefaultElementHasher<E> {
    type BaseField = E::BaseField;
    type Digest = ElementDigest<E>;

    fn hash_elements(elements: &[E]) -> Self::Digest {
        ElementDigest(elements.to_vec())
    }
}
