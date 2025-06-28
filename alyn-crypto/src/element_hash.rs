extern crate alloc;
use alloc::vec::Vec;
use core::fmt::Debug;

use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::digest::Digest;
use crate::hash::Hasher;
use blake3;
use core::marker::PhantomData;
use alyn_math::StarkField;

/// A simple byte-based digest type.
/// 
/// - This struct can be fully serialized/deserialized.
/// - It implements all the traits required by `Digest`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ElementDigest {
    /// The raw bytes of this digest
    bytes: Vec<u8>,
}

impl ElementDigest {
    /// Create a new digest from raw bytes
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }
}

/// Implement the `Digest` trait for `ElementDigest`.
/// 
/// - We must define `fn as_bytes(&self) -> Vec<u8>` to fulfill the requirement.
impl Digest for ElementDigest {
    /// Return a fresh `Vec<u8>` copy of the internal bytes.
    fn as_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }
}

/// Implement `AsRef<[u8]>` so we fulfill the `Digest` supertrait requirement.
/// 
/// This allows you to get a reference to the underlying raw bytes without copying.
impl AsRef<[u8]> for ElementDigest {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

/// Hasher backed by the `blake3` hash function. This is a very lightweight
/// implementation to make the crates compile and should not be used in
/// production environments.
pub struct Blake3Hasher<E> {
    _marker: PhantomData<E>,
}

impl<E> Default for Blake3Hasher<E> {
    fn default() -> Self {
        Self { _marker: PhantomData }
    }
}

impl<E> Hasher for Blake3Hasher<E>
where
    E: StarkField + Debug + Serialize + DeserializeOwned,
{
    type BaseField = E;
    type Digest = ElementDigest;

    fn hash(bytes: &[u8]) -> Self::Digest {
        ElementDigest::new(blake3::hash(bytes).as_bytes().to_vec())
    }

    fn merge(values: &[Self::Digest; 2]) -> Self::Digest {
        let mut hasher = blake3::Hasher::new();
        hasher.update(values[0].as_ref());
        hasher.update(values[1].as_ref());
        ElementDigest::new(hasher.finalize().as_bytes().to_vec())
    }

    fn merge_many(values: &[Self::Digest]) -> Self::Digest {
        let mut hasher = blake3::Hasher::new();
        for v in values {
            hasher.update(v.as_ref());
        }
        ElementDigest::new(hasher.finalize().as_bytes().to_vec())
    }

    fn merge_with_int(value: Self::Digest, int: u64) -> Self::Digest {
        let mut hasher = blake3::Hasher::new();
        hasher.update(value.as_ref());
        hasher.update(&int.to_le_bytes());
        ElementDigest::new(hasher.finalize().as_bytes().to_vec())
    }

    fn hash_elements<F: StarkField + Serialize>(elements: &[F]) -> Self::Digest {
        let mut bytes = Vec::new();
        for e in elements {
            bytes.extend_from_slice(&e.as_bytes());
        }
        Self::hash(&bytes)
    }
}
