extern crate alloc;
use alloc::vec::Vec;
use core::fmt::Debug;

use serde::{Deserialize, Serialize};

use crate::digest::Digest;

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
