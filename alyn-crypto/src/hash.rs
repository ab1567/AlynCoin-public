// alyn-crypto/src/hash.rs
use core::fmt::Debug;

use crate::digest::Digest;
use alyn_math::StarkField;
use serde::{Serialize, de::DeserializeOwned};

/// Hasher trait which defines a base field, a digest type, and hashing methods.
///
/// We added `type BaseField: StarkField` so you can do `H: Hasher<BaseField = A::BaseField>`.
pub trait Hasher: Sized {
    /// The field over which this hasher operates.
    type BaseField: StarkField + Debug + Serialize + DeserializeOwned;

    /// The digest type (e.g. `ElementDigest<Self::BaseField>`).
    type Digest: Digest;

    /// Hash raw bytes into a digest.
    fn hash(bytes: &[u8]) -> Self::Digest;

    /// Merge two digests.
    fn merge(values: &[Self::Digest; 2]) -> Self::Digest;

    /// Merge many digests.
    fn merge_many(values: &[Self::Digest]) -> Self::Digest;

    /// Merge a digest with a 64-bit integer.
    fn merge_with_int(value: Self::Digest, int: u64) -> Self::Digest;

    /// Hash an array of field elements (flattened).
    fn hash_elements<E: StarkField + Serialize>(elements: &[E]) -> Self::Digest;
}
