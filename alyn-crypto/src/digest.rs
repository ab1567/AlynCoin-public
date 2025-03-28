use serde::{Serialize, Deserialize};
use alloc::vec::Vec;
use core::fmt::Debug;

/// Digest trait used across the system (cryptographic hashes).
pub trait Digest:
    Clone + Debug + Eq + Serialize + for<'a> Deserialize<'a> + AsRef<[u8]>
{
    // Define associated type if needed (optional, depends on usage)
    // type Digest: Digest;

    /// Converts digest to bytes
    fn as_bytes(&self) -> Vec<u8>;
}
