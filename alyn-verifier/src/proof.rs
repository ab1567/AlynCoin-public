extern crate alloc;

use alloc::vec::Vec;
use core::fmt::Debug;
use serde::{Serialize, Deserialize};
use alyn_crypto::hash::Hasher;

/// Verifier's version of StarkProof with 1 generic param: H
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StarkProof<H>
where
    H: Hasher,
{
    pub commitments: Vec<H::Digest>,
}

impl<H> StarkProof<H>
where
    H: Hasher,
{
    // If needed, a write_into method that uses your ByteWriter. 
    // We'll keep it as a stub:
    pub fn write_into<W>(&self, _target: &mut W) -> Result<(), ()> {
        Ok(())
    }
}
