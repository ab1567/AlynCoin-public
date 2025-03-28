extern crate alloc;

use alloc::vec::Vec;
use core::fmt::Debug;
use serde::Serialize;

use alyn_math::StarkField;
use alyn_crypto::hash::Hasher;
use alyn_crypto::digest::Digest;
use alyn_utils::{
    ByteWriter,
    ByteIOError, // unified from `byte_io.rs`
};

use crate::constraint_commitment::DefaultConstraintCommitment;
use crate::trace_lde::DefaultTraceLde;

#[derive(Debug, Clone, Serialize)]
pub struct StarkProof<E, H>
where
    E: StarkField + Debug + Serialize,
    H: Hasher,
{
    pub commitments: Vec<H::Digest>,
    pub constraint_commitment: DefaultConstraintCommitment,
    pub trace_lde: DefaultTraceLde<E>,
}

impl<E, H> StarkProof<E, H>
where
    E: StarkField + Debug + Serialize,
    H: Hasher,
{
    /// Return `Result<(), ByteIOError>` to match the ByteWriter trait.
    pub fn write_into<W: ByteWriter>(&self, target: &mut W) -> Result<(), ByteIOError> {
        // Convert digest's bytes from e.g. Vec<u8> to &[u8] if needed:
        for digest in &self.commitments {
            let bytes_slice: &[u8] = &digest.as_bytes()[..];
            target.write_bytes(bytes_slice)?;
        }

        // Write out constraint commitment
        let cc_bytes = self.constraint_commitment.commitment();
        target.write_bytes(cc_bytes)?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct ProofOptions;

#[derive(Debug)]
pub struct ProverError;
