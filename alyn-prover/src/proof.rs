extern crate alloc;

use alloc::vec::Vec;
use core::fmt::Debug;
use serde::Serialize;

use alyn_math::StarkField;
use alyn_crypto::hash::Hasher;
use alyn_crypto::digest::Digest;
use alyn_utils::{
    ByteWriter,
    ByteIOError,
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
    pub fn write_into<W: ByteWriter>(&self, target: &mut W) -> Result<(), ByteIOError> {
        for digest in &self.commitments {
            let bytes_slice: &[u8] = &digest.as_bytes()[..];
            target.write_bytes(bytes_slice)?;
        }

        let cc_bytes = self.constraint_commitment.commitment();
        target.write_bytes(cc_bytes)?;
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct ProofOptions {
    pub num_queries: usize,
    pub blowup_factor: usize,
    pub grinding_factor: usize,
    pub fri_folding_factor: usize,
    pub fri_max_remainder_size: usize,
}

impl ProofOptions {
    pub fn new(
        num_queries: usize,
        blowup_factor: usize,
        grinding_factor: usize,
        fri_folding_factor: usize,
        fri_max_remainder_size: usize,
    ) -> Self {
        Self {
            num_queries,
            blowup_factor,
            grinding_factor,
            fri_folding_factor,
            fri_max_remainder_size,
        }
    }
}

#[derive(Debug)]
pub struct ProverError;
