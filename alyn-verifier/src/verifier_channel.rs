extern crate alloc;

use core::fmt::Debug;

use crate::proof::StarkProof;
use crate::error::VerificationError;
use alyn_crypto::hash::Hasher;

#[derive(Debug)]
pub struct VerifierChannel<H>
where
    H: Hasher,
{
    pub proof: StarkProof<H>,
    pub position: usize,
}

impl<H> VerifierChannel<H>
where
    H: Hasher,
{
    pub fn new(proof: StarkProof<H>) -> Result<Self, VerificationError> {
        Ok(Self { proof, position: 0 })
    }

    pub fn read_commitment(&mut self) -> Result<H::Digest, VerificationError> {
        if self.position >= self.proof.commitments.len() {
            return Err(VerificationError::InvalidCommitment);
        }
        let c = self.proof.commitments[self.position].clone();
        self.position += 1;
        Ok(c)
    }
}
