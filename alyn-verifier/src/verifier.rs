#![allow(unused)]
extern crate alloc;

use alloc::vec::Vec; // if you need
use alloc::boxed::Box; // if you need Box
use core::fmt::Debug;

use alyn_crypto::hash::Hasher;
use crate::proof::StarkProof;
use crate::error::VerificationError;

// Our top-level verify function
pub fn verify<H: Hasher>(proof: &StarkProof<H>) -> Result<(), VerificationError> {
    // minimal stub
    if proof.commitments.is_empty() {
        return Err(VerificationError::InvalidCommitment);
    }
    // do logic
    Ok(())
}
