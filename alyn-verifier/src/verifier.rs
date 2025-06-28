#![allow(unused)]
extern crate alloc;

use alloc::vec::Vec; // if you need
use alloc::boxed::Box; // if you need Box
use core::fmt::Debug;

use alyn_crypto::hash::Hasher;
use alyn_crypto::Digest;
use crate::proof::StarkProof;
use crate::error::VerificationError;

// Our top-level verify function
pub fn verify<H: Hasher>(proof: &StarkProof<H>) -> Result<(), VerificationError> {
    // Basic sanity check on the commitments.
    if proof.commitments.is_empty() {
        return Err(VerificationError::InvalidCommitment);
    }

    // Combine all commitments using the supplied hasher. This is *not* a full
    // STARK verification but at least exercises the hashing interface and fails
    // if hashing results in an empty digest.
    let root = H::merge_many(&proof.commitments);

    if root.as_bytes().is_empty() {
        return Err(VerificationError::InvalidProof);
    }

    Ok(())
}
