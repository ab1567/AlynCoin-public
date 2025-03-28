#![no_std]

extern crate alloc;

#[allow(clippy::too_many_arguments)]
#[allow(clippy::type_complexity)]
// External AlynSTARK Crate Dependencies
pub extern crate alyn_air    as air;
pub extern crate alyn_prover as prover;
pub extern crate alyn_verifier as verifier;
pub extern crate alyn_crypto as crypto;
pub extern crate alyn_math   as math;
pub extern crate alyn_utils  as utils;

// Re-export from `alyn_prover` only items which actually exist now:
pub use prover::{
    // e.g., `air_prover::AirProver` if you have that:
    air_prover::AirProver,
    // from `trace.rs`:
    trace::TraceTable,
    // from `trace_lde.rs`:
    trace_lde::DefaultTraceLde,
    // from `constraint_commitment.rs`:
    constraint_commitment::DefaultConstraintCommitment,
    // remove references to any old items (like `Prover`, `DefaultConstraintEvaluator`) if you no longer have them
};

// Re-export from `alyn_verifier` only items which still exist:
pub use verifier::{
    // if a top-level `verify` function is in `lib.rs` or `verifier.rs`:
    verify,
    // if there's an error type in `error.rs`:
    error::VerificationError,
    // if `StarkProof` is in `proof.rs`:
    proof::StarkProof,
    // remove references to `AcceptableOptions` etc. if you no longer have them
};

// Re-export from `alyn_utils` or its submodules:
pub use utils::{
    // if `Serializable` & `Deserializable` are in `serialization.rs`:
    serialization::{Serializable, Deserializable},
    // if `ByteReader` and `ByteWriter` are in `byte_io.rs`:
    byte_io::{ByteReader, ByteWriter},
};

// Prelude for convenience
pub mod prelude {
    pub use super::utils::serialization::{Serializable, Deserializable};
}
