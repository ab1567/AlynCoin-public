extern crate alloc;

pub mod air_prover;
pub mod constraint_evaluator;
pub mod trace;
pub mod trace_lde;
pub mod constraint_commitment;
pub mod proof;

pub use constraint_commitment::DefaultConstraintCommitment;
pub use proof::{StarkProof, ProofOptions, ProverError};
pub use trace_lde::{DefaultTraceLde};

// Removed unnecessary re-export of TraceLde (not defined as trait or type)
