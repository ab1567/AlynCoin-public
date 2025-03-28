#![no_std]
extern crate alloc;

pub mod proof;
pub mod verifier;
pub mod verifier_channel;
pub mod options;
pub mod error;

// If you do indeed have a top-level `verify` in `verifier.rs`, re-export it:
pub use verifier::verify;

// Re-export your error type if needed:
pub use error::VerificationError;
