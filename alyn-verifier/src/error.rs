extern crate alloc;
use alloc::string::String;
use core::fmt::{self, Display, Formatter};

#[derive(Debug)]
pub enum VerificationError {
    InvalidProof,
    InvalidCommitment,
    VerificationFailed(String),
}

impl Display for VerificationError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            VerificationError::InvalidProof => write!(f, "Invalid proof"),
            VerificationError::InvalidCommitment => write!(f, "Invalid commitment"),
            VerificationError::VerificationFailed(msg) => {
                write!(f, "Verification failed: {}", msg)
            }
        }
    }
}

// If you want std::error::Error in a no_std crate, wrap it:
//#[cfg(feature = "std")]
// comment out or remove if it's not needed
// impl std::error::Error for VerificationError {}
