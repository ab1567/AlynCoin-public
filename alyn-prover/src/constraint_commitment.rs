use alloc::vec::Vec;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DefaultConstraintCommitment {
    commitment: Vec<u8>,
}

impl DefaultConstraintCommitment {
    pub fn new(data: Vec<u8>) -> Self {
        Self { commitment: data }
    }

    pub fn commitment(&self) -> &[u8] {
        &self.commitment
    }
}
