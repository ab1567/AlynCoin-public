extern crate alloc;

use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct MerkleProof {
    pub nodes: Vec<[u8; 32]>,
    pub index: usize,
}

impl MerkleProof {
    pub fn new(nodes: Vec<[u8; 32]>, index: usize) -> Self {
        Self { nodes, index }
    }
}
