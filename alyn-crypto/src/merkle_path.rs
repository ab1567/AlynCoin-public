extern crate alloc;

use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct MerklePath {
    pub nodes: Vec<[u8; 32]>,
}

impl MerklePath {
    pub fn new(nodes: Vec<[u8; 32]>) -> Self {
        Self { nodes }
    }
}
