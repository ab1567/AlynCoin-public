use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofOptions {
    pub num_queries: usize,
    pub blowup_factor: usize,
    pub grinding_factor: usize,
    pub fri_folding_factor: usize,
    pub fri_max_remainder_size: usize,
}

impl ProofOptions {
    pub fn new(
        num_queries: usize,
        blowup_factor: usize,
        grinding_factor: usize,
        fri_folding_factor: usize,
        fri_max_remainder_size: usize,
    ) -> Self {
        Self {
            num_queries,
            blowup_factor,
            grinding_factor,
            fri_folding_factor,
            fri_max_remainder_size,
        }
    }
}
