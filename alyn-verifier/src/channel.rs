extern crate alloc;

use alloc::vec::Vec;
use crate::error::VerifierError;

pub trait VerifierChannel<E> {
    type Digest: AsRef<[u8]>;

    fn draw_fri_layer_commitment(&mut self) -> Result<Self::Digest, VerifierError>;

    fn draw_query_positions(&mut self, num_positions: usize) -> Result<Vec<usize>, VerifierError>;

    fn draw_coefficients(&mut self, num_coefficients: usize) -> Result<Vec<E>, VerifierError>;

    fn draw_bytes(&mut self, num_bytes: usize) -> Result<Vec<u8>, VerifierError>;
}
