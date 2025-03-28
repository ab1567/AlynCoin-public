extern crate alloc;
use alloc::vec::Vec;
use serde::{Serialize, Deserialize};

/// Coefficients for constraint composition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConstraintCompositionCoefficients<E> {
    pub transition: Vec<Vec<E>>,
    pub boundary: Vec<Vec<E>>,
}
