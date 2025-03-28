// alyn-prover/src/trace_lde.rs

extern crate alloc;
use alloc::vec::Vec;
use core::fmt::Debug;
use serde::Serialize;
use alyn_math::StarkField;

#[derive(Debug, Clone, Serialize)]
pub struct RowMatrix<E>
where
    E: StarkField + Debug + Serialize,
{
    pub data: Vec<Vec<E>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DefaultTraceLde<E>
where
    E: StarkField + Debug + Serialize,
{
    pub lde_matrix: RowMatrix<E>,
}

// ----------------------------------------
// Implement Default so that
//   DefaultTraceLde::<E>::default()
// is valid.
// ----------------------------------------
impl<E> Default for DefaultTraceLde<E>
where
    E: StarkField + Debug + Serialize,
{
    fn default() -> Self {
        Self {
            lde_matrix: RowMatrix { data: Vec::new() },
        }
    }
}
