// alyn-prover/src/trace.rs

extern crate alloc;
use alloc::vec::Vec;
use core::fmt::Debug;
use serde::Serialize;
use alyn_math::StarkField;

#[derive(Debug, Clone, Serialize)]
pub struct TraceTable<E>
where
    E: StarkField + Debug + Serialize,
{
    pub table: Vec<Vec<E>>,
}

// Default for TraceTable
impl<E> Default for TraceTable<E>
where
    E: StarkField + Debug + Serialize,
{
    fn default() -> Self {
        Self { table: Vec::new() }
    }
}

impl<E> TraceTable<E>
where
    E: StarkField + Debug + Serialize,
{
    pub fn add_column(&mut self, column: Vec<E>) {
        self.table.push(column);
    }
}
