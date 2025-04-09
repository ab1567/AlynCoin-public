extern crate alloc;
use alloc::vec::Vec;
use core::fmt::Debug;
use serde::Serialize;
use alyn_math::StarkField;
use alyn_air::TraceInfo;

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

    pub fn get_info(&self) -> TraceInfo<E> {
        let width = E::from_u64(self.table.len() as u64);
        let length = E::from_u64(self.table.get(0).map_or(0, |col| col.len() as u64));

        TraceInfo {
            meta: Some(vec![width, length]),
        }
    }
}
