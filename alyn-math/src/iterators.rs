use crate::matrix::Row;
use core::iter::Iterator;

pub struct RowIterator<'a, E> {
    row: &'a Row<E>,
    index: usize,
}

impl<'a, E: Copy> RowIterator<'a, E> {
    pub fn new(row: &'a Row<E>) -> Self {
        Self { row, index: 0 }
    }
}

impl<'a, E: Copy> Iterator for RowIterator<'a, E> {
    type Item = E;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index < self.row.len() {
            let item = self.row[self.index];
            self.index += 1;
            Some(item)
        } else {
            None
        }
    }
}
