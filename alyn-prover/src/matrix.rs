extern crate alloc;

use alloc::vec::Vec;
use core::fmt::Debug;
use alyn_math::StarkField;

pub struct RowMatrix<E: StarkField + Debug> {
    rows: Vec<Vec<E>>,
}

impl<E: StarkField + Debug> RowMatrix<E> {
    pub fn new(rows: Vec<Vec<E>>) -> Self {
        RowMatrix { rows }
    }

    pub fn rows(&self) -> &Vec<Vec<E>> {
        &self.rows
    }
}

pub struct ColMatrix<E: StarkField + Debug> {
    cols: Vec<Vec<E>>,
}

impl<E: StarkField + Debug> ColMatrix<E> {
    pub fn new(cols: Vec<Vec<E>>) -> Self {
        ColMatrix { cols }
    }

    pub fn cols(&self) -> &Vec<Vec<E>> {
        &self.cols
    }
}
