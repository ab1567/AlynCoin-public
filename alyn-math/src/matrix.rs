use crate::traits::StarkField;

#[derive(Debug, Clone)]
pub struct Matrix<E: StarkField> {
    data: Vec<Vec<E>>,
    rows: usize,
    cols: usize,
}

impl<E: StarkField> Matrix<E> {
    pub fn new(rows: usize, cols: usize) -> Self {
        let data = vec![vec![E::ZERO; cols]; rows];
        Self { data, rows, cols }
    }

    pub fn rows(&self) -> usize {
        self.rows
    }

    pub fn cols(&self) -> usize {
        self.cols
    }

    pub fn get(&self, row: usize, col: usize) -> E {
        self.data[row][col]
    }

    pub fn set(&mut self, row: usize, col: usize, value: E) {
        self.data[row][col] = value;
    }
}
pub type Row<E> = Vec<E>;
pub type Col<E> = Vec<E>;
