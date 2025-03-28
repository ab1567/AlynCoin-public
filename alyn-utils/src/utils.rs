#![allow(unused)]

extern crate alloc;
use alloc::vec::Vec;
use alloc::vec; // for macro usage

/// Return true if x is a power of two
pub fn is_power_of_two(x: usize) -> bool {
    x != 0 && (x & (x - 1)) == 0
}

pub fn pow2(x: usize) -> usize {
    1 << x
}

pub fn log2(x: usize) -> usize {
    let mut r = 0;
    let mut n = x;
    while n > 1 {
        n >>= 1;
        r += 1;
    }
    r
}

/// Transpose a 2D matrix in place
pub fn transpose<E: Copy>(matrix: &mut Vec<Vec<E>>) {
    // "vec!" macro usage:
    let col_len = matrix.len();
    if col_len == 0 {
        return;
    }
    let row_len = matrix[0].len();

    let mut transposed = vec![vec![matrix[0][0]; col_len]; row_len];

    for i in 0..col_len {
        for j in 0..row_len {
            transposed[j][i] = matrix[i][j];
        }
    }

    // Replace original
    *matrix = transposed;
}
