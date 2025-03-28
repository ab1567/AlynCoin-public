use crate::traits::StarkField;

pub fn pow2(mut exp: usize) -> usize {
    let mut result = 1;
    while exp > 0 {
        result <<= 1;
        exp -= 1;
    }
    result
}

pub fn log2(mut n: usize) -> usize {
    assert!(n.is_power_of_two());
    let mut result = 0;
    while n > 1 {
        n >>= 1;
        result += 1;
    }
    result
}

pub fn transpose<E: StarkField>(matrix: &mut Vec<Vec<E>>) {
    if matrix.is_empty() {
        return;
    }
    let row_len = matrix[0].len();
    let col_len = matrix.len();
    let mut transposed = vec![vec![E::ZERO; col_len]; row_len];
    for i in 0..col_len {
        for j in 0..row_len {
            transposed[j][i] = matrix[i][j];
        }
    }
    *matrix = transposed;
}

// Add this:
pub fn is_power_of_two(n: usize) -> bool {
    n != 0 && (n & (n - 1)) == 0
}
