use crate::fields::f64::BaseElement;

pub fn fft(values: &mut [BaseElement], twiddles: &[BaseElement]) {
    let n = values.len();
    let log_n = n.trailing_zeros() as usize;

    for i in 0..n {
        let j = bit_reverse(i, log_n);
        if i < j {
            values.swap(i, j);
        }
    }

    let mut m = 1;
    for _ in 0..log_n {
        let m2 = 2 * m;
        let step = n / m2;
        for k in 0..m {
            let twiddle = twiddles[k * step];
            for j in (k..n).step_by(m2) {
                let t = twiddle * values[j + m];
                values[j + m] = values[j] - t;
                values[j] += t;
            }
        }
        m = m2;
    }
}

// Moved outside of fft
fn bit_reverse(mut x: usize, log_n: usize) -> usize {
    let mut y = 0;
    for _ in 0..log_n {
        y = (y << 1) | (x & 1);
        x >>= 1;
    }
    y
}
