// /root/AlynCoin/alyn-math/src/lib.rs

extern crate alloc;

pub mod fft;
pub mod field_element;
pub mod fields;
pub mod iterators;
pub mod matrix;
pub mod utils;
pub mod traits; // ✅ Added missing module!

pub use crate::fft::fft;
pub use crate::matrix::{Col, Matrix, Row};
pub use alyn_utils::utils::{is_power_of_two, log2, pow2, transpose};

// Optional: Simplify StarkField usage across modules
pub use crate::traits::StarkField;
