// alyn-math/src/fields/f64/field.rs


pub const MODULUS: u64 = 0xffffffff00000001;
pub const GENERATOR: u64 = 7;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct F64;

impl StarkField for F64 {
    type BaseField = Self;

    fn two_adicity() -> u32 {
        32
    }

    fn modulus() -> u64 {
        MODULUS
    }

    fn generator() -> Self {
    }
}

    type BaseField = Self;

    fn zero() -> Self {
    }

    fn one() -> Self {
    }

    fn is_zero(&self) -> bool {
        self.0 == 0
    }

    fn double(&self) -> Self {
    }
}
