// ~/AlynCoin/alyn-math/src/fields/f64/field.rs

use core::ops::{Add, Sub, Mul, Div};
use crate::traits::StarkField;

pub const MODULUS: u64 = 0xffffffff00000001;
pub const GENERATOR: u64 = 7;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct BaseElement(u64);

impl BaseElement {
    pub fn new(value: u64) -> Self {
        Self(value % MODULUS)
    }

    pub fn value(&self) -> u64 {
        self.0
    }

    pub fn as_int(&self) -> u64 {
        self.0
    }
}

impl StarkField for BaseElement {
    type BaseField = Self;

    fn two_adicity() -> u32 {
        32
    }

    fn modulus() -> u64 {
        MODULUS
    }

    fn generator() -> Self {
        Self(GENERATOR)
    }

    fn zero() -> Self {
        Self(0)
    }

    fn one() -> Self {
        Self(1)
    }

    fn is_zero(&self) -> bool {
        self.0 == 0
    }

    fn double(&self) -> Self {
        Self((self.0 << 1) % MODULUS)
    }
}

// Arithmetic operations
impl Add for BaseElement {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        Self((self.0 + other.0) % MODULUS)
    }
}

impl Sub for BaseElement {
    type Output = Self;

    fn sub(self, other: Self) -> Self {
        Self((self.0 + MODULUS - other.0) % MODULUS)
    }
}

impl Mul for BaseElement {
    type Output = Self;

    fn mul(self, other: Self) -> Self {
        Self(((self.0 as u128 * other.0 as u128) % MODULUS as u128) as u64)
    }
}

impl Div for BaseElement {
    type Output = Self;

    fn div(self, other: Self) -> Self {
        self * other.inv()
    }
}

impl BaseElement {
    // Compute multiplicative inverse using Fermat's Little Theorem
    pub fn inv(self) -> Self {
        self.exp(MODULUS - 2)
    }

    pub fn exp(self, exponent: u64) -> Self {
        let mut base = self;
        let mut exp = exponent;
        let mut result = Self::one();

        while exp > 0 {
            if exp % 2 == 1 {
                result = result * base;
            }
            base = base * base;
            exp >>= 1;
        }

        result
    }
}
