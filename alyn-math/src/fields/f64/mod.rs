use core::fmt;
use core::ops::{Add, AddAssign, Div, Mul, MulAssign, Neg, Sub, SubAssign};
use serde::{Deserialize, Serialize};

/// Represents an element in the base field with modulus 2^64 - 2^32 + 1.
#[derive(Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaseElement(pub u64);

impl BaseElement {
    pub const MODULUS: u64 = 0xffffffff00000001;

    /// Creates a new field element from the provided `value`; reduced modulo MODULUS.
    pub const fn new(value: u64) -> Self {
        BaseElement(value % Self::MODULUS)
    }

    pub const fn inner(&self) -> u64 {
        self.0
    }

    pub fn zero() -> Self {
        BaseElement(0)
    }

    pub fn one() -> Self {
        BaseElement(1)
    }

    pub fn is_zero(&self) -> bool {
        self.0 == 0
    }

    pub fn inverse(self) -> Option<Self> {
        if self.is_zero() {
            None
        } else {
            Some(self.exp(Self::MODULUS - 2))
        }
    }

    pub fn square(self) -> Self {
        self * self
    }

    pub fn exp(self, power: u64) -> Self {
        let mut result = Self::one();
        let mut base = self;
        let mut exp = power;

        while exp > 0 {
            if exp % 2 == 1 {
                result *= base;
            }
            base *= base;
            exp /= 2;
        }
        result
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        self.0.to_le_bytes().to_vec()
    }

    pub fn as_int(&self) -> u64 {
        self.0
    }
}

// ---------- Operators Implementations ----------

impl Add for BaseElement {
    type Output = Self;
    fn add(self, rhs: Self) -> Self::Output {
        BaseElement((self.0 + rhs.0) % Self::MODULUS)
    }
}

impl AddAssign for BaseElement {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl Sub for BaseElement {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self::Output {
        let val = if self.0 >= rhs.0 {
            self.0 - rhs.0
        } else {
            Self::MODULUS - (rhs.0 - self.0)
        };
        BaseElement(val)
    }
}

impl SubAssign for BaseElement {
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl Mul for BaseElement {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self::Output {
        let product = (self.0 as u128 * rhs.0 as u128) % (Self::MODULUS as u128);
        BaseElement(product as u64)
    }
}

impl MulAssign for BaseElement {
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs;
    }
}

impl Div for BaseElement {
    type Output = Self;
    fn div(self, rhs: Self) -> Self::Output {
        self * rhs.inverse().expect("Division by zero")
    }
}

impl Neg for BaseElement {
    type Output = Self;
    fn neg(self) -> Self::Output {
        if self.is_zero() {
            Self::zero()
        } else {
            BaseElement(Self::MODULUS - self.0)
        }
    }
}

// ---------- Display / Debug ----------

impl fmt::Debug for BaseElement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Display for BaseElement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
