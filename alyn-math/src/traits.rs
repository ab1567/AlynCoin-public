use core::ops::{Add, Div, Mul, Neg, Sub};
use serde::{Deserialize, Serialize};

/// Basic trait for field elements.
pub trait StarkField:
    Sized
    + Clone
    + Copy
    + PartialEq
    + Eq
    + Serialize
    + for<'de> Deserialize<'de>
    + Add<Self, Output = Self>
    + Sub<Self, Output = Self>
    + Mul<Self, Output = Self>
    + Div<Self, Output = Self>
    + Neg<Output = Self>
{
    const ZERO: Self;
    const ONE: Self;

    fn zero() -> Self;
    fn one() -> Self;
    fn is_zero(&self) -> bool;
    fn inverse(self) -> Option<Self>;
    fn square(self) -> Self;
    fn exp(self, power: u64) -> Self;
    fn as_bytes(&self) -> Vec<u8>;
    fn as_int(&self) -> u64;
}
