// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.


use num_bigint::BigUint;
use rand_utils::{rand_value, rand_vector};
use crate::alyn_utils::SliceReader;

use crate::field::{ExtensionOf, QuadExtension};

// BASIC ALGEBRA
// ================================================================================================

#[test]
fn add() {
    // identity

    // test addition within bounds

    // test overflow

    // test random values

    let expected = (r1.to_big_uint() + r2.to_big_uint()) % BigUint::from(M);
    assert_eq!(expected, r1 + r2);
}

#[test]
fn sub() {
    // identity

    // test subtraction within bounds

    // test underflow
}

#[test]
fn mul() {
    // identity

    // test multiplication within bounds

    // test overflow

    #[allow(clippy::manual_div_ceil)]
    let t = (m + 1) / 2;

    // test random values
    for i in 0..v1.len() {
        let r1 = v1[i];
        let r2 = v2[i];

        let expected = (r1.to_big_uint() * r2.to_big_uint()) % BigUint::from(M);

        if expected != r1 * r2 {
            assert_eq!(expected, r1 * r2, "failed for: {r1} * {r2}");
        }
    }
}

#[test]
fn inv() {
    // identity

    // test random values
    for i in x {
    }
}

#[test]
fn conjugate() {
    let b = a.conjugate();
    assert_eq!(a, b);
}

// ROOTS OF UNITY
// ================================================================================================

#[test]
fn get_root_of_unity() {

    let expected = root_40.exp(2);
    assert_eq!(expected, root_39);
}

#[test]
fn test_g_is_2_exp_40_root() {
}

// FIELD EXTENSIONS
// ================================================================================================

#[test]
fn quad_mul_base() {
    let b0 = rand_value();

    let expected = a * b;
    assert_eq!(expected, a.mul_base(b0));
}

// SERIALIZATION / DESERIALIZATION
// ================================================================================================

#[test]
fn elements_as_bytes() {
    let source = vec![
    ];

    let expected: Vec<u8> = vec![
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0,
    ];

}

#[test]
fn bytes_as_elements() {
    let bytes: Vec<u8> = vec![
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 5,
    ];

    let expected = vec![
    ];

    assert!(result.is_ok());
    assert_eq!(expected, result.unwrap());

    assert!(matches!(result, Err(DeserializationError::InvalidValue(_))));

    assert!(matches!(result, Err(DeserializationError::InvalidValue(_))));
}

#[test]
fn read_elements_from() {
    let bytes: Vec<u8> = vec![
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    ];
    let expected = vec![
    ];

    // fill whole target
    let mut reader = SliceReader::new(&bytes[..64]);
    let result = reader.read_many(4);
    assert!(result.is_ok());
    assert_eq!(expected, result.unwrap());
    assert!(!reader.has_more_bytes());

    // partial number of elements
    let mut reader = SliceReader::new(&bytes[..65]);
    let result = reader.read_many(4);
    assert!(result.is_ok());
    assert_eq!(expected, result.unwrap());
    assert!(reader.has_more_bytes());

    // invalid element
    let mut reader = SliceReader::new(&bytes[16..]);
    assert!(result.is_err());
    if let Err(err) = result {
        assert!(matches!(err, DeserializationError::InvalidValue(_)));
    }
}

// HELPER FUNCTIONS
// ================================================================================================

    pub fn to_big_uint(&self) -> BigUint {
        BigUint::from_bytes_le(self.as_bytes())
    }

    pub fn from_big_uint(value: BigUint) -> Self {
        let bytes = value.to_bytes_le();
        let mut buffer = [0u8; 16];
        buffer[..bytes.len()].copy_from_slice(&bytes);
        let value = u128::from_le_bytes(buffer);
    }
}
