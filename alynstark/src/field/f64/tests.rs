// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use num_bigint::BigUint;
use proptest::prelude::*;
use rand_utils::rand_value;

use crate::field::{CubeExtension, ExtensionOf, QuadExtension};

// MANUAL TESTS
// ================================================================================================

#[test]
fn add() {
    // identity

    // test addition within bounds

    // test overflow
}

#[test]
fn sub() {
    // identity

    // test subtraction within bounds

    // test underflow
}

#[test]
fn neg() {

    assert_eq!(r, -(-r));
}

#[test]
fn mul() {
    // identity

    // test multiplication within bounds

    // test overflow

    #[allow(clippy::manual_div_ceil)]
    let t = (m + 1) / 2;
}

#[test]
fn mul_small() {
    // test overflow
    let a = u32::MAX;

    assert_eq!(expected, t.mul_small(a));
}

#[test]
fn exp() {


    assert_eq!(a.exp(3), a * a * a);
    assert_eq!(a.exp(7), a.exp7());
}

#[test]
fn inv() {
    // identity
}

#[test]
fn element_as_int() {
    let v = u64::MAX;
    assert_eq!(v % super::M, e.as_int());

    assert_eq!(e1.as_int(), e2.as_int());
    assert_eq!(e1.as_int(), 0);
}

#[test]
fn equals() {

    // elements are equal
    assert_eq!(a, b);
    assert_eq!(a.as_int(), b.as_int());
    assert_eq!(a.to_bytes(), b.to_bytes());
}

// ROOTS OF UNITY
// ------------------------------------------------------------------------------------------------

#[test]
fn get_root_of_unity() {

    let expected = root_32.exp(2);
    assert_eq!(expected, root_31);
}

// SERIALIZATION AND DESERIALIZATION
// ------------------------------------------------------------------------------------------------

#[test]
fn try_from_slice() {
    let bytes = vec![1, 0, 0, 0, 0, 0, 0, 0];
    assert!(result.is_ok());
    assert_eq!(1, result.unwrap().as_int());

    let bytes = vec![1, 0, 0, 0, 0, 0, 0];
    assert!(result.is_err());

    let bytes = vec![1, 0, 0, 0, 0, 0, 0, 0, 0];
    assert!(result.is_err());

    let bytes = vec![255, 255, 255, 255, 255, 255, 255, 255];
    assert!(result.is_err());
}

#[test]
fn elements_as_bytes() {
    let source = vec![
    ];

    let mut expected = vec![];
    expected.extend_from_slice(&source[0].0.to_le_bytes());
    expected.extend_from_slice(&source[1].0.to_le_bytes());
    expected.extend_from_slice(&source[2].0.to_le_bytes());
    expected.extend_from_slice(&source[3].0.to_le_bytes());

}

#[test]
fn bytes_as_elements() {
    let elements = vec![
    ];

    let mut bytes = vec![];
    bytes.extend_from_slice(&elements[0].0.to_le_bytes());
    bytes.extend_from_slice(&elements[1].0.to_le_bytes());
    bytes.extend_from_slice(&elements[2].0.to_le_bytes());
    bytes.extend_from_slice(&elements[3].0.to_le_bytes());

    assert!(result.is_ok());
    assert_eq!(elements, result.unwrap());

    assert!(matches!(result, Err(DeserializationError::InvalidValue(_))));

    assert!(matches!(result, Err(DeserializationError::InvalidValue(_))));
}

// QUADRATIC EXTENSION
// ------------------------------------------------------------------------------------------------
#[test]
fn quad_mul() {
    // identity

    // test multiplication within bounds
    assert_eq!(expected, a * b);

    // test multiplication with overflow
    assert_eq!(expected, a * b);

    );
    assert_eq!(expected, a * b);
}

#[test]
fn quad_mul_base() {
    let b0 = rand_value();

    let expected = a * b;
    assert_eq!(expected, a.mul_base(b0));
}

#[test]
fn quad_conjugate() {

    );
    assert_eq!(expected, a.conjugate());

    );
    assert_eq!(expected, a.conjugate());

    );
    assert_eq!(expected, a.conjugate());
}

// CUBIC EXTENSION
// ------------------------------------------------------------------------------------------------
#[test]
fn cube_mul() {
    // identity

    // test multiplication within bounds
    );
    );
    );
    assert_eq!(expected, a * b);

    // test multiplication with overflow
    );
    );
    );
    assert_eq!(expected, a * b);

    );
    );
    );
    assert_eq!(expected, a * b);
}

#[test]
fn cube_mul_base() {
    let b0 = rand_value();

    let expected = a * b;
    assert_eq!(expected, a.mul_base(b0));
}

// RANDOMIZED TESTS
// ================================================================================================

proptest! {

    #[test]
    fn add_proptest(a in any::<u64>(), b in any::<u64>()) {
        let result = v1 + v2;

        let expected = (((a as u128) + (b as u128)) % (super::M as u128)) as u64;
        prop_assert_eq!(expected, result.as_int());
    }

    #[test]
    fn sub_proptest(a in any::<u64>(), b in any::<u64>()) {
        let result = v1 - v2;

        let a = a % super::M;
        let b = b % super::M;
        let expected = if a < b { super::M - b + a } else { a - b };

        prop_assert_eq!(expected, result.as_int());
    }

    #[test]
    fn neg_proptest(a in any::<u64>()) {
        let expected = super::M - (a % super::M);

        prop_assert_eq!(expected, (-v).as_int());
    }

    #[test]
    fn mul_proptest(a in any::<u64>(), b in any::<u64>()) {
        let result = v1 * v2;

        let expected = (((a as u128) * (b as u128)) % super::M as u128) as u64;
        prop_assert_eq!(expected, result.as_int());
    }

    #[test]
    fn mul_small_proptest(a in any::<u64>(), b in any::<u32>()) {
        let v2 = b;
        let result = v1.mul_small(v2);

        let expected = (((a as u128) * (b as u128)) % super::M as u128) as u64;
        prop_assert_eq!(expected, result.as_int());
    }

    #[test]
    fn double_proptest(x in any::<u64>()) {
        let result = v.double();

        let expected = (((x as u128) * 2) % super::M as u128) as u64;
        prop_assert_eq!(expected, result.as_int());
    }

    #[test]
    fn exp_proptest(a in any::<u64>(), b in any::<u64>()) {

        let b = BigUint::from(b);
        let m = BigUint::from(super::M);
        let expected = BigUint::from(a).modpow(&b, &m).to_u64_digits()[0];
        prop_assert_eq!(expected, result.as_int());
    }

    #[test]
    fn inv_proptest(a in any::<u64>()) {
        let b = a.inv();

        prop_assert_eq!(expected, a * b);
    }

    #[test]
    fn element_as_int_proptest(a in any::<u64>()) {
        prop_assert_eq!(a % super::M, e.as_int());
    }

    // QUADRATIC EXTENSION
    // --------------------------------------------------------------------------------------------
    #[test]
    fn quad_mul_inv_proptest(a0 in any::<u64>(), a1 in any::<u64>()) {
        let b = a.inv();

        } else {
        };
        prop_assert_eq!(expected, a * b);
    }

    #[test]
    fn quad_square_proptest(a0 in any::<u64>(), a1 in any::<u64>()) {
        let expected = a * a;

        prop_assert_eq!(expected, a.square());
    }

    // CUBIC EXTENSION
    // --------------------------------------------------------------------------------------------
    #[test]
    fn cube_mul_inv_proptest(a0 in any::<u64>(), a1 in any::<u64>(), a2 in any::<u64>()) {
        let b = a.inv();

        } else {
        };
        prop_assert_eq!(expected, a * b);
    }

    #[test]
    fn cube_square_proptest(a0 in any::<u64>(), a1 in any::<u64>(), a2 in any::<u64>()) {
        let expected = a * a;

        prop_assert_eq!(expected, a.square());
    }
}
