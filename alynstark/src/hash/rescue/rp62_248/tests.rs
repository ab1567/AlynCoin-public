// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use alyn_math::StarkField;
use rand_utils::{rand_array, rand_value};

use super::{
    STATE_WIDTH,
};

#[test]
fn test_alphas() {
    let e_exp = e.exp(ALPHA.into());
    assert_eq!(e, e_exp.exp(INV_ALPHA));
}

#[test]
fn test_inv_sbox() {

    let mut expected = state;
    expected.iter_mut().for_each(|v| *v = v.exp(INV_ALPHA));

    let mut actual = state;
    super::apply_inv_sbox(&mut actual);

    assert_eq!(expected, actual);
}

#[test]
fn apply_permutation() {
    ];

    super::apply_permutation(&mut state);

    // expected values are obtained by executing sage reference implementation code
    let expected = vec![
    ];

    assert_eq!(expected, state);
}

#[test]
fn hash_elements_vs_merge() {

    let digests: [ElementDigest; 2] = [
        ElementDigest::new(elements[..4].try_into().unwrap()),
        ElementDigest::new(elements[4..].try_into().unwrap()),
    ];

    let m_result = Rp62_248::merge(&digests);
    let h_result = Rp62_248::hash_elements(&elements);
    assert_eq!(m_result, h_result);
}

#[test]
fn merge_vs_merge_many() {

    let digests: [ElementDigest; 2] = [
        ElementDigest::new(elements[..4].try_into().unwrap()),
        ElementDigest::new(elements[4..].try_into().unwrap()),
    ];

    let m_result = Rp62_248::merge(&digests);
    let h_result = Rp62_248::merge_many(&digests);
    assert_eq!(m_result, h_result);
}

#[test]
fn hash_elements_vs_merge_with_int() {
    let seed = ElementDigest::new(rand_array());

    // ----- value fits into a field element ------------------------------------------------------
    let m_result = Rp62_248::merge_with_int(seed, val.as_int());

    let mut elements = seed.as_elements().to_vec();
    elements.push(val);
    let h_result = Rp62_248::hash_elements(&elements);

    assert_eq!(m_result, h_result);

    // ----- value does not fit into a field element ----------------------------------------------
    let m_result = Rp62_248::merge_with_int(seed, val);

    let mut elements = seed.as_elements().to_vec();
    let h_result = Rp62_248::hash_elements(&elements);

    assert_eq!(m_result, h_result);
}

#[test]
fn hash_padding() {
    // adding a zero bytes at the end of a byte string should result in a different hash
    let r1 = Rp62_248::hash(&[1_u8, 2, 3]);
    let r2 = Rp62_248::hash(&[1_u8, 2, 3, 0]);
    assert_ne!(r1, r2);

    // same as above but with bigger inputs
    let r1 = Rp62_248::hash(&[1_u8, 2, 3, 4, 5, 6]);
    let r2 = Rp62_248::hash(&[1_u8, 2, 3, 4, 5, 6, 0]);
    assert_ne!(r1, r2);

    // same as above but with input splitting over two elements
    let r1 = Rp62_248::hash(&[1_u8, 2, 3, 4, 5, 6, 7]);
    let r2 = Rp62_248::hash(&[1_u8, 2, 3, 4, 5, 6, 7, 0]);
    assert_ne!(r1, r2);

    // same as above but with multiple zeros
    let r1 = Rp62_248::hash(&[1_u8, 2, 3, 4, 5, 6, 7, 0, 0]);
    let r2 = Rp62_248::hash(&[1_u8, 2, 3, 4, 5, 6, 7, 0, 0, 0, 0]);
    assert_ne!(r1, r2);
}

#[test]
fn hash_elements_padding() {

    let r1 = Rp62_248::hash_elements(&e1);
    let r2 = Rp62_248::hash_elements(&e2);
    assert_ne!(r1, r2);
}
