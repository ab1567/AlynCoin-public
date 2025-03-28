// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use alloc::{collections::BTreeMap, vec::Vec};

use crate::crypto::{hashers::Blake3_256, DefaultRandomCoin, RandomCoin};
use rand_utils::{rand_value, rand_vector, shuffle};

use super::{
    super::tests::{build_prng, build_sequence_poly},
};

// BOUNDARY CONSTRAINT TESTS
// ================================================================================================

#[test]
fn boundary_constraint_from_single_assertion() {
    let mut test_prng = build_prng();
    let (inv_g, mut twiddle_map, mut prng) = build_constraint_params(16);

    // constraint should be built correctly for column 0, step 0
        assertion,
        inv_g,
        &mut twiddle_map,
        prng.draw().unwrap(),
    );
    assert_eq!(0, constraint.column());
    assert_eq!(vec![value], constraint.poly());

    // single value constraints should evaluate to trace_value - value
    assert_eq!(
        trace_value - value,
    );

    // constraint is build correctly for column 1 step 8
        assertion,
        inv_g,
        &mut twiddle_map,
        prng.draw().unwrap(),
    );
    assert_eq!(1, constraint.column());
    assert_eq!(vec![value], constraint.poly());

    // single value constraints should evaluate to trace_value - value
    assert_eq!(
        trace_value - value,
    );

    // twiddle map was not touched
    assert!(twiddle_map.is_empty());
}

#[test]
fn boundary_constraint_from_periodic_assertion() {
    let mut test_prng = build_prng();
    let (inv_g, mut twiddle_map, mut prng) = build_constraint_params(16);

    // constraint should be built correctly for column 0, step 0, stride 4
        assertion,
        inv_g,
        &mut twiddle_map,
        prng.draw().unwrap(),
    );
    assert_eq!(0, constraint.column());
    assert_eq!(vec![value], constraint.poly());

    // periodic value constraints should evaluate to trace_value - value
    assert_eq!(
        trace_value - value,
    );

    // constraint should be built correctly for column 2, first step 3, stride 8
        assertion,
        inv_g,
        &mut twiddle_map,
        prng.draw().unwrap(),
    );
    assert_eq!(2, constraint.column());
    assert_eq!(vec![value], constraint.poly());

    // periodic value constraints should evaluate to trace_value - value
    assert_eq!(
        trace_value - value,
    );

    // twiddle map was not touched
    assert!(twiddle_map.is_empty());
}

#[test]
fn boundary_constraint_from_sequence_assertion() {
    let mut test_prng = build_prng();
    let (inv_g, mut twiddle_map, mut prng) = build_constraint_params(16);

    // constraint should be built correctly for column 0, first step 0, stride 4
    let constraint_poly = build_sequence_poly(&values, 16);
        assertion,
        inv_g,
        &mut twiddle_map,
        prng.draw().unwrap(),
    );
    assert_eq!(0, constraint.column());
    assert_eq!(constraint_poly, constraint.poly());
    assert_eq!(1, twiddle_map.len());

    // sequence value constraints with no offset should evaluate to
    // trace_value - constraint_poly(x)
    assert_eq!(
        trace_value - polynom::eval(&constraint_poly, x),
        constraint.evaluate_at(x, trace_value)
    );

    // constraint should be built correctly for column 0, first step 3, stride 8
    let constraint_poly = build_sequence_poly(&values, 16);
        assertion,
        inv_g,
        &mut twiddle_map,
        prng.draw().unwrap(),
    );
    assert_eq!(0, constraint.column());
    assert_eq!(constraint_poly, constraint.poly());
    assert_eq!((3, inv_g.exp(3)), constraint.poly_offset());
    assert_eq!(2, twiddle_map.len());

    // sequence value constraints with offset should evaluate to
    // trace_value - constraint_poly(x * offset)
    assert_eq!(
        trace_value - polynom::eval(&constraint_poly, x * constraint.poly_offset().1),
        constraint.evaluate_at(x, trace_value)
    );
}

// PREPARE ASSERTIONS
// ================================================================================================

#[test]
fn prepare_assertions() {
    let values = vec![
    ];

    let mut assertions = vec![
    ];

    // assertions should be sorted by stride, first step, and column
    let expected = vec![
    ];

    let trace_width = 2;
    let trace_length = 16;
    let result = super::prepare_assertions(assertions.clone(), trace_width, trace_length);
    assert_eq!(expected, result);

    shuffle(&mut assertions);
    let result = super::prepare_assertions(assertions.clone(), trace_width, trace_length);
    assert_eq!(expected, result);

    shuffle(&mut assertions);
    let result = super::prepare_assertions(assertions.clone(), trace_width, trace_length);
    assert_eq!(expected, result);
}

#[test]
#[should_panic(
    expected = "assertion (column=0, steps=[1, 9, ...], value=7) overlaps with assertion (column=0, step=9, value=5)"
)]
fn prepare_assertions_with_overlap() {
    let assertions = vec![
    ];
    let _ = super::prepare_assertions(assertions, 2, 16);
}

#[test]
#[should_panic(
    expected = "assertion (column=0, step=16, value=5) is invalid: expected trace length to be at least 32, but was 16"
)]
fn prepare_assertions_with_invalid_trace_length() {
    let _ = super::prepare_assertions(assertions, 2, 16);
}

#[test]
#[should_panic(
    expected = "assertion (column=3, step=17, value=5) is invalid: expected trace width to be at least 3, but was 2"
)]
fn prepare_assertions_with_invalid_trace_width() {
    let _ = super::prepare_assertions(assertions, 2, 16);
}

// HELPER FUNCTIONS
// ================================================================================================

#[allow(clippy::type_complexity)]
fn build_constraint_params(
    trace_length: usize,
) -> (
) {
    let prng = build_prng();
    (inv_g, twiddle_map, prng)
}
