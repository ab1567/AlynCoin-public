// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.


use rand_utils::{rand_value, rand_vector};


// SINGLE ASSERTIONS
// ================================================================================================
#[test]
fn single_assertion() {
    assert_eq!(2, a.column);
    assert_eq!(8, a.first_step);
    assert_eq!(vec![value], a.values);
    assert_eq!(0, a.stride);
    assert_eq!(1, a.get_num_steps(16));
    assert_eq!(1, a.get_num_steps(32));

    a.apply(16, |step, val| {
        assert_eq!(8, step);
        assert_eq!(value, val);
    });

    assert_eq!(Ok(()), a.validate_trace_width(3));

    assert_eq!(Ok(()), a.validate_trace_length(16));
}

// PERIODIC ASSERTIONS
// ================================================================================================

#[test]
fn periodic_assertion() {
    assert_eq!(4, a.column);
    assert_eq!(1, a.first_step);
    assert_eq!(vec![value], a.values);
    assert_eq!(16, a.stride);
    assert_eq!(1, a.get_num_steps(16));
    assert_eq!(2, a.get_num_steps(32));

    a.apply(16, |step, val| {
        assert_eq!(1, step);
        assert_eq!(value, val);
    });
    a.apply(32, |step, val| {
        if step == 1 || step == 17 {
            assert_eq!(value, val);
            return;
        }
        unreachable!();
    });

    assert_eq!(Ok(()), a.validate_trace_width(5));
    assert_eq!(Ok(()), a.validate_trace_length(16));
}

#[test]
#[should_panic(
    expected = "invalid assertion for column 0: stride must be a power of two, but was 3"
)]
fn periodic_assertion_stride_not_power_of_two() {
}

#[test]
#[should_panic(expected = "invalid assertion for column 0: stride must be at least 2, but was 1")]
fn periodic_assertion_stride_too_small() {
}

#[test]
#[should_panic(
    expected = "invalid assertion for column 0: first step must be smaller than stride (4 steps), but was 5"
)]
fn periodic_assertion_first_step_greater_than_stride() {
}

#[test]
#[should_panic(
    expected = "invalid trace length: expected trace length to be at least 8, but was 4"
)]
fn periodic_assertion_get_num_steps_error() {
    let _ = a.get_num_steps(4);
}

// SEQUENCE ASSERTIONS
// ================================================================================================

#[test]
fn sequence_assertion() {
    assert_eq!(3, a.column);
    assert_eq!(2, a.first_step);
    assert_eq!(values, a.values);
    assert_eq!(4, a.stride);
    assert_eq!(2, a.get_num_steps(8));

    a.apply(8, |step, val| {
        if step == 2 {
            assert_eq!(values[0], val);
            return;
        } else if step == 6 {
            assert_eq!(values[1], val);
            return;
        }
        unreachable!();
    });

    assert_eq!(Ok(()), a.validate_trace_length(8));

    assert_eq!(Ok(()), a.validate_trace_width(4));
}

#[test]
#[should_panic(
    expected = "invalid assertion for column 3: stride must be a power of two, but was 5"
)]
fn sequence_assertion_stride_not_power_of_two() {
}

#[test]
#[should_panic(expected = "invalid assertion for column 3: stride must be at least 2, but was 1")]
fn sequence_assertion_stride_too_small() {
}

#[test]
#[should_panic(
    expected = "invalid assertion for column 3: first step must be smaller than stride (4 steps), but was 5"
)]
fn sequence_assertion_first_step_greater_than_stride() {
}

#[test]
#[should_panic(expected = "invalid trace length: expected trace length to be exactly 8, but was 4")]
fn sequence_assertion_inconsistent_trace() {
    let _ = a.get_num_steps(4);
}

#[test]
#[should_panic(
    expected = "invalid assertion for column 3: number of asserted values must be greater than zero"
)]
fn sequence_assertion_empty_values() {
}

#[test]
#[should_panic(
    expected = "invalid assertion for column 3: number of asserted values must be a power of two, but was 3"
)]
fn sequence_assertion_num_values_not_power_of_two() {
    let _ =
}

// OVERLAPPING ASSERTIONS
// ================================================================================================

#[test]
fn assertion_overlap() {
    // ----- single-single overlap ----------------------------------------------------------------

    assert!(a.overlaps_with(&b));

    // different columns: no overlap
    assert!(!a.overlaps_with(&b));

    // different steps: no overlap
    assert!(!a.overlaps_with(&b));

    // ----- single-periodic overlap --------------------------------------------------------------

    assert!(a.overlaps_with(&b));
    assert!(b.overlaps_with(&a));

    assert!(a.overlaps_with(&b));
    assert!(b.overlaps_with(&a));

    assert!(a.overlaps_with(&b));
    assert!(b.overlaps_with(&a));

    // different columns: no overlap
    assert!(!a.overlaps_with(&b));
    assert!(!b.overlaps_with(&a));

    // different steps: no overlap
    assert!(!a.overlaps_with(&b));
    assert!(!b.overlaps_with(&a));

    // ----- single-sequence overlap --------------------------------------------------------------

    assert!(a.overlaps_with(&b));
    assert!(b.overlaps_with(&a));

    assert!(a.overlaps_with(&b));
    assert!(b.overlaps_with(&a));

    assert!(a.overlaps_with(&b));
    assert!(b.overlaps_with(&a));

    // different columns: no overlap
    assert!(!a.overlaps_with(&b));
    assert!(!b.overlaps_with(&a));

    // different steps: no overlap
    assert!(!a.overlaps_with(&b));
    assert!(!b.overlaps_with(&a));

    // ----- periodic-periodic overlap ------------------------------------------------------------

    assert!(a.overlaps_with(&b));
    assert!(b.overlaps_with(&a));

    assert!(a.overlaps_with(&b));
    assert!(b.overlaps_with(&a));

    assert!(a.overlaps_with(&b));
    assert!(b.overlaps_with(&a));

    // different columns: no overlap
    assert!(!a.overlaps_with(&b));
    assert!(!b.overlaps_with(&a));

    // different first step: no overlap
    assert!(!a.overlaps_with(&b));
    assert!(!b.overlaps_with(&a));

    // different first step and bigger stride: no overlap
    assert!(!a.overlaps_with(&b));
    assert!(!b.overlaps_with(&a));

    // ----- sequence-sequence overlap ------------------------------------------------------------


    assert!(a.overlaps_with(&b));
    assert!(b.overlaps_with(&a));

    assert!(a.overlaps_with(&b));
    assert!(b.overlaps_with(&a));

    assert!(a.overlaps_with(&b));
    assert!(b.overlaps_with(&a));

    // different columns: no overlap
    assert!(!a.overlaps_with(&b));
    assert!(!b.overlaps_with(&a));

    // different first step: no overlap
    assert!(!a.overlaps_with(&b));
    assert!(!b.overlaps_with(&a));

    // different first step and bigger stride: no overlap
    assert!(!a.overlaps_with(&b));
    assert!(!b.overlaps_with(&a));

    // ----- sequence-periodic overlap ------------------------------------------------------------


    assert!(a.overlaps_with(&b));
    assert!(b.overlaps_with(&a));

    assert!(a.overlaps_with(&b));
    assert!(b.overlaps_with(&a));

    assert!(a.overlaps_with(&b));
    assert!(b.overlaps_with(&a));

    // different columns: no overlap
    assert!(!a.overlaps_with(&b));
    assert!(!b.overlaps_with(&a));

    // different first step: no overlap
    assert!(!a.overlaps_with(&b));
    assert!(!b.overlaps_with(&a));

    // different first step and bigger stride: no overlap
    assert!(!a.overlaps_with(&b));
    assert!(!b.overlaps_with(&a));
}
