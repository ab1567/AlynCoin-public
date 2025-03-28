// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.



use crate::{tests::build_fib_trace, Trace};

#[test]
fn new_trace_table() {
    let trace_length = 8;
    let trace = build_fib_trace(trace_length * 2);

    assert_eq!(2, trace.main_trace_width());
    assert_eq!(8, trace.length());

        .into_iter()
        .collect();
    assert_eq!(expected, trace.get_column(0));

        .into_iter()
        .collect();
    assert_eq!(expected, trace.get_column(1));
}
