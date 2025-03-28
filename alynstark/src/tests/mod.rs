// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.


use crate::air::{
    crate::proof::TraceInfo, TransitionConstraintDegree,
};

use crate::TraceTable;

// FIBONACCI TRACE BUILDER
// ================================================================================================

    assert!(length.is_power_of_two(), "length must be a power of 2");


    for i in 0..(length / 2 - 1) {
        reg1.push(reg1[i] + reg2[i]);
    }

    TraceTable::init(vec![reg1, reg2])
}

// MOCK AIR
// ================================================================================================

pub struct MockAir {
}

impl MockAir {
    pub fn with_trace_length(trace_length: usize) -> Self {
        Self::new(
            crate::proof::TraceInfo::new(4, trace_length),
            (),
            crate::proof::ProofOptions::new(
                32,
                8,
                0,
                FieldExtension::None,
                4,
                31,
                BatchingMethod::Linear,
                BatchingMethod::Linear,
            ),
        )
    }

    pub fn with_periodic_columns(
        trace_length: usize,
    ) -> Self {
        let mut result = Self::new(
            crate::proof::TraceInfo::new(4, trace_length),
            (),
            crate::proof::ProofOptions::new(
                32,
                8,
                0,
                FieldExtension::None,
                4,
                31,
                BatchingMethod::Linear,
                BatchingMethod::Linear,
            ),
        );
        result.periodic_columns = column_values;
        result
    }

        let mut result = Self::new(
            crate::proof::TraceInfo::new(4, trace_length),
            (),
            crate::proof::ProofOptions::new(
                32,
                8,
                0,
                FieldExtension::None,
                4,
                31,
                BatchingMethod::Linear,
                BatchingMethod::Linear,
            ),
        );
        result.assertions = assertions;
        result
    }
}

impl Air for MockAir {
    type PublicInputs = ();

    fn new(trace_info: crate::proof::TraceInfo, _pub_inputs: (), _options: crate::proof::ProofOptions) -> Self {
        let context = build_context(trace_info, 8, 1);
        MockAir {
            context,
            assertions: Vec::new(),
            periodic_columns: Vec::new(),
        }
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }

        &self,
        _frame: &EvaluationFrame<E>,
        _periodic_values: &[E],
        _result: &mut [E],
    ) {
    }

        self.assertions.clone()
    }

    fn get_periodic_column_values(&self) -> Vec<Vec<Self::BaseField>> {
        self.periodic_columns.clone()
    }
}

// HELPER FUNCTIONS
// ================================================================================================

fn build_context<B: StarkField>(
    trace_info: crate::proof::TraceInfo,
    blowup_factor: usize,
    num_assertions: usize,
) -> AirContext<B> {
    let options = crate::proof::ProofOptions::new(
        32,
        blowup_factor,
        0,
        FieldExtension::None,
        4,
        31,
        BatchingMethod::Linear,
        BatchingMethod::Linear,
    );
    let t_degrees = vec![TransitionConstraintDegree::new(2)];
    AirContext::new(trace_info, t_degrees, num_assertions, options)
}
