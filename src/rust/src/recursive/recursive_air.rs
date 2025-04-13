extern crate alloc;

use alloc::vec::Vec;
use core::fmt::Debug;
use alyn_air::{Air, EvaluationFrame, TraceInfo};
use alyn_math::StarkField;
use serde::{Deserialize, Serialize};
use serde::de::DeserializeOwned;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(bound(
    deserialize = "E: StarkField + Debug + Serialize + DeserializeOwned + Send + Sync + 'static + PartialEq"
))]
pub struct RecursivePublicInputs<E>
where
    E: StarkField + Debug + Serialize + DeserializeOwned + Send + Sync + 'static + PartialEq,
{
    pub expected_hash: Vec<E>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(bound(
    deserialize = "E: StarkField + Debug + Serialize + DeserializeOwned + Send + Sync + 'static + PartialEq"
))]
pub struct RecursiveAIR<E>
where
    E: StarkField + Debug + Serialize + DeserializeOwned + Send + Sync + 'static + PartialEq,
{
    trace_info: TraceInfo<E>,
    pub_inputs: RecursivePublicInputs<E>,
}

impl<E> Air for RecursiveAIR<E>
where
    E: StarkField + Debug + Serialize + DeserializeOwned + Send + Sync + 'static + PartialEq,
{
    type BaseField = E;
    type PublicInputs = RecursivePublicInputs<E>;

    fn new(trace_info: TraceInfo<E>, pub_inputs: Self::PublicInputs) -> Self {
        Self { trace_info, pub_inputs }
    }

    fn context(&self) -> &TraceInfo<E> {
        &self.trace_info
    }

    fn evaluate_transition<F: StarkField + Debug>(
        &self,
        frame: &EvaluationFrame<F>,
        _periodic_values: &[F],
        result: &mut [F],
    ) {
        let current = &frame.current;
        let next = &frame.next;

        result[0] = next[0] - (current[0] + F::from_u64(1));
        result[1] = next[1] - (current[1] * current[0]);
        result[2] = next[2] - (current[2] + current[1]);
        result[3] = next[3] - (current[3] * F::from_u64(2));

        result[4] = if let Some(expected) = self.pub_inputs.expected_hash.get(0) {
            current[0] - F::from_u64(expected.as_int())
        } else {
            F::ZERO
        };

        for i in 5..result.len() {
            result[i] = F::ZERO;
        }
    }

    fn get_pub_inputs(&self) -> &Self::PublicInputs {
        &self.pub_inputs
    }
}
