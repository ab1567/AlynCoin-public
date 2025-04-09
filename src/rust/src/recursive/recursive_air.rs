use alyn_air::{Air, EvaluationFrame, TraceInfo};
use alyn_math::StarkField;
use serde::{Serialize, Deserialize};
use serde::de::DeserializeOwned;
use core::fmt::Debug;

// --------------------------------------
// RecursivePublicInputs<E>
// --------------------------------------
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(bound(deserialize = "E: StarkField + DeserializeOwned + Debug + Send + Sync + 'static + PartialEq"))]
pub struct RecursivePublicInputs<E>
where
    E: StarkField + Debug + Serialize + DeserializeOwned + Send + Sync + 'static + PartialEq,
{
    pub expected_hash: E,
}

// --------------------------------------
// RecursiveAIR<E>
// --------------------------------------
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(bound(deserialize = "E: StarkField + DeserializeOwned + Debug + Send + Sync + 'static + PartialEq"))]
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

    // Simple difference check for demonstration
    fn evaluate_transition<F: StarkField + Debug>(
        &self,
        frame: &EvaluationFrame<F>,
        _periodic_values: &[F],
        result: &mut [F],
    ) {
        // For example: result[0] = F(current[0]) - F(current[1])
        result[0] = frame.current[0] - frame.current[1];
    }

    fn get_pub_inputs(&self) -> &Self::PublicInputs {
        &self.pub_inputs
    }
}
