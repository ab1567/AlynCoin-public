use core::fmt::Debug;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use alyn_math::StarkField;
use crate::evaluation_frame::EvaluationFrame;
use crate::context::TraceInfo;

#[derive(Debug, Clone, Serialize, Eq, PartialEq)]
pub struct BoundaryConstraint<E>
where
    E: StarkField + Debug + Serialize + Eq,
{
    pub value: E,
}

impl<'de, E> Deserialize<'de> for BoundaryConstraint<E>
where
    E: StarkField + Debug + Serialize + DeserializeOwned + Eq,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper<E> {
            value: E,
        }

        let helper = Helper::deserialize(deserializer)?;
        Ok(BoundaryConstraint { value: helper.value })
    }
}

// ---------------------------------------
// Air trait definition
// ---------------------------------------

pub trait Air: Clone + Debug + Send + Sync + Serialize + for<'de> Deserialize<'de> {
    type BaseField: StarkField + Debug + Serialize + for<'de> Deserialize<'de>;
    type PublicInputs: Clone + Debug + PartialEq + Serialize + for<'de> Deserialize<'de>;

    fn new(trace_info: TraceInfo<Self::BaseField>, pub_inputs: Self::PublicInputs) -> Self;

    fn context(&self) -> &TraceInfo<Self::BaseField>;

    fn evaluate_transition<E: StarkField + Debug>(
        &self,
        frame: &EvaluationFrame<E>,
        periodic_values: &[E],
        result: &mut [E],
    );

    fn get_pub_inputs(&self) -> &Self::PublicInputs;
}
