use core::fmt::Debug;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use alyn_math::StarkField;

#[derive(Debug, Clone, Serialize, Eq, PartialEq)]
pub struct EvaluationFrame<E>
where
    E: StarkField + Debug + Serialize + Eq,
{
    pub current: Vec<E>,
}

impl<'de, E> Deserialize<'de> for EvaluationFrame<E>
where
    E: StarkField + Debug + Serialize + DeserializeOwned + Eq,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper<E> {
            current: Vec<E>,
        }

        let helper = Helper::deserialize(deserializer)?;
        Ok(EvaluationFrame { current: helper.current })
    }
}
