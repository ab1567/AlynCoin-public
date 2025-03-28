use core::fmt::Debug;
use serde::{Serialize, Deserialize, Deserializer};
use serde::de::DeserializeOwned;
use alloc::vec::Vec;
use alyn_math::StarkField;
use crate::transition_constraint::TransitionConstraint;

#[derive(Debug, Clone, Serialize, Eq, PartialEq)]
pub struct TransitionConstraintGroup<E>
where
    E: StarkField + Debug + Serialize + DeserializeOwned + Eq,
{
    pub constraints: Vec<TransitionConstraint<E>>,
}

// === Manual Deserialize Implementation ===
impl<'de, E> Deserialize<'de> for TransitionConstraintGroup<E>
where
    E: StarkField + Debug + Serialize + DeserializeOwned + Eq,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(bound = "E: StarkField + Debug + Serialize + DeserializeOwned + Eq")]
        struct Helper<E>
        where
            E: StarkField + Debug + Serialize + DeserializeOwned + Eq,
        {
            constraints: Vec<TransitionConstraint<E>>,
        }

        let helper = Helper::<E>::deserialize(deserializer)?;
        Ok(TransitionConstraintGroup {
            constraints: helper.constraints,
        })
    }
}

impl<E> TransitionConstraintGroup<E>
where
    E: StarkField + Debug + Serialize + DeserializeOwned + Eq,
{
    pub fn new(constraints: Vec<TransitionConstraint<E>>) -> Self {
        Self { constraints }
    }
}
