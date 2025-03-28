use core::fmt::Debug;
use serde::{Serialize, Deserialize, Deserializer};
use serde::de::DeserializeOwned;
use alyn_math::StarkField;

#[derive(Debug, Clone, Serialize, Eq, PartialEq)]
pub struct TransitionConstraint<E>
where
    E: StarkField + Debug + Serialize + DeserializeOwned + Eq,
{
    pub index: usize,
    pub coefficient: E,
}

// === Manual Deserialize Implementation ===
impl<'de, E> Deserialize<'de> for TransitionConstraint<E>
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
            index: usize,
            coefficient: E,
        }

        let helper = Helper::<E>::deserialize(deserializer)?;
        Ok(TransitionConstraint {
            index: helper.index,
            coefficient: helper.coefficient,
        })
    }
}

impl<E> TransitionConstraint<E>
where
    E: StarkField + Debug + Serialize + DeserializeOwned + Eq,
{
    pub fn new(index: usize, coefficient: E) -> Self {
        Self { index, coefficient }
    }
}
