use core::fmt::Debug;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use alyn_math::StarkField;

#[derive(Debug, Clone, Serialize, Eq, PartialEq)]
pub struct RandomCoin<E>
where
    E: StarkField + Debug + Serialize + Eq,
{
    pub seed: E,
}

// Deserialize impl moved outside
impl<'de, E> Deserialize<'de> for RandomCoin<E>
where
    E: StarkField + Debug + Serialize + DeserializeOwned + Eq,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper<E> {
            seed: E,
        }

        let helper = Helper::deserialize(deserializer)?;
        Ok(RandomCoin { seed: helper.seed })
    }
}
