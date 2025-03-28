extern crate alloc;
use alloc::vec::Vec;
use core::fmt::Debug;

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use alyn_math::StarkField;

// Existing definitions (unchanged).
#[derive(Debug, Clone, Serialize, Eq, PartialEq)]
pub struct TraceInfo<E>
where
    E: StarkField + Debug + Serialize + Eq,
{
    pub meta: Option<Vec<E>>,
}

impl<'de, E> Deserialize<'de> for TraceInfo<E>
where
    E: StarkField + Debug + Serialize + DeserializeOwned + Eq,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper<E> {
            meta: Option<Vec<E>>,
        }
        let helper = Helper::deserialize(deserializer)?;
        Ok(TraceInfo { meta: helper.meta })
    }
}

#[derive(Debug, Clone, Serialize, Eq, PartialEq)]
pub struct ConstraintCompositionCoefficients<E>
where
    E: StarkField + Debug + Serialize + Eq,
{
    pub coefficients: Vec<E>,
}

impl<'de, E> Deserialize<'de> for ConstraintCompositionCoefficients<E>
where
    E: StarkField + Debug + Serialize + DeserializeOwned + Eq,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper<E> {
            coefficients: Vec<E>,
        }
        let helper = Helper::deserialize(deserializer)?;
        Ok(ConstraintCompositionCoefficients {
            coefficients: helper.coefficients,
        })
    }
}

// -------------------------------------------------------------------------
// RE-ADD THE AirContext TYPE (since your code calls AirContext::new).
// -------------------------------------------------------------------------
#[derive(Debug, Clone, Serialize, Eq, PartialEq)]
pub struct AirContext<E>
where
    E: StarkField + Debug + Serialize + Eq,
{
    pub trace_info: TraceInfo<E>,
    /// For simplicity, store constraint degrees in a plain Vec<usize>.
    pub degrees: Vec<usize>,
    /// Example “blowup factor” or something similar.
    pub blowup_factor: usize,
}

impl<E> AirContext<E>
where
    E: StarkField + Debug + Serialize + Eq,
{
    pub fn new(trace_info: TraceInfo<E>, degrees: Vec<usize>, blowup_factor: usize) -> Self {
        AirContext {
            trace_info,
            degrees,
            blowup_factor,
        }
    }
}
