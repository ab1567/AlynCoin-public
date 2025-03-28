use crate::trace::TraceTable;
use crate::constraint_commitment::DefaultConstraintCommitment;
use alyn_air::Air;
use alyn_crypto::hash::Hasher;
use crate::trace_lde::DefaultTraceLde;
use crate::proof::{StarkProof, ProofOptions, ProverError};

/// AirProver: holds a trace and a constraint commitment, can now .prove(...)
pub struct AirProver<A: Air> {
    _trace: TraceTable<A::BaseField>,              // ✅ renamed to suppress unused warning
    pub_commitment: DefaultConstraintCommitment,
}

impl<A: Air> AirProver<A> {
    /// Create a new AirProver from a trace
    pub fn new(trace: TraceTable<A::BaseField>) -> Self {
        Self {
            _trace: trace,                          // ✅ use _trace to match field name
            pub_commitment: Default::default(),
        }
    }

    /// "prove" method that uses a generic hasher `H: Hasher<BaseField = A::BaseField>`.
    /// For real usage, you would build the trace LDE, commit to constraints, etc.
    pub fn prove<H: Hasher<BaseField = A::BaseField>>(
        &self,
        _options: ProofOptions,
        _pub_inputs: A::PublicInputs,
    ) -> Result<StarkProof<A::BaseField, H>, ProverError> {
        // Stub: returns an empty proof with default trace LDE
        Ok(StarkProof {
            commitments: Vec::new(),
            constraint_commitment: self.pub_commitment.clone(),
            trace_lde: DefaultTraceLde::default(),
        })
    }
}
