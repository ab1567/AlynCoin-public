use crate::trace::TraceTable;
use crate::constraint_commitment::DefaultConstraintCommitment;
use alyn_air::{Air, EvaluationFrame};
use alyn_crypto::hash::Hasher;
use crate::trace_lde::{DefaultTraceLde, RowMatrix};
use crate::proof::{StarkProof, ProofOptions, ProverError};
use alloc::vec::Vec;
use alyn_math::StarkField;

pub struct AirProver<A: Air> {
    trace: TraceTable<A::BaseField>,
}

impl<A: Air> AirProver<A> {
    pub fn new(trace: TraceTable<A::BaseField>) -> Self {
        Self { trace }
    }

    pub fn prove<H: Hasher<BaseField = A::BaseField>>(
        &self,
        _options: ProofOptions,
        pub_inputs: A::PublicInputs,
    ) -> Result<StarkProof<A::BaseField, H>, ProverError> {
        let air = A::new(self.trace.get_info(), pub_inputs.clone());

        let length = self.trace.table[0].len();
        let mut constraints = Vec::new();

        for i in 0..(length - 1) {
            let frame = EvaluationFrame {
                current: self.trace.table.iter().map(|col| col[i]).collect(),
                next: self.trace.table.iter().map(|col| col[i + 1]).collect(),
            };

            let mut result = vec![A::BaseField::ZERO; 16];
            air.evaluate_transition(&frame, &[], &mut result);
            constraints.push(result);
        }

        let dummy_digest = H::hash(b"dummy-commitment");

        Ok(StarkProof {
            commitments: vec![dummy_digest],
            constraint_commitment: DefaultConstraintCommitment::new(b"dummy-cc".to_vec()),
            trace_lde: DefaultTraceLde {
                lde_matrix: RowMatrix {
                    data: self.trace.table.clone(),
                },
            },
        })
    }
}
