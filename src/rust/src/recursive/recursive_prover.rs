use alloc::vec::Vec;
use alyn_math::fields::f64::BaseElement;
use alyn_prover::trace::TraceTable;
use crate::recursive::recursive_air::{RecursiveAIR, RecursivePublicInputs};
use alyn_prover::air_prover::AirProver;
use alyn_prover::proof::ProofOptions;
use crate::Blake3_256;
use alyn_air::Air;

pub fn generate_trace_from_inner_proof(inner_proof_bytes: &[u8]) -> TraceTable<BaseElement> {
    let values: Vec<BaseElement> = inner_proof_bytes
        .iter()
        .map(|b| BaseElement::new(*b as u64))
        .collect();

    let mut trace = TraceTable::default();
    trace.add_column(values);
    trace
}

pub fn compose_recursive_proof(inner_proof_bytes: &[u8], expected_hash: [u8; 32]) -> Vec<u8> {
    let trace = generate_trace_from_inner_proof(inner_proof_bytes);

    let field_hash = BaseElement::new(u64::from_le_bytes(expected_hash[..8].try_into().unwrap()));

    let air = RecursiveAIR::new(
        trace.get_info(),
        RecursivePublicInputs {
            expected_hash: field_hash,
        },
    );

    let prover = AirProver::<RecursiveAIR<BaseElement>>::new(trace);

    // ✅ Construct ProofOptions directly using struct syntax if `.new()` doesn't exist
    let options = ProofOptions {
        num_queries: 32,
        blowup_factor: 8,
        grinding_factor: 0,
        fri_folding_factor: 4,
        fri_max_remainder_size: 16,
    };

    let proof = prover.prove::<Blake3_256<BaseElement>>(options, air.get_pub_inputs().clone()).unwrap();

    postcard::to_allocvec(&proof).unwrap_or_default()
}
