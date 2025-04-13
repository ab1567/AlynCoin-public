extern crate alloc;

use alyn_math::StarkField;
use alloc::vec::Vec;
use alloc::string::String;
use core::fmt::Write;
use alyn_math::fields::f64::BaseElement;
use alyn_prover::trace::TraceTable;
use alyn_prover::air_prover::AirProver;
use alyn_prover::proof::ProofOptions;
use alyn_air::Air;
use crate::Blake3_256;
use crate::recursive::recursive_air::{RecursiveAIR, RecursivePublicInputs};

fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        write!(s, "{:02x}", b).unwrap();
    }
    s
}

pub fn generate_trace_from_inner_proof(inner_proof_bytes: &[u8]) -> TraceTable<BaseElement> {
    let mut trace = TraceTable::default();

    let mut col0 = Vec::new();
    let mut col1 = Vec::new();
    let mut col2 = Vec::new();
    let mut col3 = Vec::new();

    let mut state = [BaseElement::ZERO; 4];
    let entropy = BaseElement::new(inner_proof_bytes.len() as u64);

    for (i, &b) in inner_proof_bytes.iter().enumerate() {
        let val = BaseElement::new(b as u64);
        let index = BaseElement::new(i as u64);

        let s0 = state[0] + val + index + entropy;
        let s1 = state[1] * val + entropy + BaseElement::new((i * 3 % 251) as u64);
        let s2 = state[2] + s0 * s1 + BaseElement::new((i * 7 % 251) as u64);
        let s3 = s2 * BaseElement::new((b as u64).wrapping_add(17)) + state[3];

        state = [s0, s1, s2, s3];

        col0.push(s0);
        col1.push(s1);
        col2.push(s2);
        col3.push(s3);
    }

    while col0.len() < 128 {
        let i = col0.len() as u64;
        let val = BaseElement::new((i * 13 % 251) as u64);
        let index = BaseElement::new(i);
        let s0 = state[0] + val + index + entropy;
        let s1 = state[1] * val + entropy;
        let s2 = state[2] + s0 * s1 + BaseElement::new(i % 17);
        let s3 = state[3] * s2 + entropy;

        state = [s0, s1, s2, s3];

        col0.push(s0);
        col1.push(s1);
        col2.push(s2);
        col3.push(s3);
    }

    trace.add_column(col0);
    trace.add_column(col1);
    trace.add_column(col2);
    trace.add_column(col3);
    trace
}

pub fn compose_recursive_proof(
    inner_proof_bytes: &[u8],
    address_hash: [u8; 32],
) -> Vec<u8> {
    let trace = generate_trace_from_inner_proof(inner_proof_bytes);
    let expected_hash: Vec<BaseElement> = address_hash
        .iter()
        .map(|b| BaseElement::new(*b as u64))
        .collect();

    let pub_inputs = RecursivePublicInputs { expected_hash };
    let air = RecursiveAIR::new(trace.get_info(), pub_inputs);
    let prover = AirProver::<RecursiveAIR<BaseElement>>::new(trace);

    let options = ProofOptions {
        num_queries: 256,
        blowup_factor: 32,
        grinding_factor: 8,
        fri_folding_factor: 4,
        fri_max_remainder_size: 256,
    };

    match prover.prove::<Blake3_256<BaseElement>>(options, air.get_pub_inputs().clone()) {
        Ok(proof) => {
            match postcard::to_allocvec(&proof) {
                Ok(serialized) => {
                    if serialized.len() < 64 {
                        let msg = format!("proof-error: too-small-proof (len={})", serialized.len());
                        return msg.into_bytes();
                    }
                    to_hex(&serialized).into_bytes()
                }
                Err(e) => {
                    let msg = format!("serialization-error: {}", e);
                    msg.into_bytes()
                }
            }
        }
        Err(e) => {
            let msg = format!("proof-error: {:?}", e);
            msg.into_bytes()
        }
    }
}
