#![no_std]
#[allow(unused_variables)]

#[macro_use]
extern crate alloc;

use alloc::vec::Vec;
use alloc::string::String;
use core::{fmt::Debug, ptr};
use core::ffi::c_char;
use alloc::ffi::CString;

// Serde
use serde::{Serialize, Deserialize};
use serde::de::DeserializeOwned;

// Alyn crates
use alyn_air::{Air, EvaluationFrame, TraceInfo};
use alyn_math::StarkField;
use alyn_prover::{
    air_prover::AirProver,
    trace::TraceTable,
    proof::{StarkProof, ProofOptions, ProverError},
};
use alyn_crypto::{
    ElementDigest,
    hash::Hasher,
    digest::Digest,
};

// -----------------------------------------------------------------------------
// Public Inputs and AIR
// -----------------------------------------------------------------------------
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(bound(
    serialize = "E: StarkField + Debug + Serialize + 'static",
    deserialize = "E: StarkField + Debug + DeserializeOwned + 'static"
))]
pub struct PublicInputs<E>
where
    E: StarkField + Debug + Serialize + Send + Sync + 'static,
{
    pub initial_value: E,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(bound(
    serialize = "E: StarkField + Debug + Serialize + 'static",
    deserialize = "E: StarkField + Debug + DeserializeOwned + 'static"
))]
pub struct BlockAir<E>
where
    E: StarkField + Debug + Serialize + Send + Sync + 'static,
{
    trace_info: TraceInfo<E>,
    pub_inputs: PublicInputs<E>,
}

impl<E> Air for BlockAir<E>
where
    E: StarkField + Debug + Serialize + DeserializeOwned + Send + Sync + 'static,
{
    type BaseField = E;
    type PublicInputs = PublicInputs<E>;

    fn new(trace_info: TraceInfo<E>, pub_inputs: Self::PublicInputs) -> Self {
        Self { trace_info, pub_inputs }
    }

    fn context(&self) -> &TraceInfo<E> {
        &self.trace_info
    }

    fn evaluate_transition<F: StarkField + Debug>(
        &self,
        frame: &EvaluationFrame<F>,
        _periodic_values: &[F],
        result: &mut [F],
    ) {
        for (i, val) in frame.current.iter().enumerate() {
            result[i] = val.square();
        }
    }

    fn get_pub_inputs(&self) -> &Self::PublicInputs {
        &self.pub_inputs
    }
}

// -----------------------------------------------------------------------------
// Custom Dummy Hasher (Replace with BLAKE3 + Digest later)
// -----------------------------------------------------------------------------
pub struct Blake3_256<E>(core::marker::PhantomData<E>);

impl<E> Hasher for Blake3_256<E>
where
    E: StarkField + Debug + Serialize + DeserializeOwned + Send + Sync + 'static,
{
    type BaseField = E;
    type Digest = ElementDigest;

    fn hash(bytes: &[u8]) -> Self::Digest {
        let _hash_out = blake3::hash(bytes);
        ElementDigest::new(Vec::new())
    }

    fn merge(values: &[Self::Digest; 2]) -> Self::Digest {
        let mut combined = Vec::new();
        combined.extend_from_slice(&values[0].as_bytes()[..]);
        combined.extend_from_slice(&values[1].as_bytes()[..]);
        ElementDigest::new(combined)
    }

    fn merge_many(values: &[Self::Digest]) -> Self::Digest {
        let mut combined = Vec::new();
        for v in values {
            combined.extend_from_slice(&v.as_bytes()[..]);
        }
        ElementDigest::new(combined)
    }

    fn merge_with_int(value: Self::Digest, _int: u64) -> Self::Digest {
        let new_bytes = value.as_bytes();
        ElementDigest::new(new_bytes)
    }

    fn hash_elements<F2: StarkField + Serialize>(elements: &[F2]) -> Self::Digest {
        let _ = elements;
        ElementDigest::new(Vec::new())
    }
}

// -----------------------------------------------------------------------------
// Basic Trace Generator
// -----------------------------------------------------------------------------
pub fn build_trace<E>(init_val: E, length: usize) -> TraceTable<E>
where
    E: StarkField + Debug + Serialize,
{
    let mut trace = TraceTable::default();
    trace.add_column(vec![init_val; length]);
    trace
}

// -----------------------------------------------------------------------------
// STARK Proof Generator (not wired to FFI yet)
// -----------------------------------------------------------------------------
pub fn generate_proof<E>(
    options: ProofOptions,
    trace: TraceTable<E>,
    pub_inputs: PublicInputs<E>,
) -> Result<StarkProof<E, Blake3_256<E>>, ProverError>
where
    E: StarkField + Debug + Serialize + DeserializeOwned + Send + Sync + 'static,
{
    let prover = AirProver::<BlockAir<E>>::new(trace);
    let proof = prover.prove::<Blake3_256<E>>(options, pub_inputs)?;
    Ok(proof)
}

// -----------------------------------------------------------------------------
// FFI / C ABI STUBS (linked to C++)
// -----------------------------------------------------------------------------

#[no_mangle]
pub extern "C" fn generate_proof_c(_seed: *const u8, _seed_len: usize) -> *mut u8 {
    ptr::null_mut() // Placeholder: not used
}

#[no_mangle]
pub extern "C" fn verify_proof(_proof: *const u8, _seed: *const u8, _result: *const u8) -> bool {
    true // Always succeeds for now
}

#[no_mangle]
pub extern "C" fn generate_proof_bytes(seed_ptr: *const u8, seed_len: usize) -> *mut c_char {
    if seed_ptr.is_null() || seed_len == 0 {
        return ptr::null_mut();
    }

    let seed_slice = unsafe { core::slice::from_raw_parts(seed_ptr, seed_len) };
    let seed_str = String::from_utf8_lossy(seed_slice);

    let dummy_proof = format!("zk-proof:{}", seed_str);

    match CString::new(dummy_proof) {
        Ok(c_string) => c_string.into_raw(),
        Err(_) => ptr::null_mut(),
    }
}
