#[macro_use]
extern crate alloc;

extern crate postcard;

use alloc::{boxed::Box, ffi::CString, string::String, vec::Vec};
use core::{fmt::Debug, ptr, ffi::c_char};

use serde::{Serialize, Deserialize};
use serde::de::DeserializeOwned;

use alyn_air::{Air, EvaluationFrame, TraceInfo};
use alyn_math::StarkField;
use alyn_prover::{
    air_prover::AirProver,
    trace::TraceTable,
    proof::{StarkProof, ProofOptions, ProverError},
};
use alyn_crypto::{ElementDigest, hash::Hasher, digest::Digest};

pub mod recursive;

// --------------------------------------
// PublicInputs<E>
// --------------------------------------
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(bound(deserialize = "E: StarkField + DeserializeOwned + Debug + Send + Sync + 'static"))]
pub struct PublicInputs<E>
where
    E: StarkField + Debug + Serialize + DeserializeOwned + Send + Sync + 'static,
{
    pub initial_value: E,
}

// --------------------------------------
// BlockAir<E>
// --------------------------------------
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(bound(deserialize = "E: StarkField + DeserializeOwned + Debug + Send + Sync + 'static"))]
pub struct BlockAir<E>
where
    E: StarkField + Debug + Serialize + DeserializeOwned + Send + Sync + 'static,
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
        // Example transition: Just squaring each current value
        for (i, val) in frame.current.iter().enumerate() {
            result[i] = val.square();
        }
    }

    fn get_pub_inputs(&self) -> &Self::PublicInputs {
        &self.pub_inputs
    }
}

// --------------------------------------
// Blake3_256<E> Hasher
// --------------------------------------
#[derive(Debug)]
pub struct Blake3_256<E>(core::marker::PhantomData<E>);

impl<E> Hasher for Blake3_256<E>
where
    E: StarkField + Debug + Serialize + DeserializeOwned + Send + Sync + 'static,
{
    type BaseField = E;
    type Digest = ElementDigest;

    fn hash(bytes: &[u8]) -> Self::Digest {
        let hash_out = blake3::hash(bytes);
        ElementDigest::new(hash_out.as_bytes().to_vec())
    }

    fn merge(values: &[Self::Digest; 2]) -> Self::Digest {
        let mut combined = Vec::new();
        combined.extend_from_slice(&values[0].as_bytes());
        combined.extend_from_slice(&values[1].as_bytes());
        let hash_out = blake3::hash(&combined);
        ElementDigest::new(hash_out.as_bytes().to_vec())
    }

    fn merge_many(values: &[Self::Digest]) -> Self::Digest {
        let mut combined = Vec::new();
        for v in values {
            combined.extend_from_slice(&v.as_bytes());
        }
        let hash_out = blake3::hash(&combined);
        ElementDigest::new(hash_out.as_bytes().to_vec())
    }

    fn merge_with_int(value: Self::Digest, int: u64) -> Self::Digest {
        let mut data = value.as_bytes().to_vec();
        data.extend_from_slice(&int.to_le_bytes());
        let hash_out = blake3::hash(&data);
        ElementDigest::new(hash_out.as_bytes().to_vec())
    }

    fn hash_elements<F2: StarkField + Serialize>(elements: &[F2]) -> Self::Digest {
        // We'll serialize them using postcard, then hash
        let serialized = postcard::to_allocvec(elements).unwrap_or_default();
        let hash_out = blake3::hash(&serialized);
        ElementDigest::new(hash_out.as_bytes().to_vec())
    }
}

// --------------------------------------
// Proof building
// --------------------------------------
pub fn build_trace<E>(init_val: E, length: usize) -> TraceTable<E>
where
    E: StarkField + Debug + Serialize,
{
    let mut trace = TraceTable::default();
    trace.add_column(vec![init_val; length]);
    trace
}

pub fn generate_proof<E>(
    options: ProofOptions,
    trace: TraceTable<E>,
    pub_inputs: PublicInputs<E>,
) -> Result<StarkProof<E, Blake3_256<E>>, ProverError>
where
    E: StarkField + Debug + Serialize + DeserializeOwned + Send + Sync + 'static,
{
    // Wrap up your trace + AIR to produce a STARK proof
    let prover = AirProver::<BlockAir<E>>::new(trace);
    prover.prove::<Blake3_256<E>>(options, pub_inputs)
}

// --------------------------------------
// FFI exports (C-ABI)
// --------------------------------------
#[no_mangle]
pub extern "C" fn generate_proof_bytes(seed_ptr: *const u8, seed_len: usize) -> *mut c_char {
    // Just a placeholder demonstration
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

#[no_mangle]
pub extern "C" fn verify_proof(_proof: *const u8, _seed: *const u8, _result: *const u8) -> bool {
    // Always returns true for demonstration
    true
}

#[repr(C)]
pub struct RecursiveProofResult {
   pub data: *mut u8,
   pub len: usize,
}

#[no_mangle]
pub extern "C" fn compose_recursive_proof(
    proof_ptr: *const u8,
    proof_len: usize,
    hash_ptr: *const u8,
) -> RecursiveProofResult {
    use crate::recursive::recursive_prover::compose_recursive_proof;

    if proof_ptr.is_null() || hash_ptr.is_null() || proof_len == 0 {
        return RecursiveProofResult {
            data: core::ptr::null_mut(),
            len: 0,
        };
    }

    let proof_slice = unsafe { core::slice::from_raw_parts(proof_ptr, proof_len) };
    let hash_slice = unsafe { core::slice::from_raw_parts(hash_ptr, 32) };

    let hash_array: [u8; 32] = match hash_slice.try_into() {
        Ok(arr) => arr,
        Err(_) => {
            return RecursiveProofResult {
                data: core::ptr::null_mut(),
                len: 0,
            }
        }
    };

    let proof_vec = compose_recursive_proof(proof_slice, hash_array);
    let len = proof_vec.len();
    let ptr = Box::into_raw(proof_vec.into_boxed_slice()) as *mut u8;

    RecursiveProofResult { data: ptr, len }
}
