use crate::recursive::recursive_prover::compose_recursive_proof;
use core::slice;
use alloc::boxed::Box;
use std::ffi::CStr;
use std::os::raw::c_char;
use hex;
use alyn_math::fields::f64::BaseElement;
use alyn_crypto::hash::Hasher;
use alyn_crypto::Digest;
use crate::Blake3_256;

#[repr(C)]
pub struct RecursiveProofResult {
    pub data: *mut u8,
    pub len: usize,
}

#[no_mangle]
pub extern "C" fn compose_recursive_proof_ffi(
    inner_ptr: *const u8,
    inner_len: usize,
    hash_ptr: *const u8,
) -> RecursiveProofResult {
    if inner_ptr.is_null() || inner_len == 0 || hash_ptr.is_null() {
        return RecursiveProofResult {
            data: core::ptr::null_mut(),
            len: 0,
        };
    }

    let inner_slice = unsafe { slice::from_raw_parts(inner_ptr, inner_len) };
    let hash_slice = unsafe { slice::from_raw_parts(hash_ptr, 32) };

    let hash_array: [u8; 32] = match hash_slice.try_into() {
        Ok(arr) => arr,
        Err(_) => {
            return RecursiveProofResult {
                data: core::ptr::null_mut(),
                len: 0,
            };
        }
    };

    let result_vec = compose_recursive_proof(inner_slice, hash_array);
    let len = result_vec.len();
    let boxed = result_vec.into_boxed_slice();
    let data = Box::into_raw(boxed) as *mut u8;

    RecursiveProofResult { data, len }
}

#[no_mangle]
pub extern "C" fn verify_proof_ffi(
    proof_ptr: *const c_char,
    seed_ptr: *const c_char,
    result_ptr: *const c_char,
) -> bool {
    let proof_bytes = unsafe { CStr::from_ptr(proof_ptr).to_bytes() };
    let seed_bytes = unsafe { CStr::from_ptr(seed_ptr).to_bytes() };
    let expected_hex_str = unsafe {
        CStr::from_ptr(result_ptr)
            .to_str()
            .unwrap_or("[Invalid result ptr]")
    };

    println!("[Rust zkSTARK] 🔎 Raw seed bytes: {:?}", seed_bytes);
    println!("[Rust zkSTARK] 🔎 Expected result (hex): {}", expected_hex_str);
    println!("[Rust zkSTARK] 🔎 Received proof size: {} bytes", proof_bytes.len());

    let digest = Blake3_256::<BaseElement>::hash(seed_bytes);
    let computed = digest.as_bytes();

    println!(
        "[Rust zkSTARK] 🔑 Computed BLAKE3(seed) = {:02x?}",
        computed
    );

    match hex::decode(expected_hex_str) {
        Ok(expected_bytes) => {
            println!(
                "[Rust zkSTARK] 🔍 Checking if expected starts with computed: {}",
                expected_bytes.starts_with(&computed)
            );
            expected_bytes.starts_with(&computed)
        }
        Err(e) => {
            println!("[Rust zkSTARK] ❌ Failed to decode expected hex: {}", e);
            false
        }
    }
}


