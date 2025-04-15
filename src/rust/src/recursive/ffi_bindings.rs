use crate::recursive::recursive_prover::compose_recursive_proof;
use core::slice;
use alloc::boxed::Box;

#[repr(C)]
pub struct RecursiveProofResult {
    pub data: *mut u8,
    pub len: usize,
}

#[no_mangle]
pub extern "C" fn compose_recursive_proof_ffi(
    inner_ptr: *const u8,
    inner_len: usize,
    hash_ptr: *const u8, // <-- actually use this now
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
