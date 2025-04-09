use crate::recursive::recursive_prover::compose_recursive_proof;
use core::ptr;
use core::slice;
use alloc::boxed::Box;

#[no_mangle]
pub extern "C" fn compose_recursive_proof_ffi(
    inner_ptr: *const u8,
    inner_len: usize,
    hash_ptr: *const u8,
) -> *mut u8 {
    if inner_ptr.is_null() || inner_len == 0 || hash_ptr.is_null() {
        return ptr::null_mut();
    }

    let inner_slice = unsafe { slice::from_raw_parts(inner_ptr, inner_len) };
    let hash_slice = unsafe { slice::from_raw_parts(hash_ptr, 32) };

    let hash_array: [u8; 32] = match hash_slice.try_into() {
        Ok(arr) => arr,
        Err(_) => return ptr::null_mut(),
    };

    let result = compose_recursive_proof(inner_slice, hash_array);
    let boxed = result.into_boxed_slice();
    Box::into_raw(boxed) as *mut u8
}
