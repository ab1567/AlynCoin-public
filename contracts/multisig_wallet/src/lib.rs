#![no_std]
use core::panic::PanicInfo;

#[no_mangle]
pub extern "C" fn entry(_ptr: *const u8, len: usize) -> i32 {
    // In a real implementation, this would verify multiple signatures.
    // For now, simply return success if any data is provided.
    if len > 0 { 0 } else { 1 }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}
