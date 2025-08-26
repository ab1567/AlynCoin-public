#![no_std]
use core::sync::atomic::{AtomicU64, Ordering};
use core::panic::PanicInfo;

static SPEND_COUNTER: AtomicU64 = AtomicU64::new(0);

#[no_mangle]
pub extern "C" fn entry(_ptr: *const u8, len: usize) -> i32 {
    SPEND_COUNTER.fetch_add(len as u64, Ordering::SeqCst);
    0
}

#[no_mangle]
pub extern "C" fn counter() -> u64 {
    SPEND_COUNTER.load(Ordering::SeqCst)
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}
