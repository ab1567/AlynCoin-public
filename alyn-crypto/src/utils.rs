extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;

use blake3;
use hex;

/// Converts input string to BLAKE3 hash (hex format)
pub fn blake3_hex(input: &str) -> String {
    let hash = blake3::hash(input.as_bytes());
    hex::encode(hash.as_bytes())
}

/// Converts hex string to byte vector
pub fn from_hex(hex_str: &str) -> Option<Vec<u8>> {
    match hex::decode(hex_str) {
        Ok(bytes) => Some(bytes),
        Err(_) => None,
    }
}
