// alyn-utils/src/string.rs

/// Converts a byte array to a hexadecimal string.
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Converts a hexadecimal string back to bytes.
pub fn hex_to_bytes(hex_str: &str) -> Result<Vec<u8>, hex::FromHexError> {
    hex::decode(hex_str)
}
