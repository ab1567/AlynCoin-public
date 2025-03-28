extern crate alloc;
use alloc::vec::Vec;

/// A single custom error type for both reading/writing in no_std.
#[derive(Debug)]
pub enum ByteIOError {
    UnexpectedEOF,
    InvalidData,
    WriteFailed,
    // Add more variants as needed
}

/// A minimal ByteWriter trait in no_std, returning `ByteIOError`.
pub trait ByteWriter {
    fn write_bytes(&mut self, data: &[u8]) -> Result<(), ByteIOError>;
}

/// Default implementation for Vec<u8>.
impl ByteWriter for Vec<u8> {
    fn write_bytes(&mut self, data: &[u8]) -> Result<(), ByteIOError> {
        self.extend_from_slice(data);
        Ok(())
    }
}

