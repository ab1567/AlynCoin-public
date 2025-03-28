extern crate alloc;
use alloc::vec::Vec;

/// A single custom error type for reading/writing
#[derive(Debug)]
pub enum ByteIOError {
    UnexpectedEOF,
    InvalidData,
    WriteFailed,
}

/// A trait for reading in a no_std environment
pub trait ByteReader {
    fn read_u8(&mut self) -> Result<u8, ByteIOError>;
    fn read_u16(&mut self) -> Result<u16, ByteIOError>;
    fn read_u32(&mut self) -> Result<u32, ByteIOError>;
    fn read_u64(&mut self) -> Result<u64, ByteIOError>;
    fn read_bytes(&mut self, length: usize) -> Result<Vec<u8>, ByteIOError>;
}

/// A trait for writing in a no_std environment
pub trait ByteWriter {
    fn write_u8(&mut self, value: u8) -> Result<(), ByteIOError>;
    fn write_u16(&mut self, value: u16) -> Result<(), ByteIOError>;
    fn write_u32(&mut self, value: u32) -> Result<(), ByteIOError>;
    fn write_u64(&mut self, value: u64) -> Result<(), ByteIOError>;
    fn write_bytes(&mut self, bytes: &[u8]) -> Result<(), ByteIOError>;
}

// Example default implementations for Vec<u8>, etc., if you want:
impl ByteWriter for Vec<u8> {
    fn write_u8(&mut self, value: u8) -> Result<(), ByteIOError> {
        self.push(value);
        Ok(())
    }
    fn write_u16(&mut self, value: u16) -> Result<(), ByteIOError> {
        self.extend_from_slice(&value.to_le_bytes());
        Ok(())
    }
    fn write_u32(&mut self, value: u32) -> Result<(), ByteIOError> {
        self.extend_from_slice(&value.to_le_bytes());
        Ok(())
    }
    fn write_u64(&mut self, value: u64) -> Result<(), ByteIOError> {
        self.extend_from_slice(&value.to_le_bytes());
        Ok(())
    }
    fn write_bytes(&mut self, bytes: &[u8]) -> Result<(), ByteIOError> {
        self.extend_from_slice(bytes);
        Ok(())
    }
}
