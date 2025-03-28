#![allow(unused)]

use crate::byte_io::{ByteReader, ByteWriter, ByteIOError};

/// A trait for objects that can be written into a ByteWriter
pub trait Serializable {
    fn write_into<W: ByteWriter>(&self, writer: &mut W) -> Result<(), ByteIOError>;
}

/// A trait for objects that can be read from a ByteReader
pub trait Deserializable: Sized {
    fn read_from<R: ByteReader>(reader: &mut R) -> Result<Self, ByteIOError>;
}

