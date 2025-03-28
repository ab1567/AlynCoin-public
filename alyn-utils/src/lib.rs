#![no_std]

extern crate alloc;

#[allow(clippy::too_many_arguments)]
#[allow(clippy::type_complexity)]
pub mod byte_io;    // only one module now for both read & write
pub mod serialization;
pub mod utils;

pub use byte_io::{
    ByteReader,
    ByteWriter,
    ByteIOError,
};
pub use serialization::{Deserializable, Serializable};
pub use utils::{log2, pow2, transpose, is_power_of_two};
