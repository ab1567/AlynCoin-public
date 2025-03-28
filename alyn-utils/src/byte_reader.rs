// alyn-utils/src/byte_reader.rs

pub trait ByteReader {
    fn read_byte(&mut self) -> Option<u8>;
    fn read_bytes(&mut self, num: usize) -> Option<Vec<u8>> {
        let mut buf = Vec::with_capacity(num);
        for _ in 0..num {
            match self.read_byte() {
                Some(b) => buf.push(b),
                None => return None,
            }
        }
        Some(buf)
    }
}
