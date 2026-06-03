#![feature(test)]
extern crate test;

pub mod bear;
pub mod lion;
pub mod lioness;

pub(crate) mod util {
    /// XORs `a` with `b` in-place.
    pub const fn xor(a: &mut [u8], b: &[u8]) {
        let mut i = 0;
        while i < a.len() && i < b.len() {
            a[i] ^= b[i];
            i += 1;
        }
    }
}

#[cfg(test)]
pub(crate) mod test_utils {
    use blake3::KEY_LEN;
    use rand::{RngExt, rngs::ThreadRng};

    /// Generates a random byte vector of a given length
    pub fn generate_random_bytes(len: usize) -> Vec<u8> {
        let mut rng = ThreadRng::default();
        let mut bytes = Vec::with_capacity(len);
        for _ in 0..len {
            bytes.push(rng.random_range(0..=255) as u8);
        }
        bytes
    }

    /// Generates a random key of size KEY_LEN
    pub fn generate_random_key() -> [u8; KEY_LEN] {
        let mut rng = ThreadRng::default();
        let mut key = [0u8; KEY_LEN];
        for i in 0..KEY_LEN {
            key[i] = rng.random_range(0..=255) as u8;
        }
        key
    }

    /// Helper to generate static keys for microbenchmarks
    pub fn get_bench_key() -> [u8; KEY_LEN] {
        [0x42; KEY_LEN]
    }
}
