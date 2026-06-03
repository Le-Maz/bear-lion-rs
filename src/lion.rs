use crate::util::xor;
use blake3::{KEY_LEN, derive_key, hash};
use chacha20::{
    ChaCha12,
    cipher::{KeyIvInit, StreamCipher},
};

/// The LION block cipher.
///
/// LION is an arbitrary-block-size block cipher constructed from a stream cipher
/// (here ChaCha12) and a cryptographic hash function (here BLAKE3). It can encrypt
/// and decrypt blocks of any size greater than or equal to `KEY_LEN * 2`.
pub struct Lion {
    k1: [u8; KEY_LEN],
    k2: [u8; KEY_LEN],
}

impl Lion {
    /// Creates a new [`Lion`] instance from a master key.
    ///
    /// Two independent subkeys are derived from the provided master key using
    /// BLAKE3's key derivation functionality.
    pub fn new(key: [u8; KEY_LEN]) -> Self {
        let k1 = derive_key("LION key 1", &key);
        let k2 = derive_key("LION key 2", &key);
        Self { k1, k2 }
    }

    /// Encrypts a block of data in place.
    ///
    /// The encryption follows a three-round unbalanced Feistel-like network:
    /// 1. Apply a stream cipher to the right part, keyed by the left part and `k1`.
    /// 2. XOR the left part with the hash of the right part.
    /// 3. Apply a stream cipher to the right part, keyed by the new left part and `k2`.
    ///
    /// # Panics
    ///
    /// Panics if the `block` length is less than `KEY_LEN * 2`.
    pub fn encrypt(&self, block: &mut [u8]) {
        assert!(block.len() >= KEY_LEN * 2);

        let (b1, b2) = block.split_at_mut(KEY_LEN);

        // Round 1: Encrypt right half using a stream cipher keyed by (k1 XOR left half)
        let mut new_k1 = self.k1;
        xor(&mut new_k1, b1);

        let key1 = chacha20::Key::cast_from_core(&new_k1);
        let nonce1 = [0u8; 12].into();
        let mut cipher1 = ChaCha12::new(key1, &nonce1);
        cipher1.apply_keystream(b2);

        // Round 2: Mix right half into left half using a hash function
        let h = hash(b2);
        xor(b1, h.as_bytes());

        // Round 3: Encrypt right half using a stream cipher keyed by (k2 XOR new left half)
        let mut new_k2 = self.k2;
        xor(&mut new_k2, b1);

        let key2 = chacha20::Key::cast_from_core(&new_k2);
        let nonce2 = [0u8; 12].into();
        let mut cipher2 = ChaCha12::new(key2, &nonce2);
        cipher2.apply_keystream(b2);
    }

    /// Decrypts a block of data in place.
    ///
    /// Decryption is the exact inverse of the `encrypt` operation, applying
    /// the transformations in reverse order (Round 3, then 2, then 1).
    ///
    /// # Panics
    ///
    /// Panics if the `block` length is less than `KEY_LEN * 2`.
    pub fn decrypt(&self, block: &mut [u8]) {
        assert!(block.len() >= KEY_LEN * 2);

        let (b1, b2) = block.split_at_mut(KEY_LEN);

        // Inverse of Round 3: Decrypt right half using stream cipher keyed by (k2 XOR left half)
        let mut new_k2 = self.k2;
        xor(&mut new_k2, b1);

        let key2 = chacha20::Key::cast_from_core(&new_k2);
        let nonce2 = [0u8; 12].into();
        let mut cipher2 = ChaCha12::new(key2, &nonce2);
        cipher2.apply_keystream(b2);

        // Inverse of Round 2: Unmix right half from left half
        let h = hash(b2);
        xor(b1, h.as_bytes());

        // Inverse of Round 1: Decrypt right half using stream cipher keyed by (k1 XOR original left half)
        let mut new_k1 = self.k1;
        xor(&mut new_k1, b1);

        let key1 = chacha20::Key::cast_from_core(&new_k1);
        let nonce1 = [0u8; 12].into();
        let mut cipher1 = ChaCha12::new(key1, &nonce1);
        cipher1.apply_keystream(b2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{generate_random_bytes, generate_random_key};
    use blake3::KEY_LEN;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = generate_random_key();
        let lion = Lion::new(key);

        let original_data = generate_random_bytes(128);
        let mut block = original_data.clone();

        lion.encrypt(&mut block);

        assert_ne!(block, original_data);

        lion.decrypt(&mut block);

        assert_eq!(block, original_data);
    }

    #[test]
    fn different_keys_fail_to_decrypt() {
        let key1 = generate_random_key();
        let key2 = generate_random_key();

        let lion1 = Lion::new(key1);
        let lion2 = Lion::new(key2);

        let original_data = generate_random_bytes(64);
        let mut block = original_data.clone();

        lion1.encrypt(&mut block);
        lion2.decrypt(&mut block);

        assert_ne!(block, original_data);
    }

    #[test]
    #[should_panic(expected = "assertion failed: block.len() >= KEY_LEN * 2")]
    fn encrypt_block_too_small() {
        let key = generate_random_key();
        let lion = Lion::new(key);

        let mut small_block = generate_random_bytes(KEY_LEN);

        lion.encrypt(&mut small_block);
    }

    #[test]
    fn multiple_encryptions() {
        let key = generate_random_key();
        let lion = Lion::new(key);

        let original_data = generate_random_bytes(256);
        let mut block = original_data.clone();

        lion.encrypt(&mut block);
        let first_encryption = block.clone();

        lion.encrypt(&mut block);
        let second_encryption = block.clone();

        assert_ne!(first_encryption, second_encryption);

        lion.decrypt(&mut block);
        assert_eq!(block, first_encryption);

        lion.decrypt(&mut block);
        assert_eq!(block, original_data);
    }
}

#[cfg(test)]
mod benches {
    use super::*;
    extern crate test;
    use crate::test_utils::get_bench_key;
    use test::{Bencher, black_box};

    #[bench]
    fn encrypt_64_bytes(b: &mut Bencher) {
        let lion = Lion::new(get_bench_key());
        let mut data = vec![0u8; 64];

        b.iter(|| {
            lion.encrypt(&mut data);
            black_box(&mut data);
        });
    }

    #[bench]
    fn decrypt_64_bytes(b: &mut Bencher) {
        let lion = Lion::new(get_bench_key());
        let mut data = vec![0u8; 64];

        b.iter(|| {
            lion.decrypt(&mut data);
            black_box(&mut data);
        });
    }

    #[bench]
    fn encrypt_1_kibibyte(b: &mut Bencher) {
        let lion = Lion::new(get_bench_key());
        let mut data = vec![0u8; 1024];

        b.iter(|| {
            lion.encrypt(&mut data);
            black_box(&mut data);
        });
    }

    #[bench]
    fn decrypt_1_kibibyte(b: &mut Bencher) {
        let lion = Lion::new(get_bench_key());
        let mut data = vec![0u8; 1024];

        b.iter(|| {
            lion.decrypt(&mut data);
            black_box(&mut data);
        });
    }

    #[bench]
    fn encrypt_4_kibibytes(b: &mut Bencher) {
        let lion = Lion::new(get_bench_key());
        let mut data = vec![0u8; 4096];

        b.iter(|| {
            lion.encrypt(&mut data);
            black_box(&mut data);
        });
    }

    #[bench]
    fn decrypt_4_kibibytes(b: &mut Bencher) {
        let lion = Lion::new(get_bench_key());
        let mut data = vec![0u8; 4096];

        b.iter(|| {
            lion.decrypt(&mut data);
            black_box(&mut data);
        });
    }
}
