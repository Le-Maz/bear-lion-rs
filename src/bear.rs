use crate::util::xor;
use blake3::{KEY_LEN, derive_key, keyed_hash};
use chacha20::{
    ChaCha12,
    cipher::{KeyIvInit, StreamCipher},
};

/// The BEAR block cipher.
///
/// BEAR is an arbitrary-block-size block cipher constructed from a stream cipher
/// (here ChaCha12) and a keyed cryptographic hash function (here BLAKE3). It can
/// encrypt and decrypt blocks of any size greater than or equal to `KEY_LEN * 2`.
pub struct Bear {
    k1: [u8; KEY_LEN],
    k2: [u8; KEY_LEN],
}

impl Bear {
    /// Creates a new [`Bear`] instance from a master key.
    ///
    /// Two independent subkeys are derived from the provided master key using
    /// BLAKE3's key derivation functionality.
    pub fn new(key: [u8; KEY_LEN]) -> Self {
        let k1 = derive_key("BEAR key 1", &key);
        let k2 = derive_key("BEAR key 2", &key);
        Self { k1, k2 }
    }

    /// Encrypts a block of data in-place.
    ///
    /// The encryption follows a three-round unbalanced Feistel-like network:
    /// 1. XOR the left part with the keyed hash of the right part using `k1`.
    /// 2. Apply a stream cipher to the right part, keyed by the new left part.
    /// 3. XOR the left part with the keyed hash of the new right part using `k2`.
    ///
    /// # Panics
    ///
    /// Panics if the `block` length is less than `KEY_LEN * 2`.
    pub fn encrypt(&self, block: &mut [u8]) {
        assert!(block.len() >= KEY_LEN * 2);

        let (b1, b2) = block.split_at_mut(KEY_LEN);
        let h1 = keyed_hash(&self.k1, b2);
        xor(b1, h1.as_bytes());

        // SAFETY: b1 is guaranteed to be at least KEY_LEN bytes long
        let key = unsafe { chacha20::Key::slice_as_array(b1).unwrap_unchecked() };
        let nonce = [0u8; 12].into();
        let mut cipher = ChaCha12::new(key, &nonce);
        cipher.apply_keystream(b2);

        let h2 = keyed_hash(&self.k2, b2);
        xor(b2, h2.as_bytes());
    }

    /// Decrypts a block of data in-place.
    ///
    /// Decryption is the exact inverse of the `encrypt` operation, applying
    /// the transformations in reverse order.
    ///
    /// # Panics
    ///
    /// Panics if the `block` length is less than `KEY_LEN * 2`.
    pub fn decrypt(&self, block: &mut [u8]) {
        assert!(block.len() >= KEY_LEN * 2);

        let (b1, b2) = block.split_at_mut(KEY_LEN);
        let h1 = keyed_hash(&self.k2, b2);
        xor(b1, h1.as_bytes());

        // SAFETY: b1 is guaranteed to be at least KEY_LEN bytes long
        let key = unsafe { chacha20::Key::slice_as_array(b1).unwrap_unchecked() };
        let nonce = [0u8; 12].into();
        let mut cipher = ChaCha12::new(key, &nonce);
        cipher.apply_keystream(b2);

        let h2 = keyed_hash(&self.k1, b2);
        xor(b2, h2.as_bytes());
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
        let bear = Bear::new(key);

        let original_data = generate_random_bytes(128);
        let mut block = original_data.clone();

        bear.encrypt(&mut block);

        assert_ne!(block, original_data);

        bear.decrypt(&mut block);

        assert_eq!(block, original_data);
    }

    #[test]
    fn different_keys_fail_to_decrypt() {
        let key1 = generate_random_key();
        let key2 = generate_random_key();

        let bear1 = Bear::new(key1);
        let bear2 = Bear::new(key2);

        let original_data = generate_random_bytes(64);
        let mut block = original_data.clone();

        bear1.encrypt(&mut block);
        bear2.decrypt(&mut block);

        assert_ne!(block, original_data);
    }

    #[test]
    #[should_panic(expected = "assertion failed: block.len() >= KEY_LEN * 2")]
    fn encrypt_block_too_small() {
        let key = generate_random_key();
        let bear = Bear::new(key);

        let mut small_block = generate_random_bytes(KEY_LEN);

        bear.encrypt(&mut small_block);
    }

    #[test]
    fn multiple_encryptions() {
        let key = generate_random_key();
        let bear = Bear::new(key);

        let original_data = generate_random_bytes(256);
        let mut block = original_data.clone();

        bear.encrypt(&mut block);
        let first_encryption = block.clone();

        bear.encrypt(&mut block);
        let second_encryption = block.clone();

        assert_ne!(first_encryption, second_encryption);

        bear.decrypt(&mut block);
        assert_eq!(block, first_encryption);

        bear.decrypt(&mut block);
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
        let bear = Bear::new(get_bench_key());
        let mut data = vec![0u8; 64];

        b.iter(|| {
            bear.encrypt(&mut data);
            black_box(&mut data);
        });
    }

    #[bench]
    fn decrypt_64_bytes(b: &mut Bencher) {
        let bear = Bear::new(get_bench_key());
        let mut data = vec![0u8; 64];

        b.iter(|| {
            bear.decrypt(&mut data);
            black_box(&mut data);
        });
    }

    #[bench]
    fn encrypt_1_kibibyte(b: &mut Bencher) {
        let bear = Bear::new(get_bench_key());
        let mut data = vec![0u8; 1024];

        b.iter(|| {
            bear.encrypt(&mut data);
            black_box(&mut data);
        });
    }

    #[bench]
    fn decrypt_1_kibibyte(b: &mut Bencher) {
        let bear = Bear::new(get_bench_key());
        let mut data = vec![0u8; 1024];

        b.iter(|| {
            bear.decrypt(&mut data);
            black_box(&mut data);
        });
    }

    #[bench]
    fn encrypt_4_kibibytes(b: &mut Bencher) {
        let bear = Bear::new(get_bench_key());
        let mut data = vec![0u8; 4096];

        b.iter(|| {
            bear.encrypt(&mut data);
            black_box(&mut data);
        });
    }

    #[bench]
    fn decrypt_4_kibibytes(b: &mut Bencher) {
        let bear = Bear::new(get_bench_key());
        let mut data = vec![0u8; 4096];

        b.iter(|| {
            bear.decrypt(&mut data);
            black_box(&mut data);
        });
    }
}
