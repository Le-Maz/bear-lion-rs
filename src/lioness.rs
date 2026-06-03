use crate::util::xor;
use blake3::{KEY_LEN, derive_key, keyed_hash};
use chacha20::{
    ChaCha12,
    cipher::{KeyIvInit, StreamCipher},
};

/// The LIONESS block cipher.
///
/// LIONESS is an arbitrary-block-size block cipher constructed from a stream cipher
/// (here ChaCha12) and a keyed cryptographic hash function (here BLAKE3). It can
/// encrypt and decrypt blocks of any size greater than or equal to `KEY_LEN * 2`.
pub struct Lioness {
    k1: [u8; KEY_LEN],
    k2: [u8; KEY_LEN],
    k3: [u8; KEY_LEN],
    k4: [u8; KEY_LEN],
}

impl Lioness {
    /// Creates a new [`Lioness`] instance from a master key.
    ///
    /// Four independent subkeys are derived from the provided master key using
    /// BLAKE3's key derivation functionality.
    pub fn new(key: [u8; KEY_LEN]) -> Self {
        let k1 = derive_key("LIONESS key 1", &key);
        let k2 = derive_key("LIONESS key 2", &key);
        let k3 = derive_key("LIONESS key 3", &key);
        let k4 = derive_key("LIONESS key 4", &key);
        Self { k1, k2, k3, k4 }
    }

    /// Encrypts a block of data in-place.
    ///
    /// # Panics
    ///
    /// Panics if the `block` length is less than `KEY_LEN * 2`.
    pub fn encrypt(&self, block: &mut [u8]) {
        assert!(block.len() >= KEY_LEN * 2);

        let (b1, b2) = block.split_at_mut(KEY_LEN);

        // Round 1: R = R ^ S(L ^ K1)
        let mut new_k1 = self.k1;
        xor(&mut new_k1, b1);
        let key1 = chacha20::Key::cast_from_core(&new_k1);
        let nonce1 = [0u8; 12].into();
        let mut cipher1 = ChaCha12::new(key1, &nonce1);
        cipher1.apply_keystream(b2);

        // Round 2: L = L ^ H_K2(R)
        let h2 = keyed_hash(&self.k2, b2);
        xor(b1, h2.as_bytes());

        // Round 3: R = R ^ S(L ^ K3)
        let mut new_k3 = self.k3;
        xor(&mut new_k3, b1);
        let key3 = chacha20::Key::cast_from_core(&new_k3);
        let nonce3 = [0u8; 12].into();
        let mut cipher3 = ChaCha12::new(key3, &nonce3);
        cipher3.apply_keystream(b2);

        // Round 4: L = L ^ H_K4(R)
        let h4 = keyed_hash(&self.k4, b2);
        xor(b1, h4.as_bytes());
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

        // Inverse of Round 4: L = L ^ H_K4(R)
        let h4 = keyed_hash(&self.k4, b2);
        xor(b1, h4.as_bytes());

        // Inverse of Round 3: R = R ^ S(L ^ K3)
        let mut new_k3 = self.k3;
        xor(&mut new_k3, b1);
        let key3 = chacha20::Key::cast_from_core(&new_k3);
        let nonce3 = [0u8; 12].into();
        let mut cipher3 = ChaCha12::new(key3, &nonce3);
        cipher3.apply_keystream(b2);

        // Inverse of Round 2: L = L ^ H_K2(R)
        let h2 = keyed_hash(&self.k2, b2);
        xor(b1, h2.as_bytes());

        // Inverse of Round 1: R = R ^ S(L ^ K1)
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
        let lioness = Lioness::new(key);

        let original_data = generate_random_bytes(128);
        let mut block = original_data.clone();

        lioness.encrypt(&mut block);
        assert_ne!(block, original_data);

        lioness.decrypt(&mut block);
        assert_eq!(block, original_data);
    }

    #[test]
    fn different_keys_fail_to_decrypt() {
        let key1 = generate_random_key();
        let key2 = generate_random_key();

        let lioness1 = Lioness::new(key1);
        let lioness2 = Lioness::new(key2);

        let original_data = generate_random_bytes(64);
        let mut block = original_data.clone();

        lioness1.encrypt(&mut block);
        lioness2.decrypt(&mut block);

        assert_ne!(block, original_data);
    }

    #[test]
    #[should_panic(expected = "assertion failed: block.len() >= KEY_LEN * 2")]
    fn encrypt_block_too_small() {
        let key = generate_random_key();
        let lioness = Lioness::new(key);

        let mut small_block = generate_random_bytes(KEY_LEN);

        lioness.encrypt(&mut small_block);
    }

    #[test]
    fn multiple_encryptions() {
        let key = generate_random_key();
        let lioness = Lioness::new(key);

        let original_data = generate_random_bytes(256);
        let mut block = original_data.clone();

        lioness.encrypt(&mut block);
        let first_encryption = block.clone();

        lioness.encrypt(&mut block);
        let second_encryption = block.clone();

        assert_ne!(first_encryption, second_encryption);

        lioness.decrypt(&mut block);
        assert_eq!(block, first_encryption);

        lioness.decrypt(&mut block);
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
        let lioness = Lioness::new(get_bench_key());
        let mut data = vec![0u8; 64];

        b.iter(|| {
            lioness.encrypt(&mut data);
            black_box(&mut data);
        });
    }

    #[bench]
    fn decrypt_64_bytes(b: &mut Bencher) {
        let lioness = Lioness::new(get_bench_key());
        let mut data = vec![0u8; 64];

        b.iter(|| {
            lioness.decrypt(&mut data);
            black_box(&mut data);
        });
    }

    #[bench]
    fn encrypt_1_kibibyte(b: &mut Bencher) {
        let lioness = Lioness::new(get_bench_key());
        let mut data = vec![0u8; 1024];

        b.iter(|| {
            lioness.encrypt(&mut data);
            black_box(&mut data);
        });
    }

    #[bench]
    fn decrypt_1_kibibyte(b: &mut Bencher) {
        let lioness = Lioness::new(get_bench_key());
        let mut data = vec![0u8; 1024];

        b.iter(|| {
            lioness.decrypt(&mut data);
            black_box(&mut data);
        });
    }

    #[bench]
    fn encrypt_4_kibibytes(b: &mut Bencher) {
        let lioness = Lioness::new(get_bench_key());
        let mut data = vec![0u8; 4096];

        b.iter(|| {
            lioness.encrypt(&mut data);
            black_box(&mut data);
        });
    }

    #[bench]
    fn decrypt_4_kibibytes(b: &mut Bencher) {
        let lioness = Lioness::new(get_bench_key());
        let mut data = vec![0u8; 4096];

        b.iter(|| {
            lioness.decrypt(&mut data);
            black_box(&mut data);
        });
    }
}
