//! Simple library that allows to easily encrypt and decrypt data with a secret key using AES and Scrypt.

use crypto::{
    aes,
    buffer::{self, BufferResult, ReadBuffer, WriteBuffer},
    scrypt,
    symmetriccipher::{Decryptor, Encryptor},
};
use rand::{rngs::OsRng, RngCore};
use thiserror::Error;

/// Encrypt data with an scrypt derived key of the given passphrase and a random salt.
///
/// Returns a Vec<u8> of the encrypted data with salt and nonce prepended.
///
/// Anatomy of the returned byte vector:
///
/// |index  |usage|
/// |-------|-----|
/// |0 - 31 |salt |
/// |32 -   |data |
pub fn encrypt(data: &[u8], passphrase: &[u8]) -> Vec<u8> {
    let mut salt = [0u8; 32];
    OsRng.fill_bytes(&mut salt);

    let mut output = Vec::with_capacity(data.len() + salt.len());
    output.extend_from_slice(&salt);

    let key = derive_key(passphrase, &salt);
    let mut encryptor = aes::ctr(crypto::aes::KeySize::KeySize256, &key, &salt[..16]);
    let mut read_buffer = buffer::RefReadBuffer::new(data);
    let mut buffer = [0; 4096];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

    loop {
        let result = encryptor
            .encrypt(&mut read_buffer, &mut write_buffer, true)
            .unwrap();
        output.extend(write_buffer.take_read_buffer().take_remaining());
        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => {}
        }
    }

    output
}

/// Decrypt the given data with the scrypt derivation of the passphrase.
/// Returns the decrypted data on success, or an error on failure.
///
/// The given byte slice is interpreted like this:
///
/// |index  |usage|
/// |-------|-----|
/// |0 - 31 |salt |
/// |32 -   |data |
pub fn decrypt(data: &[u8], passphrase: &[u8]) -> Result<Vec<u8>, DecryptionError> {
    if data.len() < 32 {
        return Err(DecryptionError::IncompleteSalt(data.len()));
    }

    let (salt, data) = data.split_at(32);
    let key = derive_key(passphrase, salt);
    let mut decryptor = aes::ctr(crypto::aes::KeySize::KeySize256, &key, &salt[..16]);
    let mut read_buffer = buffer::RefReadBuffer::new(data);
    let mut buffer = [0; 4096];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);
    let mut decrypted = Vec::new();

    loop {
        let result = decryptor
            .decrypt(&mut read_buffer, &mut write_buffer, true)
            .unwrap();
        decrypted.extend(write_buffer.take_read_buffer().take_remaining());
        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => {}
        }
    }

    Ok(decrypted)
}

/// Represents an error that can occur during decryption.
#[derive(Error, Debug, Eq, PartialEq)]
pub enum DecryptionError {
    /// Used if the data slice is too short so it can't contain a valid salt.
    #[error("expected a 32 byte salt but only got {0} bytes")]
    IncompleteSalt(usize),

    /// Used if the data can't be decrypted either because the key or the data slice are invalid.
    #[error("invalid data or secret key")]
    Decryption,
}

/// Derives a key from the given passphrase and salt using scrypt.
fn derive_key(passphrase: &[u8], salt: &[u8]) -> Vec<u8> {
    let mut key = [0u8; 32];
    let params = scrypt::ScryptParams::new(15, 8, 1);
    scrypt::scrypt(passphrase, salt, &params, &mut key);
    key.to_vec()
}

#[cfg(test)]
mod tests {
    use crate::*;

    #[test]
    pub fn test_encrypt_and_decrypt() {
        let text = "lord ferris says: you shall not use Go";
        let passphrase = "lul no generics";

        let encrypted_data = encrypt(text.as_bytes(), passphrase.as_bytes());
        let decrypted_data = decrypt(&encrypted_data, passphrase.as_bytes()).unwrap();

        assert_eq!(text.as_bytes(), decrypted_data.as_slice());
    }

    #[test]
    pub fn test_decrypt_wrong_phrase() {
        let text = "lord ferris says: you shall not use Go";
        let passphrase = "lul no generics";
        let incorrect_passphrase = "lol no generics";

        let encrypted_data = encrypt(text.as_bytes(), passphrase.as_bytes());
        let decrypted_data = decrypt(&encrypted_data, incorrect_passphrase.as_bytes()).unwrap();

        assert_ne!(text.as_bytes(), decrypted_data.as_slice());
    }
}
