use aes_frast::aes_core;
use aes_frast::aes_with_operation_mode::{ecb_dec, ecb_enc};
use aes_frast::padding_128bit::pa_pkcs7;
use thiserror::Error;

const AES_BLOCK_SIZE: usize = 16;

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum CipherError {
    #[error("invalid AES key length: expected {expected} bytes, got {actual}")]
    InvalidKeyLength { expected: usize, actual: usize },

    #[error(
        "invalid ciphertext length: expected a non-empty multiple of {block_size}, got {actual}"
    )]
    InvalidCiphertextLength { block_size: usize, actual: usize },

    #[error("invalid PKCS#7 padding length {padding_length}")]
    InvalidPadding { padding_length: usize },
}

pub trait SimpleCipher {
    fn encrypt(&self, plain_bytes: &[u8]) -> Result<Vec<u8>, CipherError>;
    fn decrypt(&self, encrypted_bytes: &[u8]) -> Result<Vec<u8>, CipherError>;
}

#[derive(Debug)]
pub struct Aes128Ecb {
    key: [u8; 16],
}

impl Aes128Ecb {
    pub fn from_key(key: &[u8]) -> Result<Self, CipherError> {
        if key.len() != 16 {
            return Err(CipherError::InvalidKeyLength {
                expected: AES_BLOCK_SIZE,
                actual: key.len(),
            });
        }
        let mut fixed_key = [0u8; 16];
        fixed_key.copy_from_slice(key);

        Ok(Self { key: fixed_key })
    }
}

impl SimpleCipher for Aes128Ecb {
    fn encrypt(&self, plain_bytes: &[u8]) -> Result<Vec<u8>, CipherError> {
        let mut data = plain_bytes.to_vec();
        pa_pkcs7(&mut data);
        let mut result = vec![0u8; data.len()];
        let mut scheduled_keys: [u32; 44] = [0; 44];
        aes_core::key_schedule_encrypt128(&self.key, &mut scheduled_keys);
        ecb_enc(&data, &mut result, &scheduled_keys);
        Ok(result)
    }

    fn decrypt(&self, encrypted_bytes: &[u8]) -> Result<Vec<u8>, CipherError> {
        if encrypted_bytes.is_empty() || encrypted_bytes.len() % AES_BLOCK_SIZE != 0 {
            return Err(CipherError::InvalidCiphertextLength {
                block_size: AES_BLOCK_SIZE,
                actual: encrypted_bytes.len(),
            });
        }

        let mut result = vec![0u8; encrypted_bytes.len()];
        let mut scheduled_keys: [u32; 44] = [0; 44];
        aes_core::key_schedule_decrypt128(&self.key, &mut scheduled_keys);
        ecb_dec(encrypted_bytes, &mut result, &scheduled_keys);

        let padding_length = result.last().copied().map_or(0, usize::from);
        if padding_length == 0 || padding_length > AES_BLOCK_SIZE || padding_length > result.len() {
            return Err(CipherError::InvalidPadding { padding_length });
        }

        let content_length = result.len() - padding_length;
        let padding = result
            .get(content_length..)
            .ok_or(CipherError::InvalidPadding { padding_length })?;
        if !padding
            .iter()
            .all(|byte| usize::from(*byte) == padding_length)
        {
            return Err(CipherError::InvalidPadding { padding_length });
        }
        result.truncate(content_length);
        Ok(result)
    }
}

#[test]
fn test_aes_128_ecb_cipher() {
    let message = b"Hello, World";
    let key = b"1234567887654321";
    let aes = Aes128Ecb::from_key(key).unwrap();
    let encrypted = aes.encrypt(message).unwrap();
    let decrypted = aes.decrypt(encrypted.as_slice()).unwrap();
    assert_eq!(
        vec![
            208, 217, 45, 21, 237, 39, 220, 119, 98, 164, 86, 69, 76, 172, 126, 5,
        ],
        encrypted
    );
    assert_eq!(message.to_vec(), decrypted);
}
