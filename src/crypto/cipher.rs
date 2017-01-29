use rust_crypto::{aes, blockmodes, buffer};
use rust_crypto::buffer::{WriteBuffer, ReadBuffer};

#[derive(Debug)]
pub enum CipherError {
    KeyLengthMismatch,
    EncryptError,
    DecryptError,
    BufferOverflow,
}

pub trait SimpleCipher {
    fn encrypt(&self, plain_bytes: &[u8]) -> Result<Vec<u8>, CipherError>;
    fn decrypt(&self, encrypted_bytes: &[u8]) -> Result<Vec<u8>, CipherError>;
}

#[allow(non_camel_case_types)]
#[derive(Debug)]
pub struct AES_128_ECB {
    key: [u8; 16],
}

impl AES_128_ECB {
    pub fn new(key: &[u8]) -> Result<Self, CipherError> {
        if key.len() != 16 {
            return Err(CipherError::KeyLengthMismatch);
        }
        let mut fixed_key = [0u8; 16];
        fixed_key.clone_from_slice(key);

        Ok(AES_128_ECB { key: fixed_key })
    }
}

impl SimpleCipher for AES_128_ECB {
    fn encrypt(&self, plain_bytes: &[u8]) -> Result<Vec<u8>, CipherError> {
        let mut encrypter =
            aes::ecb_encryptor(aes::KeySize::KeySize128, &self.key, blockmodes::PkcsPadding);
        let mut input = buffer::RefReadBuffer::new(plain_bytes);
        let mut output_buff = vec![0u8; plain_bytes.len() + 16];
        let mut output = buffer::RefWriteBuffer::new(output_buff.as_mut_slice());

        let result = match encrypter.encrypt(&mut input, &mut output, true) {
            Err(_) => return Err(CipherError::EncryptError),
            Ok(r) => r,
        };

        match result {
            buffer::BufferResult::BufferUnderflow => {
                Ok(output.take_read_buffer().take_remaining().to_vec())
            }
            buffer::BufferResult::BufferOverflow => Err(CipherError::BufferOverflow),
        }
    }

    fn decrypt(&self, encrypted_bytes: &[u8]) -> Result<Vec<u8>, CipherError> {
        let mut decrypter =
            aes::ecb_decryptor(aes::KeySize::KeySize128, &self.key, blockmodes::PkcsPadding);
        let mut input = buffer::RefReadBuffer::new(encrypted_bytes);
        let mut output_buff = vec![0u8; encrypted_bytes.len()];
        let mut output = buffer::RefWriteBuffer::new(output_buff.as_mut_slice());

        let result = match decrypter.decrypt(&mut input, &mut output, true) {
            Err(_) => return Err(CipherError::DecryptError),
            Ok(r) => r,
        };

        match result {
            buffer::BufferResult::BufferUnderflow => {
                Ok(output.take_read_buffer().take_remaining().to_vec())
            }
            buffer::BufferResult::BufferOverflow => Err(CipherError::BufferOverflow),
        }
    }
}