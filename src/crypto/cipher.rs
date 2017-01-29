use rust_crypto::{aes, blockmodes, buffer, symmetriccipher};
use rust_crypto::buffer::{WriteBuffer, ReadBuffer};

#[derive(Debug)]
pub enum CipherError {
    // Expect length {}, got {}
    KeyLengthMismatch(usize, usize),
    EncryptError(symmetriccipher::SymmetricCipherError),
    DecryptError(symmetriccipher::SymmetricCipherError),
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
            return Err(CipherError::KeyLengthMismatch(16usize, key.len()));
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

        match try!(encrypter.encrypt(&mut input, &mut output, true)
            .map_err(CipherError::EncryptError)) {
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

        match try!(decrypter.decrypt(&mut input, &mut output, true)
            .map_err(CipherError::DecryptError)) {
            buffer::BufferResult::BufferUnderflow => {
                Ok(output.take_read_buffer().take_remaining().to_vec())
            }
            buffer::BufferResult::BufferOverflow => Err(CipherError::BufferOverflow),
        }
    }
}

#[test]
fn test_aes_128_ecb_cipher() {
    let message = b"Hello, World";
    let key = b"1234567887654321";
    let aes = AES_128_ECB::new(key).unwrap();
    let encrypted = aes.encrypt(message).unwrap();
    let decrypted = aes.decrypt(encrypted.as_slice()).unwrap();
    assert_eq!(vec![208, 217, 45, 21, 237, 39, 220, 119, 98, 164, 86, 69, 76, 172, 126, 5],
               encrypted);
    assert_eq!(message.to_vec(), decrypted);
}