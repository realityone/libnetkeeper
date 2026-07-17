use std::net::Ipv4Addr;

use byteorder::{ByteOrder, NativeEndian, NetworkEndian};

use crate::common::error::BufferError;

pub trait BytesAble {
    fn as_bytes(&self) -> Vec<u8>;

    #[inline]
    fn write_bytes(&self, dst: &mut [u8]) -> Result<(), BufferError> {
        let bytes = self.as_bytes();
        if dst.len() != bytes.len() {
            return Err(BufferError::LengthMismatch {
                expected: bytes.len(),
                actual: dst.len(),
            });
        }
        dst.copy_from_slice(&bytes);
        Ok(())
    }
}

pub trait BytesAbleNum {
    fn as_bytes_be(&self) -> Vec<u8>;
    fn as_bytes_le(&self) -> Vec<u8>;

    #[inline]
    fn write_bytes_be(&self, dst: &mut [u8]) -> Result<(), BufferError> {
        let bytes = self.as_bytes_be();
        if dst.len() != bytes.len() {
            return Err(BufferError::LengthMismatch {
                expected: bytes.len(),
                actual: dst.len(),
            });
        }
        dst.copy_from_slice(&bytes);
        Ok(())
    }

    #[inline]
    fn write_bytes_le(&self, dst: &mut [u8]) -> Result<(), BufferError> {
        let bytes = self.as_bytes_le();
        if dst.len() != bytes.len() {
            return Err(BufferError::LengthMismatch {
                expected: bytes.len(),
                actual: dst.len(),
            });
        }
        dst.copy_from_slice(&bytes);
        Ok(())
    }
}

impl BytesAble for Ipv4Addr {
    #[inline]
    fn as_bytes(&self) -> Vec<u8> {
        self.octets().to_vec()
    }
}

impl BytesAble for String {
    #[inline]
    fn as_bytes(&self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }
}

macro_rules! impl_bytes_able_for_num_type {
    ($ty:ty, $size:expr) => {
        impl BytesAble for $ty {
            #[inline]
            fn as_bytes(&self) -> Vec<u8> {
                self.as_bytes_be().to_vec()
            }
        }

        impl BytesAbleNum for $ty {
            #[inline]
            fn as_bytes_be(&self) -> Vec<u8> {
                let mut bytes = [0u8; $size];
                NetworkEndian::write_uint(&mut bytes, u64::from(*self), $size);
                bytes.to_vec()
            }

            #[inline]
            fn as_bytes_le(&self) -> Vec<u8> {
                let mut bytes = [0u8; $size];
                NativeEndian::write_uint(&mut bytes, u64::from(*self), $size);
                bytes.to_vec()
            }
        }
    };
}

impl_bytes_able_for_num_type!(u64, 8);
impl_bytes_able_for_num_type!(u32, 4);
impl_bytes_able_for_num_type!(u16, 2);
