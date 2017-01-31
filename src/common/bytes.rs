use std::net::Ipv4Addr;

use byteorder::{NetworkEndian, NativeEndian, ByteOrder};

pub trait BytesAble {
    fn as_bytes(&self) -> Vec<u8>;
    fn write_bytes(&self, dst: &mut [u8]) {
        dst.copy_from_slice(&self.as_bytes());
    }
}

pub trait BytesAbleNum {
    fn as_bytes_be(&self) -> Vec<u8>;
    fn as_bytes_le(&self) -> Vec<u8>;

    fn write_bytes_be(&self, dst: &mut [u8]) {
        dst.copy_from_slice(&self.as_bytes_be());
    }

    fn write_bytes_le(&self, dst: &mut [u8]) {
        dst.copy_from_slice(&self.as_bytes_le());
    }
}

impl BytesAble for Ipv4Addr {
    fn as_bytes(&self) -> Vec<u8> {
        self.octets().to_vec()
    }
}

impl BytesAble for String {
    fn as_bytes(&self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }
}

macro_rules! impl_bytes_able_for_num_type {
    ($ty:ty, $size:expr) => (
        impl BytesAble for $ty {
            fn as_bytes(&self) -> Vec<u8> {
                self.as_bytes_be().to_vec()
            }
        }

        impl BytesAbleNum for $ty {
            fn as_bytes_be(&self) -> Vec<u8> {
                let mut bytes = [0u8; $size];
                NetworkEndian::write_uint(&mut bytes, *self as u64, $size);
                bytes.to_vec()
            }

            fn as_bytes_le(&self) -> Vec<u8> {
                let mut bytes = [0u8; $size];
                NativeEndian::write_uint(&mut bytes, *self as u64, $size);
                bytes.to_vec()
            }
        }
    )
}

impl_bytes_able_for_num_type!(u32, 4);
impl_bytes_able_for_num_type!(u16, 2);
